using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.Networking.Connectivity;

namespace VlessVpnTask
{
    internal class VlessConfig
    {
        public string Address { get; set; }
        public int Port { get; set; } = 443;
        public string Uuid { get; set; }
        public string Type { get; set; } = "tcp";
        public string Security { get; set; } = "reality";
        public string Sni { get; set; }
        public string PublicKey { get; set; }
        public string ShortId { get; set; }
        public string Path { get; set; }
        public string Host { get; set; }
        public string Flow { get; set; }
        public string Alpn { get; set; }

        public string XhttpMode { get; set; } = "stream-one";
        public bool NoGrpcHeader { get; set; } = true;
        public bool NoSseHeader { get; set; } = true;
        public int XPaddingMin { get; set; } = 100;
        public int XPaddingMax { get; set; } = 1000;

        // Определяет, включен ли режим XHTTP
        public bool IsXhttp =>
            string.Equals(Type, "xhttp", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Type, "splithttp", StringComparison.OrdinalIgnoreCase);

        public string EffectiveXhttpMode
        {
            get
            {
                string m = (XhttpMode ?? "").Trim().ToLowerInvariant();
                if (m == "" || m == "auto")
                    return "stream-one";
                return m;
            }
        }

        public static VlessConfig Parse(string configStr)
        {
            var cfg = new VlessConfig();
            if (string.IsNullOrEmpty(configStr)) return cfg;

            var pairs = configStr.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var pair in pairs)
            {
                var kv = pair.Split(new[] { '=' }, 2);
                if (kv.Length == 2)
                {
                    string key = kv[0].Trim().ToLowerInvariant();
                    string val = kv[1].Trim();

                    switch (key)
                    {
                        case "type": cfg.Type = val; break;
                        case "security": cfg.Security = val; break;
                        case "sni": cfg.Sni = val; break;
                        case "sid":
                        case "shortid": cfg.ShortId = val; break;
                        case "flow": cfg.Flow = val; break;
                        case "path": cfg.Path = val; break;
                        case "host": cfg.Host = val; break;
                        case "alpn": cfg.Alpn = val; break;
                        case "pbk":
                        case "publickey":
                            val = val.Replace("-", "+").Replace("_", "/");
                            while (val.Length % 4 != 0) val += "=";
                            cfg.PublicKey = val;
                            break;
                    }
                }
            }
            return cfg;
        }
    }

    public sealed class VlessVpnPlugin : IVpnPlugIn
    {
        private readonly System.Threading.SemaphoreSlim _triggerWriteLock = new System.Threading.SemaphoreSlim(1, 1);
        private VpnChannel _channel;
        private VlessConfig _config;
        private volatile NatEngine _natEngine;

        private DatagramSocket _dummyTransport;
        private DatagramSocket _dummyTrigger;
        private DataWriter _triggerWriter;

        private bool _disconnected = false;

        public static NetworkAdapter PhysicalAdapter { get; set; }
        public static HostName PhysicalIp { get; set; }
        public static string ServerIp { get; set; }

        internal event Action Disconnected;
        internal bool IsConnected { get; private set; }
        internal bool SessionEnded => _disconnected;

        public void Connect(VpnChannel channel)
        {
            FileLog.W("[VPN PLUGIN] Connect() запущен.");

            ServerIp = null;
            PhysicalAdapter = null;
            PhysicalIp = null;
            _disconnected = false;
            IsConnected = false;

            _channel = channel;

            PhysicalIp = GetPhysicalIpHostName();
            if (PhysicalIp != null && PhysicalIp.IPInformation != null)
            {
                PhysicalAdapter = PhysicalIp.IPInformation.NetworkAdapter;
            }

            FileLog.W($"[VPN PLUGIN] Обнаружен физический IP Wi-Fi/LTE: {PhysicalIp?.RawName}");

            try
            {
                var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
                try { FileLog.Verbose = (localSettings.Values["v_DebugLog"] as bool?) ?? false; } catch { }
                _config = new VlessConfig
                {
                    Address = localSettings.Values["v_Address"] as string,
                    Port = (localSettings.Values["v_Port"] as int?) ?? 443,
                    Uuid = localSettings.Values["v_Uuid"] as string,
                    Type = (localSettings.Values["v_Type"] as string) ?? "tcp",
                    Security = (localSettings.Values["v_Security"] as string) ?? "reality",
                    Sni = localSettings.Values["v_Sni"] as string,
                    PublicKey = localSettings.Values["v_PublicKey"] as string,
                    ShortId = localSettings.Values["v_ShortId"] as string,
                    Path = localSettings.Values["v_Path"] as string,
                    Host = localSettings.Values["v_Host"] as string,
                    Flow = localSettings.Values["v_Flow"] as string,
                    Alpn = localSettings.Values["v_Alpn"] as string,
                    XhttpMode = (localSettings.Values["v_XhttpMode"] as string) ?? "stream-one"
                };
                if (string.IsNullOrEmpty(_config.Address))
                    throw new Exception("Конфигурация VLESS в LocalSettings не найдена.");

                FileLog.Important($"[VPN PLUGIN] Type='{_config.Type}', IsXhttp={_config.IsXhttp}, Path='{_config.Path}'");
                try
                {
                    var resolveTask = System.Net.Dns.GetHostAddressesAsync(_config.Address);
                    if (Task.WhenAny(resolveTask, Task.Delay(5000)).GetAwaiter().GetResult() == resolveTask)
                    {
                        foreach (var ip in resolveTask.GetAwaiter().GetResult())
                        {
                            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                ServerIp = ip.ToString();
                                FileLog.W($"[VPN PLUGIN] Успешно разрешен IP: {ServerIp}");
                                break;
                            }
                        }
                    }
                }
                catch (Exception ex) { FileLog.W($"[VPN PLUGIN WARN] Резолв сервера: {ex.Message}"); }

                // === РАБОЧИЙ КОМПЛЕКТ TUN-ИНТЕРФЕЙСА ===
                var ipv4List = new List<HostName> { new HostName("11.16.1.1") };
                var ipv6List = new List<HostName> { new HostName("fd00:11:16::1") };

                var routes = new VpnRouteAssignment();
                routes.ExcludeLocalSubnets = true;

                routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("0.0.0.0"), 2));
                routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("64.0.0.0"), 2));
                routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("128.0.0.0"), 2));
                routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("192.0.0.0"), 2));
                routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("11.17.0.0"), 16));

                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("::"), 3));
                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("2000::"), 3));
                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("4000::"), 3));
                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("6000::"), 3));
                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("8000::"), 3));
                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("a000::"), 3));
                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("c000::"), 3));
                routes.Ipv6InclusionRoutes.Add(new VpnRoute(new HostName("e000::"), 3));

                if (!string.IsNullOrEmpty(ServerIp))
                    routes.Ipv4ExclusionRoutes.Add(new VpnRoute(new HostName(ServerIp), 32));

                var dnsAssignment = new VpnDomainNameAssignment();
                var dnsInfo = new VpnDomainNameInfo(
                    ".",
                    VpnDomainNameType.Suffix,
                    new List<HostName> { new HostName("11.16.1.254") },
                    new List<HostName>());
                dnsAssignment.DomainNameList.Add(dnsInfo);

                FileLog.W("[VPN PLUGIN] Настройка сокетов ядра...");
                var loHost = new HostName("127.0.0.1");

                _dummyTrigger = new DatagramSocket();
                _dummyTrigger.BindEndpointAsync(loHost, "").AsTask().Wait();
                string triggerPort = _dummyTrigger.Information.LocalPort;

                _dummyTransport = new DatagramSocket();
                _channel.AssociateTransport(_dummyTransport, null);
                _dummyTransport.BindEndpointAsync(loHost, "").AsTask().Wait();
                string transportPort = _dummyTransport.Information.LocalPort;

                _dummyTransport.ConnectAsync(loHost, triggerPort).AsTask().Wait();
                _dummyTrigger.ConnectAsync(loHost, transportPort).AsTask().Wait();

                FileLog.W($"[VPN PLUGIN] Дамми-петля поднята: {transportPort}->{triggerPort}");

                _triggerWriter = new DataWriter(_dummyTrigger.OutputStream);

                // ИСПРАВЛЕНО: Режим переключается динамически в зависимости от конфига 
                // (xhttp требует DirectMode, стандартный tcp будет работать через MUX)
                bool direct = _config.IsXhttp;

                FileLog.Important($"[VPN PLUGIN] Выбран режим: {(direct ? "DIRECT (xhttp без mux)" : "MUX")}");

                _natEngine = new NatEngine();
                _natEngine.Channel = _channel;
                _natEngine.Config = _config;
                _natEngine.DirectMode = direct;
                _natEngine.TriggerDecapsulate = () =>
                {
                    Task.Run(async () =>
                    {
                        var writer = _triggerWriter;
                        if (writer == null || _natEngine == null) return;

                        await _triggerWriteLock.WaitAsync();
                        try
                        {
                            writer.WriteByte(1);
                            await writer.StoreAsync();
                        }
                        catch { }
                        finally { _triggerWriteLock.Release(); }
                    });
                };
                _natEngine.Start();

                if (!direct)
                {
                    FileLog.W("[VPN PLUGIN] Предустановка MUX-соединения до запуска TUN...");
                    VlessConnection preConn = null;
                    try
                    {
                        preConn = Task.Run(async () =>
                        {
                            for (int attempt = 1; attempt <= 3; attempt++)
                            {
                                try
                                {
                                    PhysicalIp = GetPhysicalIpHostName();
                                    if (PhysicalIp != null && PhysicalIp.IPInformation != null)
                                    {
                                        PhysicalAdapter = PhysicalIp.IPInformation.NetworkAdapter;
                                    }

                                    if (string.IsNullOrEmpty(ServerIp))
                                    {
                                        var resolveTask = System.Net.Dns.GetHostAddressesAsync(_config.Address);
                                        if (await Task.WhenAny(resolveTask, Task.Delay(2500)) == resolveTask)
                                        {
                                            foreach (var ip in await resolveTask)
                                            {
                                                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                                                {
                                                    ServerIp = ip.ToString();
                                                    FileLog.W($"[VPN PLUGIN] [Попытка {attempt}] Успешно разрешен IP: {ServerIp}");
                                                    break;
                                                }
                                            }
                                        }
                                    }

                                    var conn = new VlessConnection(_config, _channel);
                                    if (await conn.StartAsync())
                                    {
                                        return conn;
                                    }
                                    conn.Close();
                                }
                                catch (Exception ex)
                                {
                                    FileLog.W($"[VPN PLUGIN] Попытка {attempt} завершилась ошибкой: {ex.Message}");
                                }

                                FileLog.W($"[VPN PLUGIN] [Попытка {attempt}] Сеть не готова. Ожидаем 1.5 сек...");
                                await Task.Delay(1500);
                            }
                            return null;
                        }).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        FileLog.W($"[VPN PLUGIN ERROR] Исключение в задаче MUX: {ex.Message}");
                    }

                    if (preConn == null)
                        throw new Exception("Reality/MUX handshake до TUN не удался (все попытки исчерпаны).");

                    _natEngine.SetPreEstablishedMux(preConn);
                    FileLog.W("[VPN PLUGIN] MUX поднят ДО TUN успешно.");
                }
                else
                {
                    FileLog.Important("[VPN PLUGIN] DIRECT-режим (xhttp без mux): соединения открываются по требованию, пред-канал не нужен.");
                }

                _channel.StartWithMainTransport(
                    ipv4List, ipv6List, null, routes, dnsAssignment,
                    1400, 1400, true, _dummyTransport);

                FileLog.W("[VPN PLUGIN] TUN СЕТЬ ЗАПУЩЕНА СИСТЕМОЙ!");
                IsConnected = true;
            }
            catch (Exception ex)
            {
                FileLog.W($"[VPN PLUGIN ERROR] {ex.Message}");
                try
                {
                    Disconnect(_channel);
                }
                catch { }
                _channel.TerminateConnection(ex.Message);
            }
        }

        public void Disconnect(VpnChannel channel)
        {
            if (_disconnected) { try { channel?.Stop(); } catch { } return; }
            _disconnected = true;

            FileLog.Important("[VPN PLUGIN] Disconnect: освобождаю ресурсы...");

            try { _natEngine?.SignalStop(); } catch { }

            try { _dummyTransport?.Dispose(); } catch { }
            _dummyTransport = null;
            try { _dummyTrigger?.Dispose(); } catch { }
            _dummyTrigger = null;

            try { channel?.Stop(); } catch { }

            IsConnected = false;
            try { Disconnected?.Invoke(); } catch { }
            FileLog.Important("[VPN PLUGIN] Disconnect: ресурсы освобождены.");
        }

        public void Encapsulate(VpnChannel channel, VpnPacketBufferList packets, VpnPacketBufferList encapulatedPackets)
        {
            var engine = _natEngine;
            if (engine == null) return;

            uint count = packets.Size;
            if (FileLog.Verbose) FileLog.W($"[ENCAP] Вызван, пакетов от ОС: {count}");
            for (uint i = 0; i < count; i++)
            {
                var packet = packets.RemoveAtBegin();
                engine.ProcessPacketFromOs(packet);
                packets.Append(packet);
            }
        }

        public void Decapsulate(VpnChannel channel, VpnPacketBuffer encapBuffer, VpnPacketBufferList decapsulatedPackets, VpnPacketBufferList controlPacketsToSend)
        {
            var engine = _natEngine;
            if (engine == null) return;

            engine.ResetTriggerPending();

            const int MaxPerCall = 256;
            int injected = 0;

            while (injected < MaxPerCall && engine.HasPendingOsRx())
            {
                VpnPacketBuffer outBuf;
                try
                {
                    outBuf = channel.GetVpnReceivePacketBuffer();
                }
                catch (Exception ex)
                {
                    FileLog.W($"[VPN DECAPSULATE] Пул буферов исчерпан: {ex.Message}");
                    break;
                }
                if (outBuf == null) break;

                if (!engine.TryDequeueOsRx(out byte[] rawPacket)) break;

                try
                {
                    uint safeLength = (uint)Math.Min(rawPacket.Length, outBuf.Buffer.Capacity);
                    System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions.CopyTo(rawPacket, 0, outBuf.Buffer, 0, (int)safeLength);
                    outBuf.Buffer.Length = safeLength;
                    decapsulatedPackets.Append(outBuf);
                    injected++;
                }
                catch (Exception ex)
                {
                    FileLog.W($"[VPN DECAPSULATE ERROR] Сбой копирования буфера: {ex.Message}");
                }
            }

            if (_natEngine != null && engine.HasPendingOsRx())
                engine.KickDecapsulate();
        }

        public void GetKeepAlivePayload(VpnChannel channel, out VpnPacketBuffer keepAlivePacket)
        {
            keepAlivePacket = null;
        }

        public static HostName GetPhysicalIpHostName()
        {
            try
            {
                var hostNames = NetworkInformation.GetHostNames();
                foreach (var hn in hostNames)
                {
                    if (hn.Type == HostNameType.Ipv4 && hn.IPInformation?.NetworkAdapter != null)
                    {
                        string ip = hn.RawName;

                        if (ip.StartsWith("11.16.") || ip.StartsWith("11.17."))
                            continue;

                        if (ip == "127.0.0.1" || ip.StartsWith("169.254."))
                            continue;

                        return hn;
                    }
                }
            }
            catch { }
            return null;
        }
    }
}