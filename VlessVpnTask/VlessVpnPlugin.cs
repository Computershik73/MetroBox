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
    internal enum XhttpTransportMode { StreamOne, StreamUp, PacketUp }
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

        // Второе звено цепочки Amnezia. Address/Port выше — это реле, которое
        // умеет доводить только до этого узла. Пока используется для разовой
        // проверки: первое соединение направляется сюда вместо сайта, чтобы
        // выяснить, принимает ли реле IP-назначение вообще.
        public string ChainExitHost { get; set; } = "";
        public int ChainExitPort { get; set; }

        // У выходного узла свои учётные данные REALITY: ключи реле ему чужие,
        // и на них он отбрасывает на прикрытие (в логе — настоящий CA-сертификат).
        public string ChainExitUuid { get; set; } = "";
        public string ChainExitPublicKey { get; set; } = "";
        public string ChainExitSni { get; set; } = "";
        public string ChainExitShortId { get; set; } = "";
        public string ChainExitFlow { get; set; } = "";

        // Конфиг второго звена. Транспорт и режим наследуются от первого
        // (оба узла — tcp/reality), а всё, что узел проверяет у клиента,
        // подменяется на его собственное. Цепочка дальше не идёт, поэтому
        // поля ChainExit* в копии остаются пустыми — иначе получилась бы
        // бесконечная вложенность.
        public VlessConfig CloneForChainExit()
        {
            return new VlessConfig
            {
                Address = ChainExitHost,
                Port = ChainExitPort,
                Uuid = ChainExitUuid,
                PublicKey = ChainExitPublicKey,
                Sni = ChainExitSni,
                ShortId = ChainExitShortId,
                Flow = ChainExitFlow,
                Type = Type,
                Security = Security,
                Alpn = Alpn,
                Path = Path,
                Host = Host,
                XhttpMode = XhttpMode
            };
        }

        // Shadowsocks / Outline
        public string Method { get; set; } = "";     // шифр AEAD
        public string Password { get; set; } = "";
        public string SsPrefix { get; set; } = "";   // маскировка начала потока (Outline)

        public string XhttpMode { get; set; } = "stream-one";
        public bool NoGrpcHeader { get; set; } = true;
        public bool NoSseHeader { get; set; } = true;
        public int XPaddingMin { get; set; } = 100;
        public int XPaddingMax { get; set; } = 1000;

        public XhttpTransportMode ResolveXhttpMode()
        {
            string m = (XhttpMode ?? "").Trim().ToLowerInvariant();
            switch (m)
            {
                case "packet-up":
                case "packetup":
                    return XhttpTransportMode.PacketUp;
                case "stream-up":
                case "streamup":
                    return XhttpTransportMode.StreamUp;
                default:
                    // auto/пусто/stream-one -> stream-one. В отличие от senko здесь
                    // НЕ выбираем packet-up для security=none: split-транспорт
                    // (XhttpSplit) в Metrobox всегда идёт через Reality, а stream-one
                    // корректно шлёт cleartext при security=none.
                    return XhttpTransportMode.StreamOne;
            }
        }

        // Определяет, включен ли режим XHTTP
        public bool IsXhttp =>
            string.Equals(Type, "xhttp", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Type, "splithttp", StringComparison.OrdinalIgnoreCase);

        public bool IsWs =>
            string.Equals(Type, "ws", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Type, "websocket", StringComparison.OrdinalIgnoreCase);

        // Shadowsocks/Outline: собственный AEAD-транспорт, ни Reality, ни MUX не участвуют.
        public bool IsShadowsocks =>
            string.Equals(Type, "shadowsocks", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Type, "ss", StringComparison.OrdinalIgnoreCase);

        // xtls-rprx-vision активен только для своего flow и только на raw TCP
        // (не ws/xhttp), как и в xray-core.
        public bool IsVision =>
            string.Equals((Flow ?? "").Trim(), "xtls-rprx-vision", StringComparison.OrdinalIgnoreCase)
            && !IsWs && !IsXhttp;

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
        private volatile AwgEngine _awgEngine;   // AmneziaWG: работает вместо _natEngine
        private AwgConfig _awgConfig;
        private bool _netWatchActive;
        private int _netChangeBusy;   // 0/1 — защита от лавины событий NetworkStatusChanged

        public static NetworkAdapter PhysicalAdapter { get; set; }
        public static HostName PhysicalIp { get; set; }
        public static string ServerIp { get; set; }

        internal event Action Disconnected;
        internal bool IsConnected { get; private set; }
        internal bool SessionEnded => _disconnected;

        public void Connect(VpnChannel channel)
        {
            FileLog.W("[VPN PLUGIN] Connect() запущен.");

            // Жалоба от прошлой сессии не должна висеть в UI поверх нового подключения.
            NetDiag.ClearError();

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

            // Следим за сменой сети (Wi-Fi ↔ LTE). Без этого PhysicalIp определялся один раз
            // здесь и больше не обновлялся: после переключения все новые сокеты продолжали
            // привязываться к исчезнувшему локальному адресу, и туннель не восстанавливался
            // до ручного переподключения.
            try
            {
                NetworkInformation.NetworkStatusChanged += OnNetworkStatusChanged;
                _netWatchActive = true;
            }
            catch (Exception ex) { FileLog.Important($"[NET] Не удалось подписаться на смену сети: {ex.Message}"); }

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
                    XhttpMode = (localSettings.Values["v_XhttpMode"] as string) ?? "stream-one",
                    Method = (localSettings.Values["v_SsMethod"] as string) ?? "",
                    Password = (localSettings.Values["v_SsPassword"] as string) ?? "",
                    SsPrefix = (localSettings.Values["v_SsPrefix"] as string) ?? "",
                    ChainExitHost = (localSettings.Values["v_ChainExitHost"] as string) ?? "",
                    ChainExitPort = localSettings.Values["v_ChainExitPort"] is int
                        ? (int)localSettings.Values["v_ChainExitPort"] : 0,
                    ChainExitUuid = (localSettings.Values["v_ChainExitUuid"] as string) ?? "",
                    ChainExitPublicKey = (localSettings.Values["v_ChainExitPublicKey"] as string) ?? "",
                    ChainExitSni = (localSettings.Values["v_ChainExitSni"] as string) ?? "",
                    ChainExitShortId = (localSettings.Values["v_ChainExitShortId"] as string) ?? "",
                    ChainExitFlow = (localSettings.Values["v_ChainExitFlow"] as string) ?? ""
                };
                // === AmneziaWG: полностью отдельный путь ===
                // WireGuard работает на уровне IP, поэтому пользовательский TCP-стек NatEngine
                // здесь не нужен: пакет от ОС шифруется и уходит в UDP как есть.
                string awgText = localSettings.Values["v_AwgConfig"] as string;
                bool wantAwg = !string.IsNullOrEmpty(awgText) &&
                               ((_config.Type ?? "").ToLowerInvariant() == "amneziawg" ||
                                (_config.Type ?? "").ToLowerInvariant() == "awg" ||
                                (_config.Type ?? "").ToLowerInvariant() == "wireguard");
                if (wantAwg)
                {
                    ConnectAmneziaWg(awgText);
                    return;
                }

                if (string.IsNullOrEmpty(_config.Address))
                    throw new Exception("Конфигурация VLESS в LocalSettings не найдена.");

                if (_config.IsShadowsocks && !SsCipherSpec.IsSupported(_config.Method))
                    throw new Exception($"Шифр Shadowsocks '{_config.Method}' не поддерживается. " +
                                        "Нужен aes-128-gcm, aes-192-gcm, aes-256-gcm или chacha20-ietf-poly1305.");

                FileLog.Important($"[VPN PLUGIN] Type='{_config.Type}', IsXhttp={_config.IsXhttp}, Path='{_config.Path}'");
                // Резолвим ДО подъёма TUN и с повторами: сразу после переключения сети
                // (особенно на только что поднятом Wi-Fi) DNS часто ещё не готов, а одной
                // попытки с таймаутом 5 с не хватало. Если ServerIp останется пустым, дальше
                // код пойдёт подключаться ПО ИМЕНИ — но разрешать его будет уже некому, кроме
                // нашего же FakeDns внутри туннеля, который вернёт фиктивный 11.17.x.x, и
                // туннель начнёт ломиться сам в себя (в логе: таймауты подключения к туннелю
                // вперемешку с DNS-запросами имени сервера).
                ServerIp = ResolveServerIpAsync(_config.Address, 3, 2000).GetAwaiter().GetResult();
                if (!string.IsNullOrEmpty(ServerIp))
                {
                    FileLog.Important($"[VPN PLUGIN] Успешно разрешен IP: {ServerIp}");
                    try { localSettings.Values[LastServerIpKey] = ServerIp; } catch { }
                }
                else
                {
                    // Подстраховка: берём последний удачно разрешённый адрес. IP сервера от
                    // нашей сети не зависит, поэтому кэш почти всегда актуален и вытаскивает
                    // подключение там, где DNS ещё не проснулся.
                    string cachedIp = null;
                    try { cachedIp = localSettings.Values[LastServerIpKey] as string; } catch { }
                    if (!string.IsNullOrEmpty(cachedIp) && !IsTunnelFakeIp(cachedIp))
                    {
                        ServerIp = cachedIp;
                        FileLog.Important($"[VPN PLUGIN] DNS не ответил — беру последний известный IP сервера: {ServerIp}");
                    }
                    else
                    {
                        FileLog.Important("[VPN PLUGIN] ВНИМАНИЕ: IP сервера не разрешён и кэша нет — подключение может не подняться.");
                    }
                }

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
                // vision несовместим с MUX (xray запрещает mux при xtls-rprx-vision),
                // поэтому vision-профили тоже работают в per-flow DIRECT-режиме.
                // Shadowsocks мультиплексора не имеет вовсе — только per-flow соединения.
                bool direct = _config.IsXhttp || _config.IsWs || _config.IsVision || _config.IsShadowsocks;

                FileLog.Important($"[VPN PLUGIN] Выбран режим: {(direct ? "DIRECT (shadowsocks/xhttp/ws/vision без mux)" : "MUX")}");

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
                PublishTile();
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
            try { LiveTile.ShowDisconnected(); } catch { }

            // Снимаем слежение за сетью раньше всего: иначе события, прилетающие уже во
            // время разрыва, дёргали бы сброс на гаснущем движке.
            if (_netWatchActive)
            {
                try { NetworkInformation.NetworkStatusChanged -= OnNetworkStatusChanged; } catch { }
                _netWatchActive = false;
            }

            try { H2MuxRegistry.Reset(); } catch { }
            try { _awgEngine?.SignalStop(); } catch { }
            _awgEngine = null;
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
            var awg = _awgEngine;
            if (awg != null)
            {
                uint n = packets.Size;
                for (uint i = 0; i < n; i++)
                {
                    var pkt = packets.RemoveAtBegin();
                    awg.ProcessPacketFromOs(pkt);
                    packets.Append(pkt);
                }
                return;
            }

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
            var awg = _awgEngine;
            if (awg != null)
            {
                awg.ResetTriggerPending();
                int done = 0;
                while (done < 256 && awg.HasPendingOsRx())
                {
                    VpnPacketBuffer buf;
                    try { buf = channel.GetVpnReceivePacketBuffer(); }
                    catch (Exception ex) { FileLog.W($"[AWG DECAP] Пул буферов исчерпан: {ex.Message}"); break; }
                    if (buf == null) break;

                    byte[] raw;
                    if (!awg.TryDequeueOsRx(out raw)) break;
                    try
                    {
                        uint safe = (uint)Math.Min(raw.Length, buf.Buffer.Capacity);
                        System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions.CopyTo(raw, 0, buf.Buffer, 0, (int)safe);
                        buf.Buffer.Length = safe;
                        decapsulatedPackets.Append(buf);
                        done++;
                    }
                    catch (Exception ex) { FileLog.W($"[AWG DECAP ERROR] {ex.Message}"); }
                }
                if (awg.HasPendingOsRx()) awg.KickDecapsulate();
                return;
            }

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

        // Подъём AmneziaWG. Отличия от VLESS-пути: адрес TUN и DNS берутся из .conf,
        // FakeDns не нужен (DNS-пакеты идут в туннель как обычный IP-трафик), а хендшейк
        // делается ДО StartWithMainTransport — чтобы не поднимать TUN, если сервер недоступен.
        private void ConnectAmneziaWg(string confText)
        {
            string reason;
            _awgConfig = AwgConfig.Parse(confText, out reason);
            if (_awgConfig == null)
                throw new Exception("Конфиг AmneziaWG некорректен: " + reason);

            FileLog.Important($"[AWG] Профиль: endpoint={_awgConfig.EndpointHost}:{_awgConfig.EndpointPort}, " +
                              $"MTU={_awgConfig.Mtu}, Jc={_awgConfig.Jc}, Jmin={_awgConfig.Jmin}, Jmax={_awgConfig.Jmax}, " +
                              $"S1={_awgConfig.Padding[0]}, S2={_awgConfig.Padding[1]}, S4={_awgConfig.Padding[3]}, " +
                              $"H1={_awgConfig.HeaderMin[0]}..{_awgConfig.HeaderMax[0]}, " +
                              $"H4={_awgConfig.HeaderMin[3]}..{_awgConfig.HeaderMax[3]}");

            var settings = ApplicationData.Current.LocalSettings.Values;
            ServerIp = ResolveServerIpAsync(_awgConfig.EndpointHost, 3, 2000).GetAwaiter().GetResult();
            if (!string.IsNullOrEmpty(ServerIp))
            {
                try { settings[LastServerIpKey] = ServerIp; } catch { }
            }
            else
            {
                string cached = null;
                try { cached = settings[LastServerIpKey] as string; } catch { }
                if (!string.IsNullOrEmpty(cached) && !IsTunnelFakeIp(cached)) ServerIp = cached;
            }
            if (string.IsNullOrEmpty(ServerIp))
                throw new Exception("Не удалось разрешить адрес endpoint для AmneziaWG.");
            FileLog.Important($"[AWG] IP сервера: {ServerIp}");

            string tunIp = _awgConfig.FirstIpv4Address();
            if (string.IsNullOrEmpty(tunIp))
                throw new Exception("В [Interface] нет IPv4-адреса (Address).");

            var ipv4List = new List<HostName> { new HostName(tunIp) };

            var routes = new VpnRouteAssignment();
            routes.ExcludeLocalSubnets = true;
            routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("0.0.0.0"), 2));
            routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("64.0.0.0"), 2));
            routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("128.0.0.0"), 2));
            routes.Ipv4InclusionRoutes.Add(new VpnRoute(new HostName("192.0.0.0"), 2));
            // Сам сервер обязан идти мимо туннеля, иначе получится петля.
            routes.Ipv4ExclusionRoutes.Add(new VpnRoute(new HostName(ServerIp), 32));

            var dnsAssignment = new VpnDomainNameAssignment();
            var dnsServers = new List<HostName>();
            foreach (var d in _awgConfig.Dns)
            {
                if (d.IndexOf(':') >= 0) continue;               // IPv6-DNS пока не назначаем
                try { dnsServers.Add(new HostName(d)); } catch { }
            }
            if (dnsServers.Count == 0) dnsServers.Add(new HostName("1.1.1.1"));
            dnsAssignment.DomainNameList.Add(new VpnDomainNameInfo(
                ".", VpnDomainNameType.Suffix, dnsServers, new List<HostName>()));

            FileLog.W("[VPN PLUGIN] Настройка сокетов ядра (AWG)...");
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
            _triggerWriter = new DataWriter(_dummyTrigger.OutputStream);
            FileLog.W($"[VPN PLUGIN] Дамми-петля поднята: {transportPort}->{triggerPort}");

            var engine = new AwgEngine(_awgConfig);
            engine.Channel = _channel;
            engine.TriggerDecapsulate = () =>
            {
                Task.Run(async () =>
                {
                    var writer = _triggerWriter;
                    if (writer == null) return;
                    await _triggerWriteLock.WaitAsync();
                    try { writer.WriteByte(1); await writer.StoreAsync(); }
                    catch { }
                    finally { _triggerWriteLock.Release(); }
                });
            };

            // Хендшейк ДО подъёма TUN: если сервер не отвечает, лучше честно упасть здесь,
            // чем поднять туннель, через который ничего не пойдёт.
            if (!engine.StartAsync(ServerIp).GetAwaiter().GetResult())
                throw new Exception("Хендшейк AmneziaWG не удался (проверьте ключи, endpoint и параметры обфускации).");

            _awgEngine = engine;

            _channel.StartWithMainTransport(
                ipv4List, null, null, routes, dnsAssignment,
                _awgConfig.Mtu, (uint)_awgConfig.Mtu, false, _dummyTransport);

            IsConnected = true;
            PublishTile();
            FileLog.Important($"[AWG] TUN поднят: адрес {tunIp}, MTU {_awgConfig.Mtu}, DNS {string.Join(",", _awgConfig.Dns)}");
        }

        // Живая плитка: имя профиля + чем и куда подключились.
        private void PublishTile()
        {
            try
            {
                string name = null;
                try { name = Windows.Storage.ApplicationData.Current.LocalSettings.Values["v_Name"] as string; }
                catch { }

                string proto = _config == null ? "" :
                               _config.IsShadowsocks ? "shadowsocks" :
                               (_config.Type ?? "").ToLowerInvariant() == "amneziawg" ? "amneziawg" :
                               (_config.Type ?? "").ToLowerInvariant() == "wireguard" ? "wireguard" :
                               "vless";

                string host = _config?.Address ?? "";
                string details = host.Length > 0 ? $"{proto} · {host}" : proto;

                LiveTile.ShowConnected(name, details);
            }
            catch (Exception ex) { FileLog.W($"[TILE] {ex.Message}"); }
        }

        private const string LastServerIpKey = "v_LastServerIp";

        // 11.16.x.x — адрес самого TUN, 11.17.x.x — пул FakeDns. Если DNS вернул такое,
        // значит запрос ушёл в наш собственный туннель: брать этот адрес нельзя.
        private static bool IsTunnelFakeIp(string ip)
        {
            return !string.IsNullOrEmpty(ip) && (ip.StartsWith("11.16.") || ip.StartsWith("11.17."));
        }

        private static async Task<string> ResolveServerIpAsync(string host, int attempts, int perTryMs)
        {
            if (string.IsNullOrEmpty(host)) return null;

            for (int i = 1; i <= attempts; i++)
            {
                try
                {
                    var t = System.Net.Dns.GetHostAddressesAsync(host);
                    if (await Task.WhenAny(t, Task.Delay(perTryMs)) == t)
                    {
                        foreach (var ip in await t)
                        {
                            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;
                            string s = ip.ToString();
                            if (IsTunnelFakeIp(s))
                            {
                                FileLog.Important($"[VPN PLUGIN] DNS вернул адрес туннеля ({s}) — игнорирую, это ответ нашего же FakeDns.");
                                continue;
                            }
                            return s;
                        }
                    }
                    else
                    {
                        FileLog.Important($"[VPN PLUGIN] Резолв '{host}': таймаут попытки {i}/{attempts}.");
                    }
                }
                catch (Exception ex)
                {
                    FileLog.Important($"[VPN PLUGIN] Резолв '{host}', попытка {i}/{attempts}: {ex.Message}");
                }

                if (i < attempts) await Task.Delay(500);
            }
            return null;
        }

        // NetworkStatusChanged прилетает пачками и из произвольного потока: при переключении
        // Wi-Fi ↔ LTE система дёргает его несколько раз подряд, плюс отдельно — на подъём
        // нашего же TUN. Поэтому вся работа уходит в фон под флагом-защёлкой, а решение
        // принимается по ФАКТУ смены физического IP, а не по самому событию.
        private void OnNetworkStatusChanged(object sender)
        {
            if (_disconnected) return;
            if (System.Threading.Interlocked.Exchange(ref _netChangeBusy, 1) == 1) return;

            Task.Run(async () =>
            {
                try { await HandleNetworkChangeAsync(); }
                catch (Exception ex) { FileLog.Important($"[NET] Ошибка обработки смены сети: {ex.Message}"); }
                finally { System.Threading.Volatile.Write(ref _netChangeBusy, 0); }
            });
        }

        private async Task HandleNetworkChangeAsync()
        {
            string oldIp = PhysicalIp?.RawName;

            // Новый интерфейс адрес получает не мгновенно: сразу после переключения
            // GetHostNames() может вернуть пусто. Ждём появления адреса до ~10 секунд.
            HostName fresh = null;
            for (int i = 0; i < 20 && !_disconnected; i++)
            {
                fresh = GetPhysicalIpHostName();
                if (fresh != null) break;
                await Task.Delay(500);
            }
            if (_disconnected) return;

            string newIp = fresh?.RawName;
            if (newIp == null)
            {
                FileLog.Important("[NET] Сеть пропала: физический IP не найден. Жду следующего события.");
                return;
            }

            // Событий много, реальная смена адреса — редкость. Молча выходим, если ничего
            // не изменилось, иначе рвали бы живые соединения на ровном месте.
            if (string.Equals(newIp, oldIp, StringComparison.Ordinal)) return;

            PhysicalIp = fresh;
            PhysicalAdapter = fresh.IPInformation?.NetworkAdapter;
            FileLog.Important($"[NET] Сменилась сеть: {(oldIp ?? "<нет>")} → {newIp}. Пересоздаю соединения.");

            // IP сервера от нашей сети не зависит, поэтому НЕ перерезолвим его без нужды:
            // после подъёма TUN обычный DNS ушёл бы в туннель, который в этот момент как раз
            // и сломан. Резолвим только если адреса у нас так и нет.
            if (string.IsNullOrEmpty(ServerIp) && _config != null && !string.IsNullOrEmpty(_config.Address))
            {
                // Тот же резолвер с отбраковкой фиктивных адресов: TUN уже поднят, поэтому
                // обычный DNS-запрос уйдёт в туннель и вернёт 11.17.x.x от нашего FakeDns.
                string ip = await ResolveServerIpAsync(_config.Address, 2, 2000);
                if (!string.IsNullOrEmpty(ip))
                {
                    ServerIp = ip;
                    FileLog.Important($"[NET] IP сервера разрешён после смены сети: {ServerIp}");
                    try { ApplicationData.Current.LocalSettings.Values[LastServerIpKey] = ServerIp; } catch { }
                }
                else
                {
                    string cachedIp = null;
                    try { cachedIp = ApplicationData.Current.LocalSettings.Values[LastServerIpKey] as string; } catch { }
                    if (!string.IsNullOrEmpty(cachedIp) && !IsTunnelFakeIp(cachedIp))
                    {
                        ServerIp = cachedIp;
                        FileLog.Important($"[NET] Беру последний известный IP сервера: {ServerIp}");
                    }
                }
            }

            // Общие H2-туннели держат сокеты на старом интерфейсе — гасим весь пул,
            // иначе новые потоки цеплялись бы к мёртвым туннелям.
            try { H2MuxRegistry.Reset(); } catch { }
            try { _natEngine?.ResetForNetworkChange(); } catch { }

            // AmneziaWG: UDP-сокет привязан к исчезнувшему адресу, поэтому туннель
            // пересобираем целиком — с новым хендшейком через новый интерфейс.
            var awg = _awgEngine;
            if (awg != null && !string.IsNullOrEmpty(ServerIp))
            {
                FileLog.Important("[AWG] Смена сети — пересобираю туннель.");
                try
                {
                    if (await awg.RestartAsync(ServerIp))
                        FileLog.Important("[AWG] Туннель восстановлен после смены сети.");
                    else
                        FileLog.Important("[AWG] Восстановить туннель не удалось — жду следующего события сети.");
                }
                catch (Exception ex) { FileLog.Important($"[AWG] Ошибка пересборки: {ex.Message}"); }
            }
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