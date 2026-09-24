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
            System.Threading.Interlocked.Increment(ref ConnectGeneration);
            _disconnected = false;
            IsConnected = false;
            SetTunnelUp(false);

            // Повторный Connect() без Disconnect() оставлял движок прошлой сессии жить:
            // его таймеры продолжали тикать (в журнале строки [POOL] шли парами), соединения
            // висели на мёртвом канале, а брошенные задачи потом всплывали как непрочитанные
            // ошибки. Гасим всё старое до создания нового.
            var staleNat = _natEngine;
            _natEngine = null;
            if (staleNat != null)
            {
                FileLog.Important("[VPN PLUGIN] Найден движок прошлой сессии — останавливаю его.");
                try { staleNat.SignalStop(); } catch { }
            }
            var staleAwg = _awgEngine;
            _awgEngine = null;
            if (staleAwg != null)
            {
                FileLog.Important("[VPN PLUGIN] Найден туннель AmneziaWG прошлой сессии — останавливаю его.");
                try { staleAwg.SignalStop(); } catch { }
            }

            // Система сама переподключает туннель, не вызывая Disconnect: в журнале
            // Connect() приходит посреди работающего соединения. Отличать такой вызов
            // от холодного старта важно — при нём DNS спрашивать бесполезно.
            bool restartOverLiveTun = staleNat != null || staleAwg != null;
            try { H2MuxRegistry.Reset(); } catch { }

            _channel = channel;

            PhysicalIp = GetPhysicalIpHostName();
            if (PhysicalIp != null && PhysicalIp.IPInformation != null)
            {
                PhysicalAdapter = PhysicalIp.IPInformation.NetworkAdapter;
            }

            FileLog.W($"[VPN PLUGIN] Физический адрес для сокетов: {PhysicalIp?.RawName}"
                      + $" (тип интерфейса {PhysicalAdapter?.IanaInterfaceType.ToString() ?? "?"})."
                      + " На настольной машине важно, чтобы это был выход в интернет, а не виртуальный адаптер.");

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
                // При переподключении поверх поднятого TUN обычный DNS уходит в туннель,
                // который мы только что погасили: три попытки просто съедали восемь секунд,
                // и всё это время связи не было. Адрес сервера от сети не зависит, поэтому
                // берём последний известный и идём дальше.
                string knownIp = null, knownFor = null;
                try
                {
                    knownIp = localSettings.Values[LastServerIpKey] as string;
                    knownFor = localSettings.Values[LastServerHostKey] as string;
                }
                catch { }

                if (restartOverLiveTun && !string.IsNullOrEmpty(knownIp) && !IsTunnelFakeIp(knownIp) &&
                    string.Equals(knownFor, _config.Address, StringComparison.OrdinalIgnoreCase))
                {
                    ServerIp = knownIp;
                    FileLog.Important($"[VPN PLUGIN] Переподключение поверх живого TUN — беру известный IP сервера: {ServerIp} (DNS сейчас всё равно уходит в туннель).");
                }
                else
                {
                    ServerIp = ResolveServerIpAsync(_config.Address, 3, 2000).GetAwaiter().GetResult();
                    if (!string.IsNullOrEmpty(ServerIp))
                    {
                        FileLog.Important($"[VPN PLUGIN] Успешно разрешен IP: {ServerIp}");
                        try
                        {
                            localSettings.Values[LastServerIpKey] = ServerIp;
                            localSettings.Values[LastServerHostKey] = _config.Address;
                        }
                        catch { }
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
                SetTunnelUp(true);
                StartWatchdog();
                StartAppWatch();
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
            SetTunnelUp(false);

            FileLog.Important("[VPN PLUGIN] Disconnect: освобождаю ресурсы...");
            try { LiveTile.ShowDisconnected(); } catch { }

            // Снимаем слежение за сетью раньше всего: иначе события, прилетающие уже во
            // время разрыва, дёргали бы сброс на гаснущем движке.
            if (_netWatchActive)
            {
                try { NetworkInformation.NetworkStatusChanged -= OnNetworkStatusChanged; } catch { }
                _netWatchActive = false;
            }

            StopWatchdog();
            StopAppWatch();

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
            SetTunnelUp(true);
            StartAppWatch();
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

        // Приложение живёт в другом процессе и о состоянии туннеля судило по наличию
        // адреса 11.16.1.1 у машины. Адрес этот после отключения исчезает не сразу, и
        // приложение продолжало считать себя подключённым — кнопка отключения нажималась
        // впустую. Здесь плагин прямо говорит, поднят туннель или нет.
        private const string TunnelUpKey = "v_TunnelUp";

        // Номер подключения. Фоновая задача по нему понимает, что пока процесс
        // дозакрывался, система пришла с новым подключением, и выходить уже нельзя.
        internal static int ConnectGeneration;

        private static void SetTunnelUp(bool up)
        {
            try { ApplicationData.Current.LocalSettings.Values[TunnelUpKey] = up; } catch { }
        }

        private const string LastServerIpKey = "v_LastServerIp";

        // Имя, которому принадлежит запомненный адрес: сервер могли сменить, и тогда
        // кэш чужой.
        private const string LastServerHostKey = "v_LastServerIpFor";

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
        // ===================== сторож туннеля =====================
        //
        // Туннель умел умирать молча: процесс жив, таймеры тикают, а трафик не ходит —
        // и так до тех пор, пока пользователь сам не переподключится. Причин две:
        // событие смены сети приходит не всегда, а мёртвый общий H2-туннель никто не
        // проверяет. Сторож раз в полторы минуты сверяет адрес интерфейса и раз в три
        // минуты пропускает через сервер настоящий запрос.

        private System.Threading.Timer _watchdog;
        private int _watchdogBusy;
        private int _probeFails;
        private bool _probeLogged;

        private const int WatchdogPeriodMs = 90 * 1000;
        private const int ProbeBudgetMs = 8000;

        // Проба стоит рукопожатия и пары килобайт, а на телефоне трафик считают.
        // Адрес интерфейса смотрим каждый тик, туннель прощупываем раз в три минуты.
        private const int ProbeMinIntervalMs = 3 * 60 * 1000;
        private DateTime _lastProbeAt = DateTime.MinValue;

        // Две цели: одна может быть закрыта у самого сервера, и тогда здоровый
        // туннель выглядел бы мёртвым, а сторож рвал бы живые соединения.
        private static readonly byte[][] ProbeTargets =
        {
            new byte[] { 1, 1, 1, 1 },
            new byte[] { 8, 8, 8, 8 },
        };

        // ===================== туннель гаснет вместе с приложением =====================
        //
        // Закрытое крестиком приложение оставляло туннель работать, и следующее
        // подключение после нового запуска натыкалось на него — отсюда ошибка 691.
        // Приложение держит файл app.alive монопольно открытым всю свою жизнь;
        // освободиться он может только со смертью процесса. Мы раз в две секунды
        // пробуем его открыть: не открывается — приложение живо, открылся — его закрыли.
        //
        // Взводимся, только увидев приложение живым хотя бы раз. Если туннель подняли
        // из центра уведомлений, вообще не открывая приложение, файл свободен с самого
        // начала, и гасить такой туннель было бы ошибкой.

        private const string AppAliveLockName = "app.alive";
        private const int AppWatchPeriodMs = 2000;

        private System.Threading.Timer _appWatch;
        private int _appWatchBusy;
        private bool _appSeenAlive;

        private enum AppPresence { Alive, Gone, Unknown }

        private static AppPresence ProbeApp()
        {
            string path;
            try { path = System.IO.Path.Combine(ApplicationData.Current.LocalFolder.Path, AppAliveLockName); }
            catch { return AppPresence.Unknown; }

            try
            {
                // Открываем только на чтение и никому не мешаем: если приложение держит
                // файл монопольно, открытие упадёт с нарушением совместного доступа.
                using (new System.IO.FileStream(path, System.IO.FileMode.Open,
                                                System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite))
                {
                    return AppPresence.Gone;
                }
            }
            catch (System.IO.FileNotFoundException) { return AppPresence.Gone; }
            catch (System.IO.IOException ex) when ((ex.HResult & 0xFFFF) == 32)   // ERROR_SHARING_VIOLATION
            {
                return AppPresence.Alive;
            }
            catch { return AppPresence.Unknown; }
        }

        private void StartAppWatch()
        {
            StopAppWatch();
            _appSeenAlive = false;
            try
            {
                _appWatch = new System.Threading.Timer(_ => AppWatchTick(), null, 0, AppWatchPeriodMs);
            }
            catch (Exception ex) { FileLog.Important($"[APP WATCH] Не удалось завести таймер: {ex.Message}"); }
        }

        private void StopAppWatch()
        {
            var t = _appWatch;
            _appWatch = null;
            try { t?.Dispose(); } catch { }
        }

        private void AppWatchTick()
        {
            if (_disconnected || !IsConnected) return;
            if (System.Threading.Interlocked.Exchange(ref _appWatchBusy, 1) == 1) return;
            try
            {
                var state = ProbeApp();
                if (state == AppPresence.Alive)
                {
                    if (!_appSeenAlive)
                    {
                        _appSeenAlive = true;
                        FileLog.Important("[APP WATCH] Приложение открыто — туннель погаснет вместе с ним.");
                    }
                    return;
                }

                if (state == AppPresence.Gone && _appSeenAlive)
                {
                    FileLog.Important("[APP WATCH] Приложение закрыто — отключаю туннель.");
                    StopAppWatch();
                    try { Disconnect(_channel); }
                    catch (Exception ex) { FileLog.Important($"[APP WATCH] Отключение не удалось: {ex.Message}"); }
                }
            }
            finally
            {
                System.Threading.Volatile.Write(ref _appWatchBusy, 0);
            }
        }

        private void StartWatchdog()
        {
            StopWatchdog();
            _probeFails = 0;
            _probeLogged = false;
            _lastProbeAt = DateTime.MinValue;   // новое подключение проверяем на первом же тике
            try
            {
                _watchdog = new System.Threading.Timer(
                    _ => { var ignore = WatchdogTickAsync(); }, null, WatchdogPeriodMs, WatchdogPeriodMs);
            }
            catch (Exception ex) { FileLog.Important($"[WATCHDOG] Не удалось завести таймер: {ex.Message}"); }
        }

        private void StopWatchdog()
        {
            var t = _watchdog;
            _watchdog = null;
            try { t?.Dispose(); } catch { }
        }

        private async Task WatchdogTickAsync()
        {
            if (_disconnected || !IsConnected) return;
            if (System.Threading.Interlocked.Exchange(ref _watchdogBusy, 1) == 1) return;

            try
            {
                // Адрес интерфейса мог смениться без события системы — проверка дешёвая,
                // делаем её на каждом тике.
                var fresh = GetPhysicalIpHostName(PhysicalIp);
                string freshIp = fresh?.RawName;
                string knownIp = PhysicalIp?.RawName;
                if (freshIp != null && knownIp != null && !string.Equals(freshIp, knownIp, StringComparison.Ordinal))
                {
                    FileLog.Important($"[WATCHDOG] Адрес интерфейса сменился без события системы: {knownIp} → {freshIp}.");
                    OnNetworkStatusChanged(null);   // тот же путь восстановления, что и у события
                    return;
                }

                // AmneziaWG держит себя сам (keepalive + рехендшейк), пробовать нечего.
                if (_config == null || _awgEngine != null) return;
                if ((DateTime.UtcNow - _lastProbeAt).TotalMilliseconds < ProbeMinIntervalMs) return;
                _lastProbeAt = DateTime.UtcNow;

                var sw = System.Diagnostics.Stopwatch.StartNew();
                bool alive = false;
                foreach (var target in ProbeTargets)
                {
                    if (_disconnected) return;
                    if (await ProbeTunnelAsync(target)) { alive = true; break; }
                }
                if (alive)
                {
                    // Первую удачную пробу записываем всегда: в присланном журнале должно
                    // быть видно, что сторож работает, а туннель проверен на деле.
                    if (_probeFails > 0) FileLog.Important($"[WATCHDOG] Туннель снова отвечает ({sw.ElapsedMilliseconds} мс).");
                    else if (!_probeLogged) FileLog.Important($"[WATCHDOG] Туннель проверен: ответ через сервер за {sw.ElapsedMilliseconds} мс.");
                    else FileLog.W($"[WATCHDOG] Туннель отвечает ({sw.ElapsedMilliseconds} мс).");
                    _probeLogged = true;
                    _probeFails = 0;
                    return;
                }

                _probeFails++;
                FileLog.Important($"[WATCHDOG] Проверка не прошла ({_probeFails} подряд): туннель не пропускает трафик.");

                // Одна неудача бывает и на живом туннеле (сервер придушил соединение,
                // сеть моргнула). Пересобираем на второй подряд.
                if (_probeFails >= 2)
                {
                    FileLog.Important("[WATCHDOG] Пересоздаю соединения, не дожидаясь пользователя.");
                    try { H2MuxRegistry.Reset(); } catch { }
                    try { _natEngine?.ResetForNetworkChange(); } catch { }
                    _probeFails = 0;
                }
            }
            catch (Exception ex)
            {
                FileLog.Important($"[WATCHDOG] Ошибка проверки: {ex.Message}");
            }
            finally
            {
                System.Threading.Volatile.Write(ref _watchdogBusy, 0);
            }
        }

        /// Открывает через сервер поток к внешнему адресу и ждёт от него ответ.
        /// Проверяется весь путь целиком, а не доступность узла: при нерабочем ключе
        /// или мёртвом общем туннеле ответа не будет.
        private async Task<bool> ProbeTunnelAsync(byte[] targetIp)
        {
            VlessConnection conn = null;
            try
            {
                conn = new VlessConnection(_config, _channel);
                conn.ConfigureDirectIp(targetIp, false, 80);

                var start = conn.StartAsync();
                if (await Task.WhenAny(start, Task.Delay(ProbeBudgetMs)) != start || !start.Result) return false;

                byte[] req = System.Text.Encoding.ASCII.GetBytes(
                    "HEAD / HTTP/1.1\r\nHost: " + string.Join(".", targetIp) + "\r\nConnection: close\r\n\r\n");
                await conn.WriteUnderlyingAsync(req);

                var deadline = DateTime.UtcNow.AddMilliseconds(ProbeBudgetMs);
                var read = conn.ReadPayloadAsync();
                while (!_disconnected)
                {
                    var left = deadline - DateTime.UtcNow;
                    if (left <= TimeSpan.Zero) return false;

                    // Одно чтение в работе за раз: брошенное чтение унесло бы с собой
                    // уже полученный ответ и потом всплыло непрочитанной ошибкой.
                    if (await Task.WhenAny(read, Task.Delay(left)) != read) return false;

                    byte[] payload = read.Result;
                    if (payload == null) return false;          // поток закрыт — ответа нет
                    if (payload.Length > 0) return true;        // цель ответила: путь жив
                    read = conn.ReadPayloadAsync();             // пустой блок — данных пока нет
                }
                return false;
            }
            catch (Exception ex)
            {
                FileLog.W($"[WATCHDOG] Проба оборвалась: {ex.Message}");
                return false;
            }
            finally
            {
                try { conn?.Close(); } catch { }
            }
        }

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
                fresh = GetPhysicalIpHostName(PhysicalIp);
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
            return GetPhysicalIpHostName(null);
        }

        /// <param name="keepIfAlive">
        /// Адрес, на котором мы уже работаем. Пока он есть у машины, менять его нельзя.
        /// Когда TUN поднят, система начинает считать «выходом в интернет» другой
        /// интерфейс: на телефоне при живом Wi-Fi профилем интернета становилась
        /// сотовая сеть, плагин перепривязывал сокеты на её адрес, и после этого
        /// ни одно соединение с сервером уже не открывалось. Смена адреса имеет
        /// смысл только тогда, когда прежнего у машины больше нет.
        /// </param>
        public static HostName GetPhysicalIpHostName(HostName keepIfAlive)
        {
            try
            {
                // Адаптер, через который система реально ходит в интернет. На телефоне это
                // Wi-Fi или сотовая сеть и выбор очевиден, а на настольной машине рядом живут
                // виртуальные адаптеры VirtualBox, VMware и Hyper-V. Раньше брался первый
                // попавшийся адрес, и сокет, привязанный к 192.168.56.1 (VirtualBox), падал
                // с ошибкой «сделана попытка выполнить операцию на сокете при отключённой сети».
                Guid wanted = Guid.Empty;
                try
                {
                    var profile = NetworkInformation.GetInternetConnectionProfile();
                    var adapter = profile?.NetworkAdapter;
                    if (adapter != null) wanted = adapter.NetworkAdapterId;
                }
                catch { }

                string keepIp = keepIfAlive?.RawName;
                HostName keepMatch = null;
                HostName wantedMatch = null;
                HostName fallback = null;
                foreach (var hn in NetworkInformation.GetHostNames())
                {
                    if (hn.Type != HostNameType.Ipv4 || hn.IPInformation?.NetworkAdapter == null)
                        continue;

                    string ip = hn.RawName;

                    if (ip.StartsWith("11.16.") || ip.StartsWith("11.17."))
                        continue;

                    if (ip == "127.0.0.1" || ip.StartsWith("169.254."))
                        continue;

                    if (keepIp != null && string.Equals(ip, keepIp, StringComparison.Ordinal))
                        keepMatch = hn;

                    if (wantedMatch == null && wanted != Guid.Empty &&
                        hn.IPInformation.NetworkAdapter.NetworkAdapterId == wanted)
                        wantedMatch = hn;

                    if (fallback == null) fallback = hn;
                }

                // Адрес, на котором уже идёт работа, важнее любых предпочтений системы.
                if (keepMatch != null) return keepMatch;
                if (wantedMatch != null) return wantedMatch;

                // Профиль интернета не определился (бывает в момент смены сети) — ведём себя
                // как раньше и берём первый подходящий адрес.
                return fallback;
            }
            catch { }
            return null;
        }
    }
}