using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    internal enum TcpState { SynReceived, Established, Closed }


    internal class TcpConn
    {
        public string Key;
        public ushort Sid; // MUX Stream ID
        public bool MuxNewSent = false;

        public bool IsIpv6 = false; // Флаг IPv6 соединения
        public byte[] SrcIp;
        public byte[] DstIp;
        public ushort SrcPort;
        public ushort DstPort;

        public uint IsnBase;
        public uint MySeq;
        public uint PeerSeq;

        public volatile TcpState State;
        public readonly object Lock = new object();
        public int Closing;
        public int MuxSlotState; // 0 = слот MUX не занят, 1 = занят (см. _tcpSlots)
        public NatEngine.MuxCarrier Carrier;

        public readonly ConcurrentQueue<byte[]> SendQueue = new ConcurrentQueue<byte[]>();
        public int Sending = 0;
        public readonly ConcurrentQueue<byte[]> RecvQueue = new ConcurrentQueue<byte[]>();
        public int Receiving = 0;
        public int RecvQueuedBytes = 0; // через Interlocked — для backpressure к несущему каналу


        public bool SendFinPending = false;

        // Сколько ждём downstream после локального FIN, прежде чем гасить туннельный
        // сокет. Ответ сервера почти всегда приходит за доли секунды; запас нужен
        // только чтобы полузакрытые соединения не копились и не съедали слоты.
        public const int HalfCloseGraceMs = 10000;

        public byte[] DnsServerIp = new byte[4];
        public readonly List<byte> DnsBuffer = new List<byte>();
        public DateTime DnsStartTime;
        public string DnsQueryDomain;

        // HTTP(S)-прокси режим (для AppContainer-приложений в обход WFP-изоляции TUN).
        public bool IsProxy = false;           // соединение пришло на адрес прокси
        public bool ProxyEstablished = false;  // заголовок CONNECT/GET уже разобран
        public ushort ProxyTargetPort;         // реальный порт назначения (для MUX New-кадра)
        public readonly List<byte> ProxyHead = new List<byte>();

        public DateTime LastActivityUtc = DateTime.UtcNow;

        public uint OsAckedSeq;          // наибольший ACK от ОС (сколько она подтвердила)
        public int OsWindow = 65535;    // последнее окно приёма, объявленное ОС

        public IDirectConn DirectConn;       // персональное соединение VLESS/Shadowsocks (direct-режим)
        public int DirectSlotState;          // 0/1 — занят ли слот _directSlots

    }

    internal class NatEngine
    {
        private const byte FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;
        private const int MSS = 1330;

        private readonly ConcurrentDictionary<string, TcpConn> _conns = new ConcurrentDictionary<string, TcpConn>();
        private readonly Random _rnd = new Random();

        // --- Пул несущих MUX-каналов ---
        internal sealed class MuxCarrier
        {
            public VlessConnection Conn;
            public volatile bool Running;
            public int Substreams;                 // через Interlocked
            public readonly SemaphoreSlim WriteLock = new SemaphoreSlim(1, 1);
        }

        private const int PerCarrierMax = 8;                          // лимит сервера (muxConcurrency=8) на ОДИН канал
        private const int MaxCarriers = 8;                          // сколько несущих TLS-каналов держим максимум
        private const int MaxTcpStreams = PerCarrierMax * MaxCarriers; // суммарный потолок сабстримов

        private readonly List<MuxCarrier> _carriers = new List<MuxCarrier>();
        private readonly object _carriersLock = new object();        // защищает СПИСОК (быстрые операции)
        private readonly SemaphoreSlim _muxLock = new SemaphoreSlim(1, 1); // сериализует дорогое создание канала
        private readonly SemaphoreSlim _tcpSlots = new SemaphoreSlim(MaxTcpStreams, MaxTcpStreams);

        private int _sidCounter = 0;
        private readonly ConcurrentDictionary<ushort, TcpConn> _muxSessions = new ConcurrentDictionary<ushort, TcpConn>();
        private readonly ConcurrentDictionary<ushort, long> _orphanEnded = new ConcurrentDictionary<ushort, long>();

        private const int MaxDnsStreams = 3;
        private readonly SemaphoreSlim _dnsSemaphore = new SemaphoreSlim(MaxDnsStreams, MaxDnsStreams);


        private System.Threading.Timer _reaperTimer;


        // Сервер из ссылки: muxConcurrency=8, несущий MUX один => суммарно держим ≤ 8 сабстримов.
        // A-запросы DNS теперь резолвятся ЛОКАЛЬНО (fake-IP), без MUX-сабстрима, поэтому DNS
        // почти не делит бюджет MUX, и почти все 8 слотов отдаём под реальный TCP.

        // Увеличиваем лимит сабстримов до 63 для поддержки тяжелых сайтов и многопоточного Speedtest

        private const int MaxConnSendQueue = 64; // потолок очереди на сабстрим (~85 КБ)

        // Потолок входящей очереди на сабстрим. При превышении read-loop тормозит чтение
        // канала ТОЛЬКО когда именно этот сабстрим реально насыщен (окно ОС закрыто, насос
        // не успевает сливать) — а не на каждом чанке, как было. Память ограничена,
        // брошенные приложением сокеты добивает FLOWCTRL-таймаут (>30с) внутри InjectDataToOs.
        private const int MaxConnRecvBytes = 256 * 1024;

        // Ограничение очереди к ОС: если Decapsulate долго не забирает пакеты,
        // без лимита очередь раздувает память и процесс получает kill.
        private const int MaxOsRxQueue = 4096;
        private int _osRxCount;

        // Заглушка "реального" IP для локального fake-DNS: реальный адрес клиенту не нужен,
        // т.к. New-кадр MUX несёт доменное имя и сервер резолвит сам. Используется только
        // как аргумент FakeDns.RegisterStable; в [FAKE DNS HIT] лог попадёт как 0.0.0.0.
        private static readonly byte[] FakeDnsPlaceholderRealIp = new byte[] { 0, 0, 0, 0 };

        // Виртуальный HTTP(S)-прокси: любой TCP на этот адрес трактуется как прокси-подключение
        // (CONNECT для https, absolute-form GET для http). Адрес внутри маршрутизируемой
        // подсети 11.17.0.0/16. AppContainer-приложения (Edge) ходят на системный прокси через
        // web-platform/WinINET — иным путём, чем прямым сокетом, что может обойти WFP-стену TUN.
        private static readonly byte[] ProxyIp = { 11, 17, 0, 1 };
        private static bool IsProxyIp(byte[] ip) =>
            ip != null && ip.Length == 4 && ip[0] == 11 && ip[1] == 17 && ip[2] == 0 && ip[3] == 1;

        private ushort _ipIdCounter = 1000;

        public ConcurrentQueue<byte[]> OsRxQueue { get; } = new ConcurrentQueue<byte[]>();
        public Action TriggerDecapsulate { get; set; }
        public VpnChannel Channel { get; set; }
        public VlessConfig Config { get; set; }

        public Windows.Networking.Sockets.StreamSocket ServerSocket { get; set; }

        private volatile bool _stopped = false;

        private System.Threading.Timer _muxKeepAlive;

        private int _triggerPending = 0;

        private long _lastTriggerTicks = 0;

        private System.Threading.Timer _drainTimer;

        private long _osRxDropped;

        public bool DirectMode { get; set; }            // xhttp без mux

        // Лимит одновременных direct-соединений (слот держится всю жизнь flow'а).
        // БЕЗ мультиплексора каждое соединение = свой дорогой Reality-хендшейк + флуд
        // сервера, поэтому лимит низкий (8). С мультиплексором (вариант B) каждое
        // соединение = дешёвый H2-стрим в общем туннеле (хендшейк один на туннель),
        // поэтому лимит поднимаем — иначе YouTube с его 30-60 картинками стоит в очереди
        // по 8 и грузится десятки секунд. 64 покрывает всплеск, влезает в пул мультиплексора
        // (4 туннеля × ~60 стримов) и по памяти ≤ 64×128КБ приёмных окон.
        private static readonly int MaxDirectConns = VlessConnection.UseH2Mux ? 64 : 8;
        private readonly SemaphoreSlim _directSlots = new SemaphoreSlim(MaxDirectConns, MaxDirectConns);

        // Привязывает сабстрим к наименее загруженному живому каналу (<8 сабстримов),
        // при необходимости поднимает новый. Вызывается ТОЛЬКО когда слот _tcpSlots уже занят,
        // поэтому по принципу Дирихле место всегда найдётся (или можно создать новый канал).
        private async Task<MuxCarrier> AcquireCarrierAsync()
        {
            if (DirectMode) throw new InvalidOperationException("AcquireCarrier вызван в DirectMode");
            while (true)
            {
                MuxCarrier chosen = null;
                bool canCreate = false;
                lock (_carriersLock)
                {
                    foreach (var car in _carriers)
                    {
                        if (!car.Running) continue;
                        if (Volatile.Read(ref car.Substreams) >= PerCarrierMax) continue;
                        if (chosen == null || Volatile.Read(ref car.Substreams) < Volatile.Read(ref chosen.Substreams))
                            chosen = car;
                    }
                    if (chosen != null)
                    {
                        Interlocked.Increment(ref chosen.Substreams);
                        return chosen;
                    }
                    canCreate = _carriers.Count < MaxCarriers;
                }

                if (!canCreate) { await Task.Delay(10); continue; } // редкая гонка: канал умер, ждём

                await _muxLock.WaitAsync();
                try
                {
                    lock (_carriersLock)
                    {
                        foreach (var car in _carriers)
                            if (car.Running && Volatile.Read(ref car.Substreams) < PerCarrierMax) { chosen = car; break; }
                        if (chosen != null) { Interlocked.Increment(ref chosen.Substreams); return chosen; }
                        if (_carriers.Count >= MaxCarriers) continue; // создал кто-то другой
                    }

                    var conn = new VlessConnection(Config, Channel);
                    if (!await conn.StartAsync()) { conn.Close(); await Task.Delay(50); continue; }
                    var carrier = new MuxCarrier { Conn = conn, Running = true };
                    lock (_carriersLock) _carriers.Add(carrier);
                    _ = Task.Run(() => MuxReadLoopAsync(carrier));
                    Interlocked.Increment(ref carrier.Substreams);
                    FileLog.Important($"[MUX] Поднят несущий канал #{_carriers.Count}.");
                    return carrier;
                }
                finally { _muxLock.Release(); }
            }
        }

        // Пре-прогрев: гарантирует ХОТЯ БЫ один живой канал (без резервирования слота).
        public async Task EnsureAtLeastOneCarrierAsync()
        {
            if (DirectMode) return;
            lock (_carriersLock) { foreach (var c in _carriers) if (c.Running) return; }
            await _muxLock.WaitAsync();
            try
            {
                lock (_carriersLock)
                {
                    foreach (var c in _carriers) if (c.Running) return;
                    if (_carriers.Count >= MaxCarriers) return;
                }
                var conn = new VlessConnection(Config, Channel);
                if (!await conn.StartAsync()) { conn.Close(); return; }
                var carrier = new MuxCarrier { Conn = conn, Running = true };
                lock (_carriersLock) _carriers.Add(carrier);
                _ = Task.Run(() => MuxReadLoopAsync(carrier));
                FileLog.Important("[MUX] Восстановлен несущий канал (был потерян).");
            }
            finally { _muxLock.Release(); }
        }

        private void ReleaseSlotAndCarrier(TcpConn c)
        {
            if (Interlocked.Exchange(ref c.MuxSlotState, 0) == 1)
            {
                try { _tcpSlots.Release(); } catch { }
            }
            var car = Interlocked.Exchange(ref c.Carrier, null);
            if (car != null) Interlocked.Decrement(ref car.Substreams);
        }

        public void ResetTriggerPending()
        {
            Interlocked.Exchange(ref _triggerPending, 0);
        }

        public bool HasPendingOsRx()
        {
            return Volatile.Read(ref _osRxCount) > 0;
        }

        public void KickDecapsulate()
        {
            try { TriggerDecapsulate?.Invoke(); } catch { }
        }

        public bool TryDequeueOsRx(out byte[] packet)
        {
            if (OsRxQueue.TryDequeue(out packet))
            {
                Interlocked.Decrement(ref _osRxCount);
                return true;
            }
            return false;
        }

        private ushort NextSid()
        {
            while (true)
            {
                int v = System.Threading.Interlocked.Increment(ref _sidCounter) & 0xFFFF;
                if (v != 0) return (ushort)v;
            }
        }
        private async Task SendMuxKeepAliveAsync()
        {
            MuxCarrier[] snapshot;
            lock (_carriersLock) snapshot = _carriers.ToArray();
            foreach (var carrier in snapshot)
            {
                if (!carrier.Running) continue;
                await carrier.WriteLock.WaitAsync();
                try
                {
                    byte[] frame = new byte[6];
                    frame[1] = 4; frame[4] = 0x04; // metaLen=4, status=KeepAlive
                    await carrier.Conn.WriteUnderlyingAsync(frame);
                }
                catch { carrier.Running = false; try { carrier.Conn?.Close(); } catch { } }
                finally { carrier.WriteLock.Release(); }
            }
        }

        public void Start()
        {
            FileLog.Important($"[ENGINE] Старт. DirectMode={DirectMode}");

            // Резервный таймер очистки очереди: каждые 100 мс проверяет наличие пакетов.
            // Он работает на независимом потоке и ГАРАНТИРУЕТ отсутствие мертвых блокировок (deadlocks),
            // даже если Mux-поток полностью спит под воздействием Backpressure.
            _drainTimer = new System.Threading.Timer(_ =>
            {
                if (Volatile.Read(ref _osRxCount) > 0)
                {
                    try { TriggerDecapsulate?.Invoke(); } catch { }
                }
            }, null, 100, 100);
            _reaperTimer = new System.Threading.Timer(_ => ReapIdle(), null, 5000, 5000);
        }


        // Мягкий сброс при смене сети (Wi-Fi ↔ LTE). Все живые соединения привязаны к
        // СТАРОМУ физическому интерфейсу и после переключения мертвы, но сами об этом
        // «не знают»: сокет не всегда получает ошибку, и приложение висит до ручного
        // переподключения. Рвём всё разом — движок при этом НЕ останавливается, новые
        // соединения поднимутся по требованию уже через новый интерфейс. Клиентским
        // приложениям уходит FIN (внутри CloseConnLocal), поэтому они переоткрывают
        // соединения сами, не дожидаясь своих таймаутов.
        public void ResetForNetworkChange()
        {
            if (_stopped) return;

            MuxCarrier[] carriers;
            lock (_carriersLock) { carriers = _carriers.ToArray(); _carriers.Clear(); }
            foreach (var car in carriers) { car.Running = false; try { car.Conn?.Close(); } catch { } }

            var conns = _conns.Values.ToArray();
            foreach (var c in conns) { try { CloseConnLocal(c); } catch { } }

            _muxSessions.Clear();

            FileLog.Important($"[NET] Сброс после смены сети: закрыто соединений {conns.Length}, несущих каналов {carriers.Length}.");
        }

        public void Stop()
        {
            _stopped = true;
            _drainTimer?.Dispose(); _drainTimer = null;
            _reaperTimer?.Dispose(); _reaperTimer = null;
            _muxKeepAlive?.Dispose(); _muxKeepAlive = null;

            MuxCarrier[] snapshot;
            lock (_carriersLock) { snapshot = _carriers.ToArray(); _carriers.Clear(); }
            foreach (var car in snapshot) { car.Running = false; try { car.Conn?.Close(); } catch { } }

            foreach (var kv in _conns) CloseConnLocal(kv.Value);
            _conns.Clear();
            _muxSessions.Clear();
            while (OsRxQueue.TryDequeue(out _)) { }
            Interlocked.Exchange(ref _osRxCount, 0);
        }

        private void ReapIdle()
        {
            if (_stopped) return;

            FileLog.Important(
                $"[POOL] slots={_tcpSlots.CurrentCount}/{MaxTcpStreams} " +
                $"carriers={_carriers.Count} conns={_conns.Count} mux={_muxSessions.Count} " +
                $"osrx={Volatile.Read(ref _osRxCount)} dropped={Volatile.Read(ref _osRxDropped)}");

            DateTime now = DateTime.UtcNow;
            foreach (var kv in _conns)
            {
                var c = kv.Value;
                if (c.State == TcpState.Closed) continue;
                if (c.Key.StartsWith("DNS:")) continue;
                if ((now - c.LastActivityUtc).TotalSeconds > 45)
                {
                    var carrier = c.Carrier;
                    var sid = c.Sid;
                    FileLog.W($"[REAPER] Закрываю простаивающий сабстрим {c.Key} (sid {sid})");
                    CloseConnLocal(c);                                   // освобождает наш слот
                    if (carrier != null) _ = SendMuxEndBySidAsync(carrier, sid); // освобождает слот сервера
                }
            }
        }

        public bool ProcessPacketFromOs(VpnPacketBuffer vpnBuffer)
        {
            try
            {
                byte[] buf = vpnBuffer.Buffer.ToArray();
                int length = buf.Length;
                if (length < 20) { FileLog.W($"[PKT] Слишком короткий: {length}б"); return false; }

                byte version = (byte)(buf[0] >> 4);
                byte proto = (version == 4) ? buf[9] : (version == 6 ? buf[6] : (byte)0);
                //FileLog.W($"[PKT] ver={version} proto={proto} len={length}");
                if (version == 4)
                {
                    int ipHeaderLen = (buf[0] & 0x0F) * 4;
                    byte protocol = buf[9];

                    if (protocol == 6)
                    {
                        int t = ipHeaderLen;
                        ushort srcPort = (ushort)((buf[t] << 8) | buf[t + 1]);
                        ushort dstPort = (ushort)((buf[t + 2] << 8) | buf[t + 3]);
                        byte flags = buf[t + 13];

                        // Подробный лог каждого TCP пакета от ОС
                        if (FileLog.Verbose)
                        { FileLog.W($"[TCP FROM OS] {buf[12]}.{buf[13]}.{buf[14]}.{buf[15]}:{srcPort} -> {buf[16]}.{buf[17]}.{buf[18]}.{buf[19]}:{dstPort} | Flags: {flags:X2} (Seq: {ReadU32(buf, t + 4)})"); }

                        HandleTcpFromOs(buf, length, ipHeaderLen, false);
                        return true;
                    }
                    if (protocol == 17) { HandleUdpFromOs(buf, length, ipHeaderLen); return true; }
                }
                else if (version == 6) // <-- ОБРАБОТКА IPv6 ТРАФИКА
                {
                    if (length < 40) return false;
                    byte nextHeader = buf[6];

                    if (nextHeader == 6) // TCP over IPv6
                    {
                        int ipHeaderLen = 40; // Фиксированный размер основного заголовка IPv6
                        int t = ipHeaderLen;
                        if (length < t + 20) return false;

                        ushort srcPort = (ushort)((buf[t] << 8) | buf[t + 1]);
                        ushort dstPort = (ushort)((buf[t + 2] << 8) | buf[t + 3]);
                        byte flags = buf[t + 13];

                        if (FileLog.Verbose) FileLog.W($"[TCPv6 FROM OS] SrcPort: {srcPort} -> DstPort: {dstPort} | Flags: {flags:X2}");

                        HandleTcpFromOs(buf, length, ipHeaderLen, true);
                        return true;
                    }
                }
                return false;
            }
            catch { return true; }
        }

        // Неблокирующая остановка для Disconnect: выставляем флаг и закрываем сокеты,
// НО не ждём завершения фоновых циклов и не делаем тяжёлую уборку.
// Заблокированные read-loop'ы вывалятся из чтения по ObjectDisposed сами.
public void SignalStop()
{
    _stopped = true;

    try { _drainTimer?.Dispose(); } catch { }  _drainTimer = null;
    try { _reaperTimer?.Dispose(); } catch { } _reaperTimer = null;
    try { _muxKeepAlive?.Dispose(); } catch { } _muxKeepAlive = null;

    // Закрываем несущие каналы (mux) — если используются
    MuxCarrier[] snapshot;
    lock (_carriersLock) { snapshot = _carriers.ToArray(); }
    foreach (var car in snapshot)
    {
        car.Running = false;
        try { car.Conn?.Close(); } catch { }
    }

    // Закрываем direct-соединения — Close() разблокирует read-loop'ы.
    // НЕ зовём CloseConnLocal (он делает лишнюю уборку и может ждать); только рвём сокеты.
    foreach (var kv in _conns)
    {
        try { kv.Value.DirectConn?.Close(); } catch { }
    }
}

        private void HandleTcpFromOs(byte[] buf, int length, int ipHeaderLen, bool isIpv6)
        {
            int t = ipHeaderLen;
            if (length < t + 20) return;

            ushort srcPort = (ushort)((buf[t] << 8) | buf[t + 1]);
            ushort dstPort = (ushort)((buf[t + 2] << 8) | buf[t + 3]);
            uint seq = ReadU32(buf, t + 4);
            int dataOff = (buf[t + 12] >> 4) * 4;
            byte flags = buf[t + 13];

            int payloadStart = t + dataOff;
            int payloadLen = length - payloadStart;
            if (payloadLen < 0) payloadLen = 0;

            byte[] srcIpBytes = new byte[isIpv6 ? 16 : 4];
            byte[] dstIpBytes = new byte[isIpv6 ? 16 : 4];

            if (isIpv6)
            {
                System.Buffer.BlockCopy(buf, 8, srcIpBytes, 0, 16);
                System.Buffer.BlockCopy(buf, 24, dstIpBytes, 0, 16);
            }
            else
            {
                System.Buffer.BlockCopy(buf, 12, srcIpBytes, 0, 4);
                System.Buffer.BlockCopy(buf, 16, dstIpBytes, 0, 4);
            }

            string key = $"{(isIpv6 ? "v6" : "v4")}:{BitConverter.ToString(srcIpBytes)}:{srcPort}->{BitConverter.ToString(dstIpBytes)}:{dstPort}";

            TcpConn c;

            if ((flags & RST) != 0)
            {
                FileLog.W($"[TCP STATE] RST received for {key}");
                if (_conns.TryRemove(key, out c)) CloseConnLocal(c);
                return;
            }

            if ((flags & SYN) != 0 && (flags & ACK) == 0)
            {
                if (_conns.TryGetValue(key, out c))
                {
                    FileLog.W($"[TCP STATE] Retransmit SYN, resending SYN-ACK for {key}");
                    lock (c.Lock) ResendSynAck(c);
                    return;
                }

                ushort sid = NextSid();

                c = new TcpConn
                {
                    Key = key,
                    Sid = sid,
                    IsIpv6 = isIpv6,
                    SrcIp = srcIpBytes,
                    DstIp = dstIpBytes,
                    SrcPort = srcPort,
                    DstPort = dstPort,
                    MySeq = NextIsn(),
                    PeerSeq = seq + 1,
                    State = TcpState.SynReceived
                };

                if (!isIpv6 && IsProxyIp(dstIpBytes))
                {
                    c.IsProxy = true; // цель узнаем из строки CONNECT/GET
                    FileLog.Important($"[PROXY SYN] SYN на прокси {dstIpBytes[0]}.{dstIpBytes[1]}.{dstIpBytes[2]}.{dstIpBytes[3]}:{dstPort} (sid {sid}) — AppContainer достучался до TUN!");
                }
                else if (!isIpv6 && FakeDns.TryResolve(dstIpBytes, out byte[] realIp, out string fakeDomain))
                {
                    c.DnsQueryDomain = fakeDomain;  // используется в SendMuxDataAsync для addrType=0x02
                    FileLog.W($"[FAKE DNS HIT] SYN to fake {dstIpBytes[0]}.{dstIpBytes[1]}.{dstIpBytes[2]}.{dstIpBytes[3]}:{dstPort} -> {fakeDomain} (real {realIp[0]}.{realIp[1]}.{realIp[2]}.{realIp[3]})");
                }


                _conns[key] = c;
                _muxSessions[sid] = c;
                c.OsAckedSeq = c.MySeq; // на старте inflight = 0

                FileLog.W($"[TCP STATE] New SYN. Sending initial SYN-ACK. Key: {key}");
                lock (c.Lock) SendSynAckInitial(c);
                if (!DirectMode) Task.Run(() => EnsureAtLeastOneCarrierAsync());
                return;
            }

            if (!_conns.TryGetValue(key, out c))
            {
                if ((flags & FIN) == 0) SendRstFor(buf, ipHeaderLen, seq, payloadLen, flags, isIpv6);
                return;
            }

            if ((flags & ACK) != 0)
            {
                uint ackNum = ReadU32(buf, t + 8);
                int win = (buf[t + 14] << 8) | buf[t + 15];
                lock (c.Lock)
                {
                    if ((int)(ackNum - c.OsAckedSeq) > 0) c.OsAckedSeq = ackNum; // только вперёд (с учётом wraparound)
                    c.OsWindow = win;
                }
            }

            if (c.State == TcpState.SynReceived && (flags & ACK) != 0)
            {
                c.State = TcpState.Established;
                FileLog.W($"[TCP STATE] Established! Handshake complete for {key}");
            }

            bool hasData = payloadLen > 0;
            bool isFin = (flags & FIN) != 0;

            if (hasData || isFin)
            {
                lock (c.Lock)
                {
                    // Backpressure к ОС: если очередь исходящих MUX-данных этого сабстрима
                    // переполнена, НЕ принимаем новые байты (не двигаем PeerSeq) и шлём
                    // дубль-ACK на последний принятый байт. ОС придержит данные у себя и
                    // пришлёт позже. Так мы НИКОГДА не выбрасываем уже заакканные байты
                    // потока (именно это рвало соединение под нагрузкой).
                    if (hasData && seq == c.PeerSeq && c.SendQueue.Count >= MaxConnSendQueue)
                    {
                        SendAck(c);
                        return;
                    }

                    byte[] dataToMux = null;
                    if (hasData && seq == c.PeerSeq)
                    {
                        dataToMux = new byte[payloadLen];
                        System.Buffer.BlockCopy(buf, payloadStart, dataToMux, 0, payloadLen);
                        c.PeerSeq += (uint)payloadLen;
                        c.LastActivityUtc = DateTime.UtcNow;
                    }

                    bool sendFin = false;
                    if (isFin)
                    {
                        c.PeerSeq += 1;
                        sendFin = true;
                    }

                    if (c.IsProxy && !c.ProxyEstablished)
                    {
                        if (dataToMux != null) HandleProxyHead(c, dataToMux);
                        SendAck(c);
                        if (sendFin) CloseConnLocal(c);
                    }
                    else if (dataToMux != null || sendFin)
                    {
                        if (FileLog.Verbose) FileLog.W($"[TCP DATA] Queueing {payloadLen} bytes to MUX for {key}");
                        
                        QueueMuxData(c, dataToMux, sendFin);
                        SendAck(c);
                    }
                    else
                    {
                        SendAck(c);
                    }
                }
            }
        }

        private void QueueMuxData(TcpConn c, byte[] data, bool isFin)
        {
            // Никаких молчаливых потерь: продюсер (HandleTcpFromOs) уже притормаживает ОС
            // до вызова, поэтому очередь ограничена. Выбрасывать уже заакканные байты нельзя.
            if (data != null)
                c.SendQueue.Enqueue(data);

            if (isFin)
            {
                lock (c.Lock) { c.SendFinPending = true; }
            }

            if (Interlocked.CompareExchange(ref c.Sending, 1, 0) == 0)
                Task.Run(() => ProcessSendQueueAsync(c));
        }

        private async Task ProcessSendQueueAsync(TcpConn c)
        {
            try
            {
                while (c.SendQueue.TryDequeue(out byte[] payload))
                {
                    if (DirectMode) await SendDirectDataAsync(c, payload);
                    else await SendMuxDataAsync(c, payload);
                }

                bool sendFin = false;
                lock (c.Lock)
                {
                    if (c.SendFinPending) { c.SendFinPending = false; sendFin = true; }
                }

                if (sendFin)
                {
                    if (DirectMode)
                    {
                        // Локальный FIN означает только «клиент больше ничего не пришлёт»,
                        // а не «соединение закрыто»: ответ сервера может быть ещё в пути.
                        // Раньше мы гасили здесь весь туннельный сокет, и недочитанный
                        // downstream пропадал — отсюда ответы, обрезанные на 262 байтах.
                        // Полузакрытия у StreamSocket нет, поэтому даём downstream дочитаться
                        // и закрываем по льготному таймауту, чтобы слоты не утекали.
                        var halfClosed = c.DirectConn;
                        _ = Task.Run(async () =>
                        {
                            await Task.Delay(TcpConn.HalfCloseGraceMs);
                            try { halfClosed?.Close(); } catch { }
                            CloseConnLocal(c);
                        });
                    }
                    else
                    {
                        await SendMuxEndAsync(c);
                        CloseConnLocal(c);
                    }
                }
            }
            catch (Exception ex)
            {
                FileLog.W($"[NAT ENGINE ERROR] ProcessSendQueue failed: {ex.Message}");
            }
            finally
            {
                Interlocked.Exchange(ref c.Sending, 0);

                lock (c.Lock)
                {
                    if (!c.SendQueue.IsEmpty || c.SendFinPending)
                    {
                        if (Interlocked.CompareExchange(ref c.Sending, 1, 0) == 0)
                        {
                            Task.Run(() => ProcessSendQueueAsync(c));
                        }
                    }
                }
            }
        }

        // Открывает (лениво, один раз) персональное VLESS-соединение к РЕАЛЬНОМУ адресу и
        // запускает насос чтения downstream. Вызывается строго последовательно для данного c
        // (гарантировано флагом c.Sending в ProcessSendQueueAsync).
        private async Task EnsureDirectConnAsync(TcpConn c)
        {
            if (c.DirectConn != null) return;

            if (Volatile.Read(ref c.DirectSlotState) == 0)
            {
                await _directSlots.WaitAsync();
                Interlocked.Exchange(ref c.DirectSlotState, 1);
                if (Volatile.Read(ref c.Closing) == 1 || c.State == TcpState.Closed)
                { ReleaseDirectSlot(c); return; }
            }

            ushort port = c.IsProxy ? c.ProxyTargetPort : c.DstPort;
            bool useDomain = !c.IsIpv6
                             && !string.IsNullOrEmpty(c.DnsQueryDomain)
                             && (FakeDns.IsFakeIp(c.DstIp) || c.IsProxy);

            bool isSs = Config != null && Config.IsShadowsocks;

            // Цепочка Amnezia: реле доводит только до парного выходного узла
            // (проверено — запрос к его IP через реле вернул живой ответ, а
            // доменные назначения реле закрывает). Поэтому сначала поднимаем
            // звено до реле с назначением «выходной узел», а настоящий адрес
            // сайта уходит уже во втором звене поверх него.
            VlessConnection chainOuter = null;
            if (!isSs && Config != null &&
                !string.IsNullOrEmpty(Config.ChainExitHost) && Config.ChainExitPort > 0)
            {
                byte[] exitIp;
                if (VlessConnection.TryParseIpv4Public(Config.ChainExitHost, out exitIp))
                {
                    chainOuter = new VlessConnection(Config, Channel);
                    chainOuter.ConfigureDirectIp(exitIp, false, (ushort)Config.ChainExitPort);
                    if (!await chainOuter.StartAsync())
                    {
                        FileLog.Important("[CHAIN] Первое звено (реле) не поднялось.");
                        try { chainOuter.Close(); } catch { }
                        ReleaseDirectSlot(c);
                        CloseConnLocal(c);
                        return;
                    }
                    FileLog.Important($"[CHAIN] Первое звено поднято: реле → {Config.ChainExitHost}:{Config.ChainExitPort}.");
                }
                else
                {
                    FileLog.Important($"[CHAIN] Выходной узел '{Config.ChainExitHost}' не IPv4 — цепочку не строю.");
                }
            }

            // Второе звено проверяется выходным узлом по ЕГО ключам REALITY —
            // с ключами реле он отбрасывает на прикрытие. Поэтому конфиг тут
            // свой: адрес, uuid и параметры reality берутся от выходного узла.
            var connCfg = Config;
            if (chainOuter != null)
            {
                connCfg = Config.CloneForChainExit();
            }

            IDirectConn conn = isSs ? (IDirectConn)new SsConnection(connCfg)
                                    : new VlessConnection(connCfg, Channel);
            if (chainOuter != null)
            {
                ((VlessConnection)conn).UseChainTransport(chainOuter);
            }
            if (useDomain) conn.ConfigureDirectDomain(c.DnsQueryDomain, port);
            else conn.ConfigureDirectIp(c.DstIp, c.IsIpv6, port);

            string proto = isSs ? "Shadowsocks" : "VLESS";
            string tgt = useDomain ? c.DnsQueryDomain
                                   : (c.IsIpv6 ? "[v6]" : $"{c.DstIp[0]}.{c.DstIp[1]}.{c.DstIp[2]}.{c.DstIp[3]}");
            FileLog.Important($"[DIRECT] Открываю {proto} к {tgt}:{port} (key {c.Key})");

            if (!await conn.StartAsync())
            {
                FileLog.Important($"[DIRECT] Не удалось поднять {proto} к {tgt}:{port}");
                try { conn.Close(); } catch { }
                ReleaseDirectSlot(c);
                CloseConnLocal(c);
                return;
            }

            c.DirectConn = conn;
            _ = Task.Run(() => DirectReadLoopAsync(c, conn));
        }

        private async Task SendDirectDataAsync(TcpConn c, byte[] payload)
        {
            await EnsureDirectConnAsync(c);
            var conn = c.DirectConn;
            if (conn == null || c.State == TcpState.Closed) return;

            try
            {
                await conn.WriteUnderlyingAsync(payload ?? new byte[0]);
            }
            catch (Exception ex)
            {
                FileLog.W($"[DIRECT] Ошибка записи {c.Key}: {ex.Message}");
                try { conn.Close(); } catch { }
                CloseConnLocal(c);
            }
        }

        // Насос downstream: читает payload из персонального соединения и вливает в ОС.
        private async Task DirectReadLoopAsync(TcpConn c, IDirectConn conn)
        {
            long got = 0;
            string why = "локальное соединение закрыто";
            try
            {
                while (!_stopped && c.State != TcpState.Closed)
                {
                    byte[] data;
                    try { data = await conn.ReadPayloadAsync(); }
                    catch (ObjectDisposedException) { why = "сокет освобождён"; break; }
                    catch (System.Runtime.InteropServices.COMException) { why = "ввод-вывод прерван"; break; }   // I/O aborted при закрытии
                    catch (NullReferenceException) { why = "сокет освобождён"; break; }

                    if (data == null) { why = "сервер закрыл поток"; break; }
                    if (data.Length == 0) continue;
                    if (c.State == TcpState.Closed) break;
                    got += data.Length;
                    c.LastActivityUtc = DateTime.UtcNow;
                    if (FileLog.Verbose)
                    {
                        int n = Math.Min(data.Length, 16);
                        var sb = new StringBuilder();
                        for (int i = 0; i < n; i++) sb.Append(data[i].ToString("X2")).Append(' ');
                        FileLog.W($"[DIRECT->OS] {c.Key} {data.Length}b: {sb}");
                    }
                    await InjectDataToOs(c, data);
                }
            }
            catch (Exception ex) { why = ex.Message; FileLog.W($"[DIRECT READ] {c.Key}: {ex.Message}"); }
            finally
            {
                // Цикл раньше завершался молча, поэтому «сервер закрыл соединение» и
                // «сервер молчит, а мы ждём» выглядели в логе совершенно одинаково —
                // никак. А это два разных диагноза, и различие между ними решающее.
                FileLog.Important($"[DIRECT<-] {c.Key}: downstream завершён ({why}), принято {got}б.");
                try { conn.Close(); } catch { }
                CloseConnLocal(c);
            }
        }

        private void ReleaseDirectSlot(TcpConn c)
        {
            if (Interlocked.Exchange(ref c.DirectSlotState, 0) == 1)
            {
                try { _directSlots.Release(); } catch { }
            }
        }


        public void SetPreEstablishedMux(VlessConnection conn)
        {
            var carrier = new MuxCarrier { Conn = conn, Running = true };
            lock (_carriersLock) _carriers.Add(carrier);
            _ = Task.Run(() => MuxReadLoopAsync(carrier));

            _muxKeepAlive = new System.Threading.Timer(
                _ => { _ = SendMuxKeepAliveAsync(); }, null, 3000, 3000);

            FileLog.Important("[TCP STACK] MUX (канал #1) установлен ДО старта TUN.");
        }

        private async Task SendMuxDataAsync(TcpConn c, byte[] payload)
        {
            // Несущий канал теперь подбирается в SendMuxChunkAsync (для New-кадра).
            if (payload == null || payload.Length == 0)
            {
                await SendMuxChunkAsync(c, null, 0, 0);
                return;
            }
            int offset = 0;
            while (offset < payload.Length)
            {
                int chunkLen = Math.Min(MSS, payload.Length - offset);
                await SendMuxChunkAsync(c, payload, offset, chunkLen);
                offset += chunkLen;
            }
        }

        private async Task SendMuxChunkAsync(TcpConn c, byte[] payload, int offset, int chunkLen)
        {
            if (!c.MuxNewSent && Volatile.Read(ref c.MuxSlotState) == 0)
            {
                await _tcpSlots.WaitAsync();
                Interlocked.Exchange(ref c.MuxSlotState, 1);

                if (Volatile.Read(ref c.Closing) == 1 || c.State == TcpState.Closed)
                { ReleaseSlotAndCarrier(c); return; }

                c.Carrier = await AcquireCarrierAsync();

                if (Volatile.Read(ref c.Closing) == 1 || c.State == TcpState.Closed)
                { ReleaseSlotAndCarrier(c); return; }
            }

            var carrier = c.Carrier;
            if (carrier == null || !carrier.Running) { CloseConnLocal(c); return; }

            await carrier.WriteLock.WaitAsync();
            try
            {
                using (var ms = new MemoryStream())
                {
                    bool isNew = !c.MuxNewSent;
                    c.MuxNewSent = true;

                    if (isNew)
                    {
                        ushort muxPort = c.IsProxy ? c.ProxyTargetPort : c.DstPort;
                        bool useDomain = !c.IsIpv6
                                         && !string.IsNullOrEmpty(c.DnsQueryDomain)
                                         && (FakeDns.IsFakeIp(c.DstIp) || c.IsProxy);

                        byte[] meta;
                        if (useDomain)
                        {
                            byte[] nameBytes = System.Text.Encoding.UTF8.GetBytes(c.DnsQueryDomain);
                            if (nameBytes.Length > 255) useDomain = false;
                            else
                            {
                                meta = new byte[8 + 1 + nameBytes.Length];
                                meta[0] = (byte)(c.Sid >> 8); meta[1] = (byte)c.Sid;
                                meta[2] = 0x01; meta[3] = 0x01; meta[4] = 0x01;
                                meta[5] = (byte)(muxPort >> 8); meta[6] = (byte)muxPort;
                                meta[7] = 0x02; meta[8] = (byte)nameBytes.Length;
                                System.Buffer.BlockCopy(nameBytes, 0, meta, 9, nameBytes.Length);
                                ms.WriteByte((byte)(meta.Length >> 8)); ms.WriteByte((byte)meta.Length);
                                ms.Write(meta, 0, meta.Length);
                                goto AFTER_META;
                            }
                        }
                        {
                            int addrLen = c.IsIpv6 ? 16 : 4;
                            meta = new byte[8 + addrLen];
                            meta[0] = (byte)(c.Sid >> 8); meta[1] = (byte)c.Sid;
                            meta[2] = 0x01; meta[3] = 0x01; meta[4] = 0x01;
                            meta[5] = (byte)(muxPort >> 8); meta[6] = (byte)muxPort;
                            meta[7] = c.IsIpv6 ? (byte)0x03 : (byte)0x01;
                            System.Buffer.BlockCopy(c.DstIp, 0, meta, 8, addrLen);
                            ms.WriteByte((byte)(meta.Length >> 8)); ms.WriteByte((byte)meta.Length);
                            ms.Write(meta, 0, meta.Length);
                        }
                    AFTER_META:;
                    }
                    else
                    {
                        byte[] meta = new byte[4];
                        meta[0] = (byte)(c.Sid >> 8); meta[1] = (byte)c.Sid;
                        meta[2] = 0x02; meta[3] = 0x01;
                        ms.WriteByte((byte)(meta.Length >> 8)); ms.WriteByte((byte)meta.Length);
                        ms.Write(meta, 0, meta.Length);
                    }

                    ms.WriteByte((byte)(chunkLen >> 8)); ms.WriteByte((byte)chunkLen);
                    if (chunkLen > 0) ms.Write(payload, offset, chunkLen);

                    await carrier.Conn.WriteUnderlyingAsync(ms.ToArray());
                }
            }
            catch { carrier.Running = false; try { carrier.Conn?.Close(); } catch { } }
            finally { carrier.WriteLock.Release(); }
        }

        private Task SendMuxEndAsync(TcpConn c) => SendMuxEndBySidAsync(c.Carrier, c.Sid);

        private async Task SendMuxEndBySidAsync(MuxCarrier carrier, ushort sid)
        {
            if (carrier == null || !carrier.Running) return;
            await carrier.WriteLock.WaitAsync();
            try
            {
                byte[] frame = new byte[6];
                frame[1] = 4;
                frame[2] = (byte)(sid >> 8); frame[3] = (byte)sid;
                frame[4] = 0x03; // Status = End
                await carrier.Conn.WriteUnderlyingAsync(frame);
            }
            catch { carrier.Running = false; try { carrier.Conn?.Close(); } catch { } }
            finally { carrier.WriteLock.Release(); }
        }

        private async Task MuxReadLoopAsync(MuxCarrier carrier)
        {
            var conn = carrier.Conn;
            var inBuf = new ByteAccumulator();
            try
            {
                while (carrier.Running)
                {

                    FileLog.Important($"[MUXLOOP] жду downstream...");
                    byte[] raw = await conn.ReadVlessPayloadAsync();
                    FileLog.Important($"[MUXLOOP] получено {(raw == null ? "null" : raw.Length + "b")}");
                    if (raw == null) break;
                    if (raw.Length == 0) continue;
                    inBuf.Append(raw, raw.Length);

                    while (inBuf.Count >= 2)
                    {
                        int metaLen = (inBuf[0] << 8) | inBuf[1];
                        if (inBuf.Count < 2 + metaLen) break;
                        if (metaLen < 4) throw new Exception("Mux metaLen too small");

                        ushort sid = (ushort)((inBuf[2] << 8) | inBuf[3]);
                        byte status = inBuf[4];
                        byte opt = inBuf[5];

                        int payloadLenOff = 2 + metaLen;
                        int totalFrameLen = payloadLenOff;
                        byte[] payload = null;
                        bool hasData = (opt & 0x01) != 0;

                        if (hasData)
                        {
                            if (inBuf.Count < payloadLenOff + 2) break;
                            int payloadLen = (inBuf[payloadLenOff] << 8) | inBuf[payloadLenOff + 1];
                            totalFrameLen += 2 + payloadLen;
                            if (inBuf.Count < totalFrameLen) break;
                            if (payloadLen > 0) payload = inBuf.Slice(payloadLenOff + 2, payloadLen);
                        }

                        if (status == 0x01 || status == 0x02) // New / Keep
                        {
                            if (_muxSessions.TryGetValue(sid, out var c))
                            {
                                c.LastActivityUtc = DateTime.UtcNow;
                                if (payload != null)
                                {
                                    if (c.Key.StartsWith("DNS:")) HandleDnsTcpResponse(c, payload);
                                    else await EnqueueDownToOs(carrier, c, payload);
                                }
                            }
                            else if (payload != null)
                            {
                                // Данные для уже закрытого сабстрима: приложение закрыло сокет, но сервер
                                // продолжает слать буфер (видно в дампе как непрерывный поток на "мёртвые" sid).
                                // Шлём End назад -> сервер прекращает, освобождает свой слот и перестаёт
                                // забивать несущий канал, вытесняя upload-сабстримы.
                                long nowT = Environment.TickCount;
                                if (!_orphanEnded.TryGetValue(sid, out long prev) || (nowT - prev) > 2000)
                                {
                                    _orphanEnded[sid] = nowT;
                                    _ = SendMuxEndBySidAsync(carrier, sid); // fire-and-forget, чтобы не тормозить чтение
                                }
                            }
                        }
                        else if (status == 0x03)
                        {
                            if (_muxSessions.TryRemove(sid, out var c))
                            {
                                if (c.Key.StartsWith("DNS:"))
                                {
                                    c.State = TcpState.Closed;
                                    _dnsSemaphore.Release();
                                    ReleaseSlotAndCarrier(c);
                                }
                                else CloseConnLocal(c);
                            }
                        }

                        inBuf.Consume(totalFrameLen);
                    }
                }
            }
            catch { }
            finally
            {
                carrier.Running = false;
                conn.Close();
                lock (_carriersLock) _carriers.Remove(carrier);

                // Закрываем ТОЛЬКО сабстримы этого канала — остальные каналы живут дальше.
                foreach (var kv in _muxSessions)
                {
                    var ac = kv.Value;
                    if (ac.Carrier != carrier) continue;
                    if (ac.Key.StartsWith("DNS:"))
                    {
                        if (_muxSessions.TryRemove(ac.Sid, out _)) _dnsSemaphore.Release();
                        ReleaseSlotAndCarrier(ac);
                    }
                    else CloseConnLocal(ac);
                }
            }
        }


        // Складывает payload в пер-коннекшн очередь и сразу возвращается — read-loop канала
        // больше НЕ ждёт окно ОС внутри себя и тут же идёт к следующему sid.
        private async Task EnqueueDownToOs(MuxCarrier carrier, TcpConn c, byte[] payload)
        {
            if (payload == null || payload.Length == 0) return;

            c.RecvQueue.Enqueue(payload);
            Interlocked.Add(ref c.RecvQueuedBytes, payload.Length);

            if (Interlocked.CompareExchange(ref c.Receiving, 1, 0) == 0)
                _ = Task.Run(() => ProcessRecvQueueAsync(c));

            // Backpressure к серверу БЕЗ HOL для лёгких стримов: притормаживаем чтение несущего
            // канала ТОЛЬКО если именно ЭТОТ сабстрим реально переполнен. Здоровые контрол-стримы
            // (hello, аналитика) сливаются мгновенно и сюда не попадают вообще.
            while (Volatile.Read(ref c.RecvQueuedBytes) > MaxConnRecvBytes)
            {
                if (_stopped || !carrier.Running || c.State == TcpState.Closed) break;
                await Task.Delay(5);
            }
        }

        // Насос одного сабстрима: гонит входящие чанки в ОС с flow-control (Delay(5) на окно)
        // на СВОЕЙ таске, не трогая read-loop канала. Точная копия логики ProcessSendQueueAsync.
        private async Task ProcessRecvQueueAsync(TcpConn c)
        {
            try
            {
                while (c.RecvQueue.TryDequeue(out byte[] payload))
                {
                    Interlocked.Add(ref c.RecvQueuedBytes, -payload.Length);
                    await InjectDataToOs(c, payload);
                    if (c.State == TcpState.Closed || _stopped) break;
                }
            }
            catch (Exception ex)
            {
                FileLog.W($"[NAT ENGINE ERROR] ProcessRecvQueue failed: {ex.Message}");
            }
            finally
            {
                Interlocked.Exchange(ref c.Receiving, 0);
                if (!c.RecvQueue.IsEmpty && c.State != TcpState.Closed && !_stopped)
                {
                    if (Interlocked.CompareExchange(ref c.Receiving, 1, 0) == 0)
                        _ = Task.Run(() => ProcessRecvQueueAsync(c));
                }
            }
        }

        private async Task InjectDataToOs(TcpConn c, byte[] payload)
        {
            if (payload == null || payload.Length == 0) return;
            c.LastActivityUtc = DateTime.UtcNow;

            int off = 0;
            while (off < payload.Length)
            {
                int windowWaitMs = 0;
                int chunk;

                while (true)
                {
                    int inflight, win;
                    lock (c.Lock)
                    {
                        inflight = (int)(c.MySeq - c.OsAckedSeq);
                        win = c.OsWindow;
                    }

                    // Сколько байт реально влезает в окно приёма ОС ПРЯМО СЕЙЧАС.
                    int avail = win - inflight;
                    int remaining = payload.Length - off;
                    bool globalOk = Volatile.Read(ref _osRxCount) < 1024;

                    // КЛЮЧЕВОЕ: НИКОГДА не пишем сверх окна. Ретрансмиссии у стека нет,
                    // поэтому сегмент, отправленный в переполненное (в т.ч. нулевое) окно,
                    // ОС молча отбросит → в потоке образуется дыра → соединение зависает
                    // навсегда. Это и есть затык на ~20-й секунде, когда плеер набрал
                    // буфер и ОС схлопнула окно приёма.
                    // Условие (avail >= MSS || inflight == 0 || avail >= remaining) —
                    // защита от silly-window: обычно ждём место под целый MSS, но если
                    // в полёте ничего нет или это остаток payload, шлём и меньше, чтобы
                    // не словить дедлок на маленьком окне.
                    bool canSend = globalOk && avail >= 1 &&
                                   (avail >= MSS || inflight == 0 || avail >= remaining);

                    if (canSend)
                    {
                        chunk = Math.Min(Math.Min(MSS, remaining), avail);
                        break;
                    }

                    if (c.State == TcpState.Closed || _stopped) return;

                    await Task.Delay(5);

                    windowWaitMs += 5;
                    if (windowWaitMs > 30000)
                    {
                        FileLog.W($"[FLOWCTRL] Окно ОС или очередь заблокированы >30с, закрываю {c.Key}");
                        var carrier = c.Carrier; var sid = c.Sid;
                        CloseConnLocal(c);
                        if (carrier != null) _ = SendMuxEndBySidAsync(carrier, sid);
                        return;
                    }
                }

                byte[] seg;
                lock (c.Lock)
                {
                    byte flags = ACK;
                    if (off + chunk == payload.Length) flags |= PSH;
                    seg = BuildSegment(c, flags, c.MySeq, c.PeerSeq, payload, off, chunk, false);
                    c.MySeq += (uint)chunk;
                }
                EnqueueToOs(seg, seg.Length, trigger: true);
                off += chunk;
            }
        }

        // ======================= HTTP(S)-ПРОКСИ =======================
        // Виртуальный прокси: клиент (Edge) подключается к ProxyIp, шлёт CONNECT host:port
        // (https) или absolute-form GET http://host/... (http). Мы локально отыгрываем прокси
        // и открываем MUX-сабстрим к реальному хосту по домену. Для https — сквозной TLS без
        // подмены (Edge проверяет настоящий сертификат хоста через CONNECT-туннель).

        // Синхронная инъекция готовых байт клиенту как TCP-сегментов (для ответа "200").
        private void InjectRawToOs(TcpConn c, byte[] data)
        {
            if (data == null || data.Length == 0) return;
            int off = 0;
            while (off < data.Length)
            {
                int chunk = Math.Min(MSS, data.Length - off);
                byte[] seg;
                lock (c.Lock)
                {
                    byte flags = ACK;
                    if (off + chunk == data.Length) flags |= PSH;
                    seg = BuildSegment(c, flags, c.MySeq, c.PeerSeq, data, off, chunk, false);
                    c.MySeq += (uint)chunk;
                }
                EnqueueToOs(seg, seg.Length, true);
                off += chunk;
            }
        }

        private static int FindHeaderEnd(List<byte> buf)
        {
            for (int i = 0; i + 3 < buf.Count; i++)
            {
                if (buf[i] == 0x0D && buf[i + 1] == 0x0A && buf[i + 2] == 0x0D && buf[i + 3] == 0x0A)
                    return i;
            }
            return -1;
        }

        private static void ParseHostPort(string s, int defPort, out string host, out int port)
        {
            host = s; port = defPort;
            if (string.IsNullOrEmpty(s)) return;
            int idx = s.LastIndexOf(':');
            if (idx > 0 && idx < s.Length - 1)
            {
                string p = s.Substring(idx + 1);
                if (int.TryParse(p, out int pv) && pv > 0 && pv < 65536)
                {
                    host = s.Substring(0, idx);
                    port = pv;
                }
            }
        }

        private static bool ParseAbsoluteUrl(string url, out string host, out int port, out string pathAndQuery)
        {
            host = null; port = 80; pathAndQuery = "/";
            try
            {
                int scheme = url.IndexOf("://", StringComparison.OrdinalIgnoreCase);
                int start = 0;
                if (scheme >= 0)
                {
                    string sch = url.Substring(0, scheme).ToLowerInvariant();
                    if (sch == "https") port = 443;
                    start = scheme + 3;
                }
                int slash = url.IndexOf('/', start);
                string authority = (slash < 0) ? url.Substring(start) : url.Substring(start, slash - start);
                pathAndQuery = (slash < 0) ? "/" : url.Substring(slash);
                ParseHostPort(authority, port, out host, out port);
                return !string.IsNullOrEmpty(host);
            }
            catch { return false; }
        }

        private void HandleProxyHead(TcpConn c, byte[] data)
        {
            c.ProxyHead.AddRange(data);
            if (c.ProxyHead.Count > 32768) { CloseConnLocal(c); return; } // защита от мусора

            int headEnd = FindHeaderEnd(c.ProxyHead);
            if (headEnd < 0) return; // ждём полный заголовок (\r\n\r\n)

            string head = Encoding.ASCII.GetString(c.ProxyHead.ToArray(), 0, headEnd);
            string[] lines = head.Split(new[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0) { CloseConnLocal(c); return; }
            string[] rl = lines[0].Split(' ');
            if (rl.Length < 3) { CloseConnLocal(c); return; }
            string method = rl[0];
            string target = rl[1];
            string httpVer = rl[2];
            int after = headEnd + 4;

            if (method.Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                ParseHostPort(target, 443, out string host, out int port);
                c.DnsQueryDomain = host;
                c.ProxyTargetPort = (ushort)port;
                c.ProxyEstablished = true;

                // Подтверждаем туннель клиенту; дальше пойдёт сырой TLS.
                InjectRawToOs(c, Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n"));

                // Данные после заголовка (обычно нет — клиент ждёт 200) — в MUX.
                if (c.ProxyHead.Count > after)
                {
                    byte[] rest = c.ProxyHead.GetRange(after, c.ProxyHead.Count - after).ToArray();
                    QueueMuxData(c, rest, false);
                }
                c.ProxyHead.Clear();
                FileLog.Important($"[PROXY CONNECT] {host}:{port} (sid {c.Sid})");
            }
            else
            {
                // http через прокси: absolute-form GET http://host/path -> origin-form.
                if (!ParseAbsoluteUrl(target, out string host, out int port, out string pathOnly))
                {
                    CloseConnLocal(c);
                    return;
                }
                c.DnsQueryDomain = host;
                c.ProxyTargetPort = (ushort)port;
                c.ProxyEstablished = true;

                var sb = new StringBuilder();
                sb.Append(method).Append(' ').Append(pathOnly).Append(' ').Append(httpVer).Append("\r\n");
                for (int i = 1; i < lines.Length; i++)
                {
                    string ln = lines[i];
                    if (ln.Length == 0) continue;
                    if (ln.StartsWith("Proxy-Connection", StringComparison.OrdinalIgnoreCase)) continue; // прокси-only
                    sb.Append(ln).Append("\r\n");
                }
                sb.Append("\r\n");
                byte[] reqHead = Encoding.ASCII.GetBytes(sb.ToString());

                byte[] body = (c.ProxyHead.Count > after)
                    ? c.ProxyHead.GetRange(after, c.ProxyHead.Count - after).ToArray()
                    : null;
                c.ProxyHead.Clear();

                QueueMuxData(c, reqHead, false);
                if (body != null && body.Length > 0) QueueMuxData(c, body, false);

                FileLog.Important($"[PROXY HTTP] {method} {host}:{port}{pathOnly} (sid {c.Sid})");
            }
        }

        private void SendSynAckInitial(TcpConn c)
        {
            c.IsnBase = c.MySeq;
            byte[] seg = BuildSegment(c, (byte)(SYN | ACK), c.MySeq, c.PeerSeq, null, 0, 0, true);
            EnqueueToOs(seg, seg.Length);
            c.MySeq += 1;
        }

        private void ResendSynAck(TcpConn c)
        {
            byte[] seg = BuildSegment(c, (byte)(SYN | ACK), c.IsnBase, c.PeerSeq, null, 0, 0, true);
            EnqueueToOs(seg, seg.Length);
        }

        private void SendAck(TcpConn c)
        {
            byte[] seg = BuildSegment(c, ACK, c.MySeq, c.PeerSeq, null, 0, 0, false);
            EnqueueToOs(seg, seg.Length);
        }

        private void SendRstFor(byte[] inBuf, int ipHeaderLen, uint inSeq, int payloadLen, byte inFlags, bool isIpv6)
        {
            int tcpHdrLen = 20;
            int totalLen = ipHeaderLen + tcpHdrLen;
            byte[] b = new byte[totalLen];
            int o = ipHeaderLen;

            if (isIpv6)
            {
                b[0] = 0x60;
                b[4] = 0; b[5] = 20; // Длина полезной нагрузки
                b[6] = 6;            // Протокол TCP
                b[7] = 64;           // Hop Limit
                // Разворачиваем адреса для возврата RST отправителю
                System.Buffer.BlockCopy(inBuf, 24, b, 8, 16);
                System.Buffer.BlockCopy(inBuf, 8, b, 24, 16);
            }
            else
            {
                b[0] = 0x45; b[2] = 0; b[3] = (byte)totalLen; b[6] = 0x40; b[8] = 64; b[9] = 6;
                System.Buffer.BlockCopy(inBuf, 16, b, 12, 4);
                System.Buffer.BlockCopy(inBuf, 12, b, 16, 4);
            }

            ushort sp = (ushort)((inBuf[ipHeaderLen] << 8) | inBuf[ipHeaderLen + 1]);
            ushort dp = (ushort)((inBuf[ipHeaderLen + 2] << 8) | inBuf[ipHeaderLen + 3]);

            b[o + 0] = (byte)(dp >> 8); b[o + 1] = (byte)(dp & 0xFF);
            b[o + 2] = (byte)(sp >> 8); b[o + 3] = (byte)(sp & 0xFF);

            uint ackNum = inSeq + (uint)payloadLen + (((inFlags & SYN) != 0) ? 1u : 0u) + (((inFlags & FIN) != 0) ? 1u : 0u);
            WriteU32(b, o + 4, 0);
            WriteU32(b, o + 8, ackNum);
            b[o + 12] = 0x50;
            b[o + 13] = (byte)(RST | ACK);

            if (isIpv6)
            {
                RecalculateTCPChecksumIpv6(b, 40, totalLen);
            }
            else
            {
                RecalculateIPv4Checksum(b, 20);
                RecalculateTCPChecksum(b, 20, totalLen);
            }
            EnqueueToOs(b, totalLen);
        }

        private void CloseConnLocal(TcpConn c)
        {
            if (Interlocked.Exchange(ref c.Closing, 1) == 1) return;
            c.State = TcpState.Closed;
            _conns.TryRemove(c.Key, out _);

            // ИСПРАВЛЕНИЕ: Освобождаем память закрытой сессии MUX, чтобы избежать убийства процесса системой
            _muxSessions.TryRemove(c.Sid, out _);

            // Возвращаем слот MUX, если этот сабстрим его занимал (ровно один раз —
            // защищено Closing-гвардом в начале метода).
            ReleaseSlotAndCarrier(c);
            ReleaseDirectSlot(c);                       
            try { c.DirectConn?.Close(); } catch { }    

            byte[] seg;
            lock (c.Lock)
            {
                seg = BuildSegment(c, (byte)(FIN | ACK), c.MySeq, c.PeerSeq, null, 0, 0, false);
                c.MySeq += 1;
            }
            EnqueueToOs(seg, seg.Length);
        }

        private byte[] BuildSegment(TcpConn c, byte flags, uint seq, uint ack, byte[] payload, int payloadOff, int payloadLen, bool withMss)
        {
            int tcpHdr = withMss ? 24 : 20;
            int total = (c.IsIpv6 ? 40 : 20) + tcpHdr + payloadLen;
            byte[] b = new byte[total];
            int o;

            if (c.IsIpv6)
            {
                b[0] = 0x60;
                int pLen = tcpHdr + payloadLen;
                b[4] = (byte)(pLen >> 8); b[5] = (byte)(pLen & 0xFF);
                b[6] = 6;  // Next Header = TCP
                b[7] = 64; // Hop Limit
                System.Buffer.BlockCopy(c.DstIp, 0, b, 8, 16);
                System.Buffer.BlockCopy(c.SrcIp, 0, b, 24, 16);
                o = 40;
            }
            else
            {
                b[0] = 0x45;
                b[2] = (byte)(total >> 8); b[3] = (byte)(total & 0xFF);
                b[6] = 0x40;
                b[8] = 64;
                b[9] = 6;
                System.Buffer.BlockCopy(c.DstIp, 0, b, 12, 4);
                System.Buffer.BlockCopy(c.SrcIp, 0, b, 16, 4);
                o = 20;
            }

            b[o + 0] = (byte)(c.DstPort >> 8); b[o + 1] = (byte)(c.DstPort & 0xFF);
            b[o + 2] = (byte)(c.SrcPort >> 8); b[o + 3] = (byte)(c.SrcPort & 0xFF);
            WriteU32(b, o + 4, seq);
            WriteU32(b, o + 8, ack);
            b[o + 12] = (byte)((tcpHdr / 4) << 4);
            b[o + 13] = flags;
            b[o + 14] = 0xFF; b[o + 15] = 0xFF;

            if (withMss)
            {
                b[o + 20] = 2; b[o + 21] = 4;
                b[o + 22] = (byte)(MSS >> 8); b[o + 23] = (byte)(MSS & 0xFF);
            }
            if (payloadLen > 0)
                System.Buffer.BlockCopy(payload, payloadOff, b, o + tcpHdr, payloadLen);

            if (c.IsIpv6)
            {
                RecalculateTCPChecksumIpv6(b, 40, total);
            }
            else
            {
                RecalculateIPv4Checksum(b, 20);
                RecalculateTCPChecksum(b, 20, total);
            }

            return b;
        }

        private void EnqueueToOs(byte[] buf, int length, bool trigger = true)
        {
            if (_stopped) return;
            try
            {
                bool isOdd = (length % 2 != 0);
                int bufLen = isOdd ? (length + 1) : length;

                byte[] rawPacket = new byte[bufLen];
                System.Buffer.BlockCopy(buf, 0, rawPacket, 0, length);

                if (isOdd)
                {
                    rawPacket[bufLen - 1] = 0;
                }

                if (Volatile.Read(ref _osRxCount) >= MaxOsRxQueue)
                {
                    if (OsRxQueue.TryDequeue(out _)) Interlocked.Decrement(ref _osRxCount);
                    FileLog.Important($"[OSRX DROP] всего отброшено={Interlocked.Increment(ref _osRxDropped)}");
                }

                OsRxQueue.Enqueue(rawPacket);
                Interlocked.Increment(ref _osRxCount);

                if (trigger)
                {
                    // Шлем быстрый триггер для низкого пинга.
                    // Если он потеряется, резервный _drainTimer подстрахует и пнет ОС через 100 мс.
                    if (Interlocked.CompareExchange(ref _triggerPending, 1, 0) == 0)
                    {
                        try { TriggerDecapsulate?.Invoke(); } catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                FileLog.W($"[DNS DEBUG ERROR] Исключение в EnqueueToOs: {ex}");
            }
        }

        private static void WriteU32(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
        private static uint ReadU32(byte[] b, int o) { return (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]); }
        private uint NextIsn()
        {
            byte[] r = new byte[4];
            lock (_rnd) _rnd.NextBytes(r);
            return (uint)((r[0] << 24) | (r[1] << 16) | (r[2] << 8) | r[3]);
        }

        // ============================================================
        //  DNS-ПЕРЕХВАТЧИК
        //  AAAA -> локальная NODATA-заглушка (форсим IPv4).
        //  A    -> ЛОКАЛЬНЫЙ ответ fake-IP, БЕЗ round-trip к 8.8.8.8 через MUX.
        //          New-кадр MUX и так несёт домен -> сервер сам резолвит реальный IP.
        //          Это убирает DNS-сабстримы и шторм таймаутов, освобождая бюджет MUX под TCP.
        //  прочее -> старый путь через MUX (ResolveDnsOverTcpAsync), на случай TXT/SRV/PTR.
        // ============================================================
        private bool HandleUdpFromOs(byte[] buf, int length, int ipHeaderLen)
        {
            int udpStart = ipHeaderLen;
            if (length < udpStart + 8) return false;

            ushort srcPort = (ushort)((buf[udpStart] << 8) | buf[udpStart + 1]);
            ushort dstPort = (ushort)((buf[udpStart + 2] << 8) | buf[udpStart + 3]);
            if (FileLog.Verbose) FileLog.W($"[UDP] {buf[12]}.{buf[13]}.{buf[14]}.{buf[15]}:{srcPort} -> {buf[16]}.{buf[17]}.{buf[18]}.{buf[19]}:{dstPort} len={length}");
            if (dstPort != 53) return false;

            int udpLen = (buf[udpStart + 4] << 8) | buf[udpStart + 5];
            if (udpLen <= 8 || udpStart + udpLen > length) return false;

            byte[] dnsPayload = new byte[udpLen - 8];
            System.Buffer.BlockCopy(buf, udpStart + 8, dnsPayload, 0, dnsPayload.Length);

            byte[] srcIpBytes = { buf[12], buf[13], buf[14], buf[15] };
            byte[] dstIpBytes = { buf[16], buf[17], buf[18], buf[19] };

            // БЛОКИРОВКА IPv6 ЗАПРОСОВ (AAAA):
            if (IsAaaaQuery(dnsPayload))
            {
                byte[] emptyReply = BuildEmptyDnsReply(dnsPayload);
                if (emptyReply != null)
                {
                    string domain = ParseDnsQuestion(dnsPayload);
                    FileLog.W($"[DNS BLOCK AAAA] Локальная заглушка IPv6 (AAAA) для: {domain}");
                    InjectDnsReply(emptyReply, srcIpBytes, dstIpBytes, srcPort, dstPort);
                    return true;
                }
            }

            // ЛОКАЛЬНЫЙ ОТВЕТ НА A-ЗАПРОС (без MUX-сабстрима):
            // Регистрируем стабильный fake-IP для домена в ту же карту FakeDns, которую читает
            // обработчик SYN (FakeDns.TryResolve / IsFakeIp). Реальный IP не нужен — сервер
            // резолвит сам по домену из New-кадра, поэтому передаём заглушку 0.0.0.0.
            if (IsAQuery(dnsPayload))
            {
                string domain = ParseDnsQuestion(dnsPayload);
                if (!string.IsNullOrEmpty(domain) && domain != "Unknown" && domain != "Malformed" && domain != "ErrorParsing")
                {
                    byte[] fakeIp = FakeDns.RegisterStable(domain, FakeDnsPlaceholderRealIp);
                    if (fakeIp != null)
                    {
                        byte[] aReply = BuildFakeAReply(dnsPayload, fakeIp);
                        if (aReply != null)
                        {
                            FileLog.Important($"[FAKE DNS LOCAL] {domain} -> {fakeIp[0]}.{fakeIp[1]}.{fakeIp[2]}.{fakeIp[3]}");
                            InjectDnsReply(aReply, srcIpBytes, dstIpBytes, srcPort, dstPort);
                            return true;
                        }
                    }
                }
                // если что-то пошло не так — падаем на старый путь через MUX ниже
            }

            // В direct-режиме редкие не-A/AAAA запросы (TXT/SRV/PTR) не гоняем по туннелю
            // отдельным соединением — отвечаем пустым NODATA. A резолвится локально (fake), этого
            // хватает для веб-сёрфинга, а заводить ещё одно Reality-соединение под DNS нерентабельно.
            if (DirectMode)
            {
                byte[] empty = BuildEmptyDnsReply(dnsPayload);
                if (empty != null)
                {
                    InjectDnsReply(empty, srcIpBytes, dstIpBytes, srcPort, dstPort);
                    return true;
                }
            }

            ResolveDnsOverTcpAsync(dnsPayload, srcIpBytes, dstIpBytes, srcPort);
            return true;
        }

        private static bool IsAaaaQuery(byte[] dnsPayload)
        {
            if (dnsPayload == null || dnsPayload.Length < 12) return false;
            try
            {
                int pos = 12;
                while (pos < dnsPayload.Length)
                {
                    int len = dnsPayload[pos];
                    if (len == 0) break;
                    pos += 1 + len;
                }
                pos++; // Пропускаем нулевой байт QNAME
                if (pos + 4 <= dnsPayload.Length)
                {
                    ushort qtype = (ushort)((dnsPayload[pos] << 8) | dnsPayload[pos + 1]);
                    return qtype == 28; // 28 = AAAA (IPv6)
                }
            }
            catch (Exception ex)
            {
                FileLog.W($"[DNS BLOCK ERROR] IsAaaaQuery failed: {ex.Message}");
            }
            return false;
        }

        // Проверка, что DNS-запрос — это A (IPv4) запрос.
        private static bool IsAQuery(byte[] dnsPayload)
        {
            if (dnsPayload == null || dnsPayload.Length < 12) return false;
            try
            {
                int pos = 12;
                while (pos < dnsPayload.Length)
                {
                    int len = dnsPayload[pos];
                    if (len == 0) break;
                    if ((len & 0xC0) != 0) return false; // компрессия в вопросе недопустима
                    pos += 1 + len;
                }
                pos++; // нулевой байт QNAME
                if (pos + 4 <= dnsPayload.Length)
                {
                    ushort qtype = (ushort)((dnsPayload[pos] << 8) | dnsPayload[pos + 1]);
                    return qtype == 1; // 1 = A (IPv4)
                }
            }
            catch { }
            return false;
        }

        private static byte[] BuildEmptyDnsReply(byte[] query)
        {
            if (query == null || query.Length < 12) return null;
            try
            {
                byte[] reply = new byte[query.Length];
                System.Buffer.BlockCopy(query, 0, reply, 0, query.Length);

                // Устанавливаем флаги: Standard Query Response, No Error (0x8180)
                reply[2] = 0x81;
                reply[3] = 0x80;

                // Зануляем количество ответов, авторитетных записей и дополнительных записей
                reply[6] = 0; reply[7] = 0;   // Answer Count = 0
                reply[8] = 0; reply[9] = 0;   // Authority Count = 0
                reply[10] = 0; reply[11] = 0; // Additional Count = 0

                return reply;
            }
            catch
            {
                return null;
            }
        }

        // Строит DNS-ответ на A-запрос с одной A-записью = fakeIp. EDNS/Additional из запроса
        // отбрасываются (для fake-ответа не нужны). NAME в ответе — указатель на вопрос (0xC00C).
        private static byte[] BuildFakeAReply(byte[] query, byte[] fakeIp)
        {
            if (query == null || query.Length < 12 || fakeIp == null || fakeIp.Length < 4) return null;
            try
            {
                // Находим конец первого вопроса: header(12) + QNAME + QTYPE(2) + QCLASS(2).
                int pos = 12;
                while (pos < query.Length)
                {
                    int len = query[pos];
                    if (len == 0) { pos++; break; }
                    if ((len & 0xC0) != 0) return null; // компрессия в вопросе недопустима
                    pos += 1 + len;
                    if (pos >= query.Length) return null;
                }
                pos += 4; // QTYPE + QCLASS
                if (pos > query.Length) return null;
                int qEnd = pos;

                byte[] reply = new byte[qEnd + 16];
                System.Buffer.BlockCopy(query, 0, reply, 0, qEnd);

                reply[2] = 0x81; reply[3] = 0x80; // QR=1, RD->RA, NOERROR
                reply[4] = 0x00; reply[5] = 0x01; // QDCOUNT = 1
                reply[6] = 0x00; reply[7] = 0x01; // ANCOUNT  = 1
                reply[8] = 0; reply[9] = 0;       // NSCOUNT  = 0
                reply[10] = 0; reply[11] = 0;     // ARCOUNT  = 0

                int o = qEnd;
                reply[o++] = 0xC0; reply[o++] = 0x0C;             // NAME -> указатель на offset 12
                reply[o++] = 0x00; reply[o++] = 0x01;             // TYPE  = A
                reply[o++] = 0x00; reply[o++] = 0x01;             // CLASS = IN
                reply[o++] = 0x00; reply[o++] = 0x00; reply[o++] = 0x00; reply[o++] = 0x3C; // TTL = 60s
                reply[o++] = 0x00; reply[o++] = 0x04;             // RDLENGTH = 4
                reply[o++] = fakeIp[0]; reply[o++] = fakeIp[1]; reply[o++] = fakeIp[2]; reply[o++] = fakeIp[3];

                return reply;
            }
            catch
            {
                return null;
            }
        }

        private void ResolveDnsOverTcpAsync(byte[] dnsPayload, byte[] origSrcIp, byte[] origDstIp, ushort origSrcPort)
        {
            // Запускаем асинхронно на ThreadPool, чтобы не блокировать сетевой стек ОС
            System.Threading.Tasks.Task.Run(async () =>
            {
                await _dnsSemaphore.WaitAsync();
                ushort sid = 0;
                string domain = "Unknown";
                try
                {
                    sid = NextSid();

                    domain = ParseDnsQuestion(dnsPayload);

                    var c = new TcpConn
                    {
                        Key = $"DNS:{sid}",
                        Sid = sid,
                        IsIpv6 = false,
                        SrcPort = origSrcPort,
                        DstPort = 53,
                        State = TcpState.Established,
                        DnsStartTime = DateTime.UtcNow,
                        DnsQueryDomain = domain
                    };

                    FileLog.W($"[DNS START] Запрос от Edge/системы: {domain} (SID {sid})");

                    c.DstIp = new byte[] { 8, 8, 8, 8 };


                    c.SrcIp = new byte[] { origSrcIp[0], origSrcIp[1], origSrcIp[2], origSrcIp[3] };
                    c.DnsServerIp[0] = origDstIp[0]; c.DnsServerIp[1] = origDstIp[1]; c.DnsServerIp[2] = origDstIp[2]; c.DnsServerIp[3] = origDstIp[3];

                    _muxSessions[sid] = c;

                    byte[] tcpQuery = new byte[2 + dnsPayload.Length];
                    tcpQuery[0] = (byte)(dnsPayload.Length >> 8);
                    tcpQuery[1] = (byte)(dnsPayload.Length & 0xFF);
                    System.Buffer.BlockCopy(dnsPayload, 0, tcpQuery, 2, dnsPayload.Length);

                    QueueMuxData(c, tcpQuery, false);

                    // Резервный таймер самовосстановления: если ответа не будет 5 секунд,
                    // принудительно освобождаем слот семафора, спасая туннель от зависания.
                    var localSid = sid;
                    var localDomain = domain;
                    _ = System.Threading.Tasks.Task.Run(async () =>
                    {
                        await System.Threading.Tasks.Task.Delay(5000);
                        // Переименовано c -> timedOutConn, чтобы избежать конфликта с внешней 'c'
                        if (_muxSessions.TryRemove(localSid, out var timedOutConn))
                        {
                            _dnsSemaphore.Release();
                            FileLog.W($"[DNS TIMEOUT] Стрим SID {localSid} ({localDomain}) закрыт по таймауту.");
                            if (timedOutConn != null && Interlocked.Exchange(ref timedOutConn.MuxSlotState, 0) == 1)
                            {
                                try { ReleaseSlotAndCarrier(c); } catch { }
                            }
                        }
                    });
                }
                catch
                {
                    if (sid != 0) _muxSessions.TryRemove(sid, out _);
                    _dnsSemaphore.Release();
                }
            });
        }

        private void HandleDnsTcpResponse(TcpConn c, byte[] payload)
        {
            try
            {
               // FileLog.W($"[DNS DEBUG] Вход в HandleDnsTcpResponse для SID {c.Sid}, размер payload: {payload.Length} байт");
                lock (c.Lock)
                {
                    c.DnsBuffer.AddRange(payload);
                  //  FileLog.W($"[DNS DEBUG] SID {c.Sid}: Буфер DnsBuffer после добавления: {c.DnsBuffer.Count} байт");

                    while (c.DnsBuffer.Count >= 2)
                    {
                        int dnsLen = (c.DnsBuffer[0] << 8) | c.DnsBuffer[1];
                      //  FileLog.W($"[DNS DEBUG] SID {c.Sid}: Распарсена длина dnsLen = {dnsLen} байт");

                        if (c.DnsBuffer.Count < 2 + dnsLen)
                        {
                          //  FileLog.W($"[DNS DEBUG] SID {c.Sid}: Недостаточно байт в буфере ({c.DnsBuffer.Count} < {2 + dnsLen}), ожидаем догрузки...");
                            break;
                        }

                        byte[] dnsResponse = c.DnsBuffer.Skip(2).Take(dnsLen).ToArray();
                        c.DnsBuffer.RemoveRange(0, 2 + dnsLen);

                        dnsResponse = RewriteAAnswersToFake(dnsResponse, c.DnsQueryDomain);


                        byte[] srcIpBytes = c.DnsServerIp;
                        byte[] dstIpBytes = c.SrcIp;

                        //FileLog.W($"[DNS DEBUG] SID {c.Sid}: Впрыскивание DNS-ответа (размер: {dnsResponse.Length} байт) в ОС...");
                        InjectDnsReply(dnsResponse, dstIpBytes, srcIpBytes, c.SrcPort, 53);
                       // FileLog.W($"[DNS DEBUG] SID {c.Sid}: DNS-ответ успешно впрыснут.");

                        double elapsedMs = (DateTime.UtcNow - c.DnsStartTime).TotalMilliseconds;
                        FileLog.W($"[DNS SUCCESS] {c.DnsQueryDomain} разрешен за {elapsedMs:F1} мс (SID {c.Sid}).");

                        _ = SendMuxEndAsync(c);

                        if (_muxSessions.TryRemove(c.Sid, out _))
                        {
                            ReleaseSlotAndCarrier(c);
                         //   FileLog.W($"[DNS DEBUG] SID {c.Sid}: Слот семафора успешно возвращен.");
                        }
                        break;
                    }
                }
                //FileLog.W($"[DNS DEBUG] Успешный выход из HandleDnsTcpResponse для SID {c.Sid}");
            }
            catch (Exception ex)
            {
                // Перехватываем ошибку, чтобы она больше не убивала поток чтения MUX
                FileLog.W($"[DNS DEBUG ERROR] КРИТИЧЕСКАЯ ОШИБКА в HandleDnsTcpResponse для SID {c.Sid}: {ex}");
            }
        }

        private static byte[] RewriteAAnswersToFake(byte[] response, string domain)
        {
            if (response == null || response.Length < 12) return response;
            if (string.IsNullOrEmpty(domain)) return response;
            try
            {
                int qd = (response[4] << 8) | response[5];
                int an = (response[6] << 8) | response[7];
                if (qd < 1 || an < 1) return response;

                // Перебираем все A-записи (TYPE=1, CLASS=1, RDLENGTH=4)
                // и заменяем 4 байта RDATA на fake-IP.
                int pos = 12;
                // Пропустить QDCOUNT * (name + qtype + qclass)
                for (int i = 0; i < qd; i++)
                {
                    if (!SkipName(response, ref pos)) return response;
                    pos += 4;
                    if (pos > response.Length) return response;
                }

                bool rewroteAny = false;
                for (int i = 0; i < an; i++)
                {
                    if (!SkipName(response, ref pos)) return response;
                    if (pos + 10 > response.Length) return response;
                    ushort type = (ushort)((response[pos] << 8) | response[pos + 1]);
                    ushort klass = (ushort)((response[pos + 2] << 8) | response[pos + 3]);
                    ushort rdlen = (ushort)((response[pos + 8] << 8) | response[pos + 9]);
                    int rdataPos = pos + 10;
                    if (rdataPos + rdlen > response.Length) return response;

                    if (type == 1 && klass == 1 && rdlen == 4)
                    {
                        byte[] realIp = new byte[4] {
                    response[rdataPos], response[rdataPos + 1],
                    response[rdataPos + 2], response[rdataPos + 3]
                };
                        byte[] fakeIp = FakeDns.RegisterStable(domain, realIp);
                        if (fakeIp != null)
                        {
                            response[rdataPos] = fakeIp[0];
                            response[rdataPos + 1] = fakeIp[1];
                            response[rdataPos + 2] = fakeIp[2];
                            response[rdataPos + 3] = fakeIp[3];
                            rewroteAny = true;
                            if (FileLog.Verbose) FileLog.W($"[FAKE DNS] {domain}: real={realIp[0]}.{realIp[1]}.{realIp[2]}.{realIp[3]} -> fake={fakeIp[0]}.{fakeIp[1]}.{fakeIp[2]}.{fakeIp[3]}");
                        }
                    }

                    pos = rdataPos + rdlen;
                }

                return response;
            }
            catch (Exception ex)
            {
                FileLog.W($"[FAKE DNS ERROR] {ex.Message}");
                return response;
            }
        }
        private static bool SkipName(byte[] msg, ref int pos)
        {
            int jumps = 0;
            while (pos < msg.Length)
            {
                int len = msg[pos++];
                if (len == 0) return true;
                if ((len & 0xC0) == 0xC0)
                {
                    if (pos >= msg.Length) return false;
                    pos++;
                    return ++jumps < 16;
                }
                if ((len & 0xC0) != 0) return false;
                pos += len;
                if (pos > msg.Length) return false;
            }
            return false;
        }


        private static string ParseDnsQuestion(byte[] dnsPayload)
        {
            if (dnsPayload == null || dnsPayload.Length < 12) return "Unknown";
            try
            {
                int pos = 12;
                var sb = new StringBuilder();
                while (pos < dnsPayload.Length)
                {
                    int len = dnsPayload[pos];
                    if (len == 0) break;
                    if (pos + 1 + len > dnsPayload.Length) return "Malformed";

                    if (sb.Length > 0) sb.Append(".");
                    sb.Append(Encoding.UTF8.GetString(dnsPayload, pos + 1, len));
                    pos += 1 + len;
                }
                return sb.ToString();
            }
            catch
            {
                return "ErrorParsing";
            }
        }

        private void InjectDnsReply(byte[] reply, byte[] origSrcIp, byte[] origDstIp, ushort origSrcPort, ushort origDstPort)
        {
           // FileLog.W("[DNS DEBUG] InjectDnsReply: Старт метода");
            int totalLen = 20 + 8 + reply.Length;
            byte[] buf = new byte[totalLen];

            buf[0] = 0x45;
            buf[1] = 0;
            buf[2] = (byte)(totalLen >> 8); buf[3] = (byte)(totalLen & 0xFF);

            ushort ipId = _ipIdCounter++;
            buf[4] = (byte)(ipId >> 8); buf[5] = (byte)(ipId & 0xFF);
            buf[6] = 0x40; buf[7] = 0;

            buf[8] = 64;
            buf[9] = 17; // UDP

          //  FileLog.W("[DNS DEBUG] InjectDnsReply: Копирование IP адресов");
            System.Buffer.BlockCopy(origDstIp, 0, buf, 12, 4);
            System.Buffer.BlockCopy(origSrcIp, 0, buf, 16, 4);

          //  FileLog.W("[DNS DEBUG] InjectDnsReply: Расчет чексуммы IPv4");
            RecalculateIPv4Checksum(buf, 20);

            buf[20] = (byte)(origDstPort >> 8); buf[21] = (byte)(origDstPort & 0xFF);
            buf[22] = (byte)(origSrcPort >> 8); buf[23] = (byte)(origSrcPort & 0xFF);
            int udpLen = 8 + reply.Length;
            buf[24] = (byte)(udpLen >> 8); buf[25] = (byte)(udpLen & 0xFF);

           // FileLog.W("[DNS DEBUG] InjectDnsReply: Расчет чексуммы UDP");
            RecalculateUDPChecksum(buf, 20, totalLen, reply);

          //  FileLog.W("[DNS DEBUG] InjectDnsReply: Копирование payload");
            System.Buffer.BlockCopy(reply, 0, buf, 28, reply.Length);

           // FileLog.W("[DNS DEBUG] InjectDnsReply: Отправка в EnqueueToOs...");
            EnqueueToOs(buf, buf.Length);
          //  FileLog.W("[DNS DEBUG] InjectDnsReply: Завершение метода");
        }

        private static void RecalculateIPv4Checksum(byte[] buf, int headerLen)
        {
            buf[10] = 0; buf[11] = 0;
            uint sum = 0;
            for (int i = 0; i < headerLen; i += 2) sum += (uint)((buf[i] << 8) | buf[i + 1]);
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            ushort finalChecksum = (ushort)(~sum);
            buf[10] = (byte)(finalChecksum >> 8); buf[11] = (byte)(finalChecksum & 0xFF);
        }

        private static void RecalculateTCPChecksum(byte[] buf, int ipHeaderLen, int totalLen)
        {
            int t = ipHeaderLen;
            int tLen = totalLen - ipHeaderLen;
            buf[t + 16] = 0; buf[t + 17] = 0;
            uint sum = 0;
            for (int i = 12; i < 20; i += 2) sum += (uint)((buf[i] << 8) | buf[i + 1]);
            sum += 6; sum += (uint)tLen;
            for (int i = t; i < totalLen - 1; i += 2) sum += (uint)((buf[i] << 8) | buf[i + 1]);
            if (tLen % 2 != 0) sum += (uint)(buf[totalLen - 1] << 8);
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            ushort finalChecksum = (ushort)(~sum);
            buf[t + 16] = (byte)(finalChecksum >> 8); buf[t + 17] = (byte)(finalChecksum & 0xFF);
        }

        // НОВЫЙ МЕТОД: Точный расчет чексуммы для IPv6 через псевдозаголовок
        private static void RecalculateTCPChecksumIpv6(byte[] buf, int ipHeaderLen, int totalLen)
        {
            int t = ipHeaderLen;
            int tLen = totalLen - ipHeaderLen;
            buf[t + 16] = 0; buf[t + 17] = 0;
            uint sum = 0;

            // Псевдо-заголовок IPv6
            for (int i = 8; i < 40; i += 2) sum += (uint)((buf[i] << 8) | buf[i + 1]);
            sum += 6; // Next Header (TCP)

            sum += (uint)(tLen >> 16);
            sum += (uint)(tLen & 0xFFFF);

            // Заголовок TCP и данные
            for (int i = t; i < totalLen - 1; i += 2) sum += (uint)((buf[i] << 8) | buf[i + 1]);
            if (totalLen % 2 != 0) sum += (uint)(buf[totalLen - 1] << 8);

            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            ushort finalChecksum = (ushort)(~sum);
            buf[t + 16] = (byte)(finalChecksum >> 8); buf[t + 17] = (byte)(finalChecksum & 0xFF);
        }

        private static void RecalculateUDPChecksum(byte[] buf, int ipHeaderLen, int totalLen, byte[] payload)
        {
            int u = ipHeaderLen;
            int uLen = totalLen - ipHeaderLen;
            buf[u + 6] = 0; buf[u + 7] = 0;
            uint sum = 0;
            for (int i = 12; i < 20; i += 2) sum += (uint)((buf[i] << 8) | buf[i + 1]);
            sum += 17; sum += (uint)uLen;
            for (int i = u; i < u + 6; i += 2) sum += (uint)((buf[i] << 8) | buf[i + 1]);
            for (int i = 0; i < payload.Length - 1; i += 2) sum += (uint)((payload[i] << 8) | payload[i + 1]);
            if (payload.Length % 2 != 0) sum += (uint)(payload[payload.Length - 1] << 8);
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            ushort finalChecksum = (ushort)(~sum);
            if (finalChecksum == 0) finalChecksum = 0xFFFF;
            buf[u + 6] = (byte)(finalChecksum >> 8); buf[u + 7] = (byte)(finalChecksum & 0xFF);
        }

        // Растущий байтовый буфер со скользящим окном [_start, _start+_count).
        // Заменяет List<byte> + Skip/Take/RemoveRange (которые были O(n) на каждый MUX-фрейм).
        private sealed class ByteAccumulator
        {
            private byte[] _buf = new byte[16384];
            private int _start;
            private int _count;

            public int Count => _count;

            // Индекс относительно логического начала окна.
            public byte this[int i] => _buf[_start + i];

            public void Append(byte[] data, int len)
            {
                EnsureSpace(len);
                System.Buffer.BlockCopy(data, 0, _buf, _start + _count, len);
                _count += len;
            }

            public byte[] Slice(int off, int n)
            {
                var r = new byte[n];
                System.Buffer.BlockCopy(_buf, _start + off, r, 0, n);
                return r;
            }

            public void Consume(int n)
            {
                _start += n;
                _count -= n;
                if (_count == 0) _start = 0;
                else if (_start > _buf.Length / 2) Compact();
            }

            private void EnsureSpace(int extra)
            {
                if (_start + _count + extra <= _buf.Length) return;
                if (_count + extra <= _buf.Length) { Compact(); return; }
                int newCap = _buf.Length;
                while (newCap < _count + extra) newCap *= 2;
                var nb = new byte[newCap];
                System.Buffer.BlockCopy(_buf, _start, nb, 0, _count);
                _buf = nb;
                _start = 0;
            }

            private void Compact()
            {
                if (_start == 0) return;
                System.Buffer.BlockCopy(_buf, _start, _buf, 0, _count);
                _start = 0;
            }
        }

    }
}
