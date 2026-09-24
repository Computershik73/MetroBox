using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    // ================= ВАРИАНТ B: мультиплексирование xhttp stream-one =================
    //
    // Раньше КАЖДЫЙ проксируемый flow (каждое TCP-соединение приложения) открывал
    // собственный TCP + Reality-хендшейк + HTTP/2 (stream id всегда = 1). При загрузке
    // YouTube это 30-60 хендшейков за пару секунд — сервер друга захлёбывался: переставал
    // отвечать на ServerHello (таймауты 8с) и/или чаще ронял нас на прикрытие (fallback).
    //
    // Теперь на сервер держится небольшой ПУЛ общих туннелей (Reality+H2), а каждый flow —
    // это отдельный H2-СТРИМ (id 1,3,5,...) внутри общего туннеля. Хендшейков — единицы
    // вместо десятков. Один насос чтения на туннель демультиплексирует входящие кадры по
    // stream id; запись сериализуется под локом (Reality EncryptRecord не потокобезопасен).
    //
    // Kill-switch: VlessConnection.UseH2Mux = false → мгновенный откат к старому пути
    // (один Reality+H2 на flow).

    internal sealed class H2Stream
    {
        public readonly int Id;
        private readonly H2MuxTransport _t;
        private readonly object _lock = new object();
        private readonly Queue<byte[]> _down = new Queue<byte[]>();
        private TaskCompletionSource<bool> _sig;
        private bool _closed;

        public int Status = -1;
        public bool HeadersDone;

        // окно ОТПРАВКИ этого стрима (сколько МЫ можем послать серверу); server
        // INITIAL_WINDOW_SIZE по умолчанию 65535. Меняется под H2MuxTransport._winLock.
        internal int SendWindow;

        internal H2Stream(H2MuxTransport t, int id, int initSendWindow)
        {
            _t = t; Id = id; SendWindow = initSendWindow;
        }

        internal void EnqueueDown(byte[] d) { lock (_lock) { _down.Enqueue(d); SignalLocked(); } }
        internal void MarkClosed() { lock (_lock) { _closed = true; SignalLocked(); } }
        internal void SignalHeaders() { lock (_lock) { SignalLocked(); } }
        private void SignalLocked() { if (_sig != null && !_sig.Task.IsCompleted) _sig.TrySetResult(true); }

        public bool Closed { get { lock (_lock) { return _closed && _down.Count == 0; } } }

        // Читает следующий блок downstream. null = стрим завершён/сброшен/не-200.
        public async Task<byte[]> ReadDownAsync()
        {
            while (true)
            {
                byte[] chunk = null;
                Task wait = null;
                lock (_lock)
                {
                    if (_down.Count > 0) chunk = _down.Dequeue();
                    else if (_closed) return null;
                    else if (HeadersDone && Status > 0 && Status != 200) return null;
                    else
                    {
                        if (_sig == null || _sig.Task.IsCompleted)
                            _sig = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                        wait = _sig.Task;
                    }
                }
                if (chunk != null)
                {
                    // Окно СТРИМА кредитуем после выдачи наружу — это back-pressure на стрим.
                    // Окно СОЕДИНЕНИЯ насос кредитует сразу при приёме (чтобы медленный стрим
                    // не блокировал остальные — общее окно велико и не «залипает»).
                    await _t.CreditStreamAsync(Id, chunk.Length);
                    return chunk;
                }
                await wait;
            }
        }

        public Task WriteAsync(byte[] data) { return _t.WriteStreamDataAsync(this, data); }
        public void Close() { _t.CloseStream(this); }
    }

    internal sealed class H2MuxTransport
    {
        private const int StreamRecvWindow = 128 * 1024;        // наше приёмное окно НА СТРИМ (лимит памяти на стрим; > BDP LTE, т.е. не режет скорость)
        private const int ConnRecvWindowInit = 16 * 1024 * 1024; // приёмное окно СОЕДИНЕНИЯ (кредитуем сразу)
        private static readonly byte[] Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        private readonly VlessConfig _cfg;
        private readonly string _authority;
        private readonly string _path;

        private StreamSocket _socket;
        private DataReader _reader;
        private DataWriter _hsWriter;
        private System.IO.Stream _outStream;
        private RealityTls13Stream _reality;

        private readonly SemaphoreSlim _wlock = new SemaphoreSlim(1, 1);   // сериализация записи (Reality не потокобезопасен)
        private readonly SemaphoreSlim _startLock = new SemaphoreSlim(1, 1);
        private bool _started;
        private volatile bool _dead;

        private readonly object _smapLock = new object();
        private readonly Dictionary<int, H2Stream> _streams = new Dictionary<int, H2Stream>();
        private int _nextId = 1;
        private int _reserved;

        // окна ОТПРАВКИ (сколько МЫ можем послать)
        private readonly object _winLock = new object();
        private int _connSend = 65535;
        private int _curInit = 65535;            // текущее server INITIAL_WINDOW_SIZE
        private volatile int _peerMaxFrame = 16384;
        private volatile int _peerMaxStreams = 64; // до прихода SETTINGS — консервативно
        private TaskCompletionSource<bool> _winSig;

        // буфер отложенного H2-парсинга (plaintext после Reality)
        private byte[] _buf = new byte[65536];
        private int _bufLen;
        // управляющие кадры, накопленные при разборе (flush после Feed)
        private readonly List<byte> _pending = new List<byte>();

        public bool Dead { get { return _dead; } }
        public int Load { get { lock (_smapLock) { return _streams.Count + _reserved; } } }

        public H2MuxTransport(VlessConfig cfg)
        {
            _cfg = cfg;
            string host = !string.IsNullOrEmpty(cfg.Host) ? cfg.Host
                        : (!string.IsNullOrEmpty(cfg.Sni) ? cfg.Sni : cfg.Address);
            _authority = host;
            string p = string.IsNullOrEmpty(cfg.Path) ? "/" : cfg.Path;
            if (!p.EndsWith("/")) p += "/";
            _path = p;
        }

        internal bool TryReserve(int softCap)
        {
            lock (_smapLock)
            {
                int cap = Math.Min(_peerMaxStreams, softCap);
                if (_streams.Count + _reserved < cap) { _reserved++; return true; }
                return false;
            }
        }
        internal void ForceReserve() { lock (_smapLock) { _reserved++; } }

        // ===== установка туннеля =====

        public async Task<bool> EnsureStartedAsync()
        {
            if (_started) return !_dead;
            await _startLock.WaitAsync();
            try
            {
                if (_started) return !_dead;
                bool ok = await ConnectAndHandshakeAsync();
                if (!ok) { _dead = true; _started = true; return false; }
                await WriteFramesAsync(BuildClientHandshake());
                _started = true;
                var _ignore = Task.Run((Func<Task>)RunReadPumpAsync);
                return true;
            }
            finally { _startLock.Release(); }
        }

        private async Task<bool> ConnectAndHandshakeAsync()
        {
            string targetHost = string.IsNullOrEmpty(VlessVpnPlugin.ServerIp) ? _cfg.Address : VlessVpnPlugin.ServerIp;
            string sec = (_cfg.Security ?? "").ToLower();
            bool isReality = sec == "reality";

            // Обычный TLS отличается от REALITY только содержимым ClientHello: ни
            // аутентификации в session_id, ни разбора подменного сертификата. Всё
            // остальное — тот же TLS 1.3 нашим стеком, поэтому и код тот же.
            bool isTls = sec == "tls";
            const int maxAttempts = 3;

            for (int attempt = 1; ; attempt++)
            {
                StreamSocket sock = new StreamSocket();
                sock.Control.NoDelay = true;
                sock.Control.KeepAlive = true;

                try
                {
                    Windows.Foundation.IAsyncAction connectOp;
                    if (VlessVpnPlugin.PhysicalIp != null)
                        connectOp = sock.ConnectAsync(
                            new EndpointPair(VlessVpnPlugin.PhysicalIp, "", new HostName(targetHost), _cfg.Port.ToString()),
                            SocketProtectionLevel.PlainSocket);
                    else
                        connectOp = sock.ConnectAsync(new HostName(targetHost), _cfg.Port.ToString(),
                            SocketProtectionLevel.PlainSocket);

                    var ct = connectOp.AsTask();
                    if (await Task.WhenAny(ct, Task.Delay(8000)) != ct)
                    {
                        try { connectOp.Cancel(); } catch { }
                        try { sock.Dispose(); } catch { }
                        FileLog.W("[H2MUX] Таймаут TCP-подключения к туннелю (8с).");
                        return false;
                    }
                    await ct;
                }
                catch (Exception ex)
                {
                    try { sock.Dispose(); } catch { }
                    FileLog.W($"[H2MUX] TCP-ошибка туннеля: {ex.Message}");
                    return false;
                }

                var reader = new DataReader(sock.InputStream);
                reader.InputStreamOptions = InputStreamOptions.Partial;
                var writer = new DataWriter(sock.OutputStream);

                if (!isReality && !isTls)
                {
                    _socket = sock; _reader = reader; _hsWriter = writer;
                    _outStream = sock.OutputStream.AsStreamForWrite(81920);
                    FileLog.Important("[H2MUX] Туннель установлен (без шифрования).");
                    return true;
                }

                var rs = new RealityTls13Stream(_cfg) { PlainTls = isTls };
                var hs = rs.EstablishHandshakeAsync(writer, reader);
                bool ok = await Task.WhenAny(hs, Task.Delay(8000)) == hs && await hs;
                if (ok)
                {
                    _socket = sock; _reader = reader; _hsWriter = writer; _reality = rs;
                    _outStream = sock.OutputStream.AsStreamForWrite(81920);
                    FileLog.Important(isTls
                        ? $"[H2MUX] Туннель установлен (TLS 1.3 OK, ALPN='{(string.IsNullOrEmpty(rs.NegotiatedAlpn) ? "<нет>" : rs.NegotiatedAlpn)}')."
                        : $"[H2MUX] Туннель установлен (Reality OK, попытка {attempt}).");

                    // Туннель говорит по HTTP/2. Если сервер выбрал http/1.1, дальше пойдут
                    // кадры, которых он не ждёт, — без этой строки причина была бы не видна.
                    if (isTls && !string.IsNullOrEmpty(rs.NegotiatedAlpn) &&
                        !string.Equals(rs.NegotiatedAlpn, "h2", StringComparison.OrdinalIgnoreCase))
                        FileLog.Important($"[H2MUX] ВНИМАНИЕ: сервер выбрал ALPN '{rs.NegotiatedAlpn}' вместо h2 — xhttp через общий туннель ему не подойдёт.");
                    return true;
                }

                try { writer.Dispose(); } catch { }
                try { reader.Dispose(); } catch { }
                try { sock.Dispose(); } catch { }

                if (rs.ServerFellBack && attempt < maxAttempts)
                {
                    FileLog.W($"[H2MUX] Reality fallback туннеля (попытка {attempt}) — быстрый повтор.");
                    continue;
                }
                FileLog.W(isTls
                    ? "[H2MUX] TLS-хендшейк туннеля: таймаут/сбой."
                    : rs.ServerFellBack
                        ? "[H2MUX] Reality fallback туннеля — исчерпаны попытки."
                        : "[H2MUX] Reality handshake туннеля: таймаут/сбой.");
                return false;
            }
        }

        // ===== открытие/закрытие стрима =====

        public async Task<H2Stream> OpenStreamAsync()
        {
            if (_dead) return null;
            int id;
            int initWin;
            H2Stream st;
            lock (_winLock) { initWin = _curInit; }
            lock (_smapLock)
            {
                if (_dead) return null;
                id = _nextId; _nextId += 2;
                st = new H2Stream(this, id, initWin);
                _streams[id] = st;
                if (_reserved > 0) _reserved--;
            }
            await WriteFramesAsync(BuildHeaders(id));
            if (_dead) { st.MarkClosed(); return null; }
            return st;
        }

        internal void CloseStream(H2Stream st)
        {
            bool existed;
            lock (_smapLock) { existed = _streams.Remove(st.Id); }
            st.MarkClosed();
            if (existed && !_dead)
            {
                var f = new List<byte>();
                WriteFrameHeader(f, 4, 0x3, 0x0, st.Id);   // RST_STREAM
                f.Add(0); f.Add(0); f.Add(0); f.Add(0x8);  // error = CANCEL(0x8)
                var _ignore = WriteFramesAsync(f.ToArray());
            }
        }

        internal void KillAll()
        {
            _dead = true;
            List<H2Stream> all;
            lock (_smapLock) { all = new List<H2Stream>(_streams.Values); _streams.Clear(); }
            foreach (var s in all) s.MarkClosed();
            SignalWindow();
            H2MuxRegistry.Remove(this);
            try { _outStream?.Dispose(); } catch { }
            try { _reader?.Dispose(); } catch { }
            try { _hsWriter?.Dispose(); } catch { }
            try { _socket?.Dispose(); } catch { }
        }

        // ===== отправка данных стрима =====

        internal async Task WriteStreamDataAsync(H2Stream st, byte[] payload)
        {
            if (payload == null || payload.Length == 0 || _dead) return;
            int off = 0;
            int maxFrame = _peerMaxFrame > 0 ? Math.Min(_peerMaxFrame, 16384) : 16384;
            while (off < payload.Length)
            {
                if (_dead || IsClosed(st)) return;
                int piece = Math.Min(payload.Length - off, maxFrame);
                while (!TryReserveSend(st, piece))
                {
                    if (_dead || IsClosed(st)) return;
                    await WaitWindowAsync();
                }
                byte[] frame = FrameData(st.Id, payload, off, piece);
                await WriteFramesAsync(frame);
                off += piece;
            }
        }

        private bool IsClosed(H2Stream st)
        {
            lock (_smapLock) { return !_streams.ContainsKey(st.Id); }
        }

        private bool TryReserveSend(H2Stream st, int len)
        {
            lock (_winLock)
            {
                if (_connSend >= len && st.SendWindow >= len)
                {
                    _connSend -= len;
                    st.SendWindow -= len;
                    return true;
                }
                return false;
            }
        }

        private Task WaitWindowAsync()
        {
            lock (_winLock)
            {
                if (_winSig == null || _winSig.Task.IsCompleted)
                    _winSig = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                return _winSig.Task;
            }
        }

        private void SignalWindow()
        {
            lock (_winLock) { if (_winSig != null && !_winSig.Task.IsCompleted) _winSig.TrySetResult(true); }
        }

        // Кредит окна СТРИМА после выдачи блока наружу (окно соединения кредитуется в насосе).
        internal async Task CreditStreamAsync(int sid, int n)
        {
            if (n <= 0 || _dead) return;
            var f = new List<byte>();
            WriteFrameHeader(f, 4, 0x8, 0x0, sid);
            f.Add((byte)(n >> 24)); f.Add((byte)(n >> 16)); f.Add((byte)(n >> 8)); f.Add((byte)n);
            await WriteFramesAsync(f.ToArray());
        }

        // Единственная точка записи в сокет: сериализуется + шифруется Reality.
        internal async Task WriteFramesAsync(byte[] frames)
        {
            if (frames == null || frames.Length == 0 || _dead) return;
            await _wlock.WaitAsync();
            try
            {
                byte[] toSend = _reality != null ? _reality.EncryptRecord(frames) : frames;
                _outStream.Write(toSend, 0, toSend.Length);
                await _outStream.FlushAsync();
            }
            catch (Exception ex)
            {
                FileLog.W($"[H2MUX] Ошибка записи в туннель: {ex.Message}");
                _dead = true;
                SignalWindow();
            }
            finally { _wlock.Release(); }
        }

        // ===== насос чтения (демультиплексор) =====

        private async Task RunReadPumpAsync()
        {
            try
            {
                while (!_dead)
                {
                    byte[] plain = await ReadTlsPlaintextAsync();
                    if (plain == null) break;
                    Feed(plain);
                    if (_pending.Count > 0)
                    {
                        byte[] p = _pending.ToArray();
                        _pending.Clear();
                        await WriteFramesAsync(p);
                    }
                }
            }
            catch (Exception ex) { FileLog.W($"[H2MUX] Насос чтения упал: {ex.Message}"); }
            finally { FileLog.Important("[H2MUX] Туннель закрыт — гашу все его стримы."); KillAll(); }
        }

        private async Task<bool> ReadExactAsync(uint count)
        {
            try
            {
                uint loaded = _reader.UnconsumedBufferLength;
                while (loaded < count)
                {
                    uint bytesRead = await _reader.LoadAsync(count - loaded);
                    if (bytesRead == 0) return false;
                    loaded += bytesRead;
                }
                return true;
            }
            catch { return false; }
        }

        private async Task<byte[]> ReadTlsPlaintextAsync()
        {
            try
            {
                if (_reality != null)
                {
                    while (true)
                    {
                        if (!await ReadExactAsync(5)) return null;
                        byte[] header = new byte[5];
                        _reader.ReadBytes(header);

                        byte recordType = header[0];
                        int len = (header[3] << 8) | header[4];
                        if (len <= 0) continue;

                        if (!await ReadExactAsync((uint)len)) return null;
                        byte[] payload = new byte[len];
                        _reader.ReadBytes(payload);

                        if (recordType == 20) continue; // ChangeCipherSpec

                        byte innerType;
                        byte[] plain = _reality.DecryptRecordExplicit(header, payload, out innerType);
                        if (plain == null) { FileLog.W("[H2MUX] Ошибка расшифровки TLS-записи."); return null; }
                        if (innerType == 23) return plain;      // application_data
                        // служебные (23!=) — пропускаем
                    }
                }
                else
                {
                    uint bytesAvailable = await _reader.LoadAsync(16384);
                    if (bytesAvailable == 0) return null;
                    byte[] data = new byte[bytesAvailable];
                    _reader.ReadBytes(data);
                    return data;
                }
            }
            catch (Exception ex) { FileLog.W($"[H2MUX READ ERROR] {ex.Message}"); return null; }
        }

        private void Feed(byte[] plain)
        {
            if (plain != null && plain.Length > 0)
            {
                if (_bufLen + plain.Length > _buf.Length)
                {
                    int newCap = _buf.Length * 2;
                    while (newCap < _bufLen + plain.Length) newCap *= 2;
                    Array.Resize(ref _buf, newCap);
                }
                System.Buffer.BlockCopy(plain, 0, _buf, _bufLen, plain.Length);
                _bufLen += plain.Length;
            }

            int p = 0;
            while (_bufLen - p >= 9)
            {
                int len = (_buf[p] << 16) | (_buf[p + 1] << 8) | _buf[p + 2];
                byte type = _buf[p + 3];
                byte flags = _buf[p + 4];
                int sid = ((_buf[p + 5] & 0x7F) << 24) | (_buf[p + 6] << 16) | (_buf[p + 7] << 8) | _buf[p + 8];

                if (_bufLen - p - 9 < len) break;

                int fp = p + 9;
                byte[] payload = new byte[len];
                System.Buffer.BlockCopy(_buf, fp, payload, 0, len);

                HandleFrame(type, flags, sid, payload);
                p = fp + len;
            }

            if (p > 0)
            {
                _bufLen -= p;
                if (_bufLen > 0) System.Buffer.BlockCopy(_buf, p, _buf, 0, _bufLen);
            }
        }

        private H2Stream Get(int sid)
        {
            lock (_smapLock) { H2Stream s; return _streams.TryGetValue(sid, out s) ? s : null; }
        }

        private void HandleFrame(byte type, byte flags, int sid, byte[] payload)
        {
            switch (type)
            {
                case 0x0: // DATA
                    {
                        int dataStart = 0, dataLen = payload.Length;
                        if ((flags & 0x8) != 0) // PADDED
                        {
                            int padLen = payload.Length > 0 ? payload[0] : 0;
                            dataStart = 1;
                            dataLen = payload.Length - 1 - padLen;
                            if (dataLen < 0) dataLen = 0;
                        }

                        H2Stream st = Get(sid);
                        if (st != null && dataLen > 0)
                        {
                            byte[] d = new byte[dataLen];
                            Array.Copy(payload, dataStart, d, 0, dataLen);
                            st.EnqueueDown(d);
                        }

                        // Окно СОЕДИНЕНИЯ возвращаем СРАЗУ на весь кадр (payload.Length) —
                        // чтобы медленный стрим не блокировал общий канал. Окно СТРИМА:
                        // «служебную» часть (padding+padlen) сразу, полезные данные —
                        // после выдачи наружу (см. H2Stream.ReadDownAsync → CreditStreamAsync).
                        QueueWindowUpdate(0, payload.Length);
                        int immediateStream = payload.Length - dataLen;
                        if (st != null && immediateStream > 0) QueueWindowUpdate(sid, immediateStream);

                        if ((flags & 0x1) != 0 && st != null) // END_STREAM
                        {
                            lock (_smapLock) { _streams.Remove(sid); }
                            st.MarkClosed();
                        }
                        break;
                    }
                case 0x1: // HEADERS
                    {
                        int pos = 0;
                        int blockEnd = payload.Length;
                        if ((flags & 0x8) != 0) { int padLen = payload.Length > 0 ? payload[0] : 0; pos = 1; blockEnd = payload.Length - padLen; }
                        if ((flags & 0x20) != 0) pos += 5; // PRIORITY

                        H2Stream st = Get(sid);
                        int status = HpackFindStatus(payload, pos, blockEnd);
                        if (st != null)
                        {
                            if (status > 0) st.Status = status;
                            st.HeadersDone = true;
                            st.SignalHeaders();
                            if (status > 0 && status != 200)
                                NetDiag.ReportHttp($"H2MUX sid={sid}", status, "200 OK");
                            else if (status == 200)
                                NetDiag.ClearError();
                            if ((flags & 0x1) != 0) { lock (_smapLock) { _streams.Remove(sid); } st.MarkClosed(); }
                        }
                        break;
                    }
                case 0x3: // RST_STREAM
                    {
                        int err = payload.Length >= 4 ? ((payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]) : -1;
                        H2Stream st = Get(sid);
                        if (st != null)
                        {
                            FileLog.Important($"[H2MUX] sid={sid} <<< RST_STREAM error={err} (сервер сбросил стрим)");
                            lock (_smapLock) { _streams.Remove(sid); }
                            st.MarkClosed();
                        }
                        break;
                    }
                case 0x4: // SETTINGS
                    if ((flags & 0x1) == 0) { ApplyServerSettings(payload); QueueSettingsAck(); }
                    break;
                case 0x6: // PING
                    if ((flags & 0x1) == 0) QueuePingAck(payload);
                    break;
                case 0x7: // GOAWAY
                    {
                        int lastId = payload.Length >= 4 ? ((payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]) : -1;
                        int err = payload.Length >= 8 ? ((payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]) : -1;
                        FileLog.Important($"[H2MUX] <<< GOAWAY lastStream={lastId} error={err}");
                        NetDiag.Report("H2MUX", $"сервер закрыл туннель (GOAWAY, код {err})");
                        _dead = true;
                        break;
                    }
                case 0x8: // WINDOW_UPDATE
                    {
                        if (payload.Length < 4) break;
                        int inc = ((payload[0] & 0x7F) << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
                        if (sid == 0) { lock (_winLock) { _connSend += inc; } }
                        else { H2Stream st = Get(sid); if (st != null) { lock (_winLock) { st.SendWindow += inc; } } }
                        SignalWindow();
                        break;
                    }
                default:
                    break;
            }
        }

        private void ApplyServerSettings(byte[] p)
        {
            for (int i = 0; i + 6 <= p.Length; i += 6)
            {
                int id = (p[i] << 8) | p[i + 1];
                long v = ((long)p[i + 2] << 24) | ((long)p[i + 3] << 16) | ((long)p[i + 4] << 8) | p[i + 5];
                if (id == 0x4) // INITIAL_WINDOW_SIZE → сдвигаем окна отправки всех стримов
                {
                    List<H2Stream> all;
                    lock (_smapLock) { all = new List<H2Stream>(_streams.Values); }
                    lock (_winLock)
                    {
                        int delta = (int)(v - _curInit);
                        foreach (var s in all) s.SendWindow += delta;
                        _curInit = (int)v;
                    }
                    SignalWindow();
                }
                else if (id == 0x5) { _peerMaxFrame = (int)v; }        // MAX_FRAME_SIZE
                else if (id == 0x3) { if (v > 0 && v < 100000) _peerMaxStreams = (int)v; } // MAX_CONCURRENT_STREAMS
            }
        }

        // ===== построение кадров =====

        private byte[] BuildClientHandshake()
        {
            var o = new List<byte>();
            o.AddRange(Preface);
            var s = new List<byte>();
            AddSetting(s, 0x1, 0);                 // HEADER_TABLE_SIZE = 0
            AddSetting(s, 0x2, 0);                 // ENABLE_PUSH = 0
            AddSetting(s, 0x4, StreamRecvWindow);  // INITIAL_WINDOW_SIZE (наше приёмное окно на стрим)
            WriteFrameHeader(o, s.Count, 0x4, 0x0, 0);
            o.AddRange(s);
            int inc = ConnRecvWindowInit - 65535;
            WriteFrameHeader(o, 4, 0x8, 0x0, 0);
            o.Add((byte)(inc >> 24)); o.Add((byte)(inc >> 16)); o.Add((byte)(inc >> 8)); o.Add((byte)inc);
            return o.ToArray();
        }

        private byte[] BuildHeaders(int sid)
        {
            int padMin = _cfg.XPaddingMin > 0 ? _cfg.XPaddingMin : 100;
            int padMax = _cfg.XPaddingMax > padMin ? _cfg.XPaddingMax : 1000;
            int padLen = new Random().Next(padMin, padMax + 1);
            string referer = "https://" + _authority + "/?x_padding=" + new string('X', padLen);

            var h = new List<byte>();
            h.Add(0x83);                                // :method POST
            h.Add(0x87);                                // :scheme https
            h.Add(0x01); WriteHpackStr(h, _authority);  // :authority
            h.Add(0x04); WriteHpackStr(h, _path);       // :path
            h.Add(0x00); WriteHpackStr(h, "content-type"); WriteHpackStr(h, "application/octet-stream");
            h.Add(0x00); WriteHpackStr(h, "referer"); WriteHpackStr(h, referer);

            var o = new List<byte>();
            WriteFrameHeader(o, h.Count, 0x1, 0x4, sid); // HEADERS, END_HEADERS
            o.AddRange(h);
            return o.ToArray();
        }

        private byte[] FrameData(int sid, byte[] data, int off, int len)
        {
            var o = new List<byte>(9 + len);
            WriteFrameHeader(o, len, 0x0, 0x0, sid);
            for (int i = 0; i < len; i++) o.Add(data[off + i]);
            return o.ToArray();
        }

        private void QueueSettingsAck() { WriteFrameHeader(_pending, 0, 0x4, 0x1, 0); }
        private void QueuePingAck(byte[] payload)
        {
            WriteFrameHeader(_pending, 8, 0x6, 0x1, 0);
            for (int i = 0; i < 8 && i < payload.Length; i++) _pending.Add(payload[i]);
            for (int i = payload.Length; i < 8; i++) _pending.Add(0);
        }
        private void QueueWindowUpdate(int sid, int inc)
        {
            if (inc <= 0) return;
            WriteFrameHeader(_pending, 4, 0x8, 0x0, sid);
            _pending.Add((byte)(inc >> 24)); _pending.Add((byte)(inc >> 16));
            _pending.Add((byte)(inc >> 8)); _pending.Add((byte)inc);
        }

        // ===== низкоуровневые H2/HPACK-хелперы =====

        private static void WriteFrameHeader(List<byte> o, int len, byte type, byte flags, int sid)
        {
            o.Add((byte)(len >> 16)); o.Add((byte)(len >> 8)); o.Add((byte)len);
            o.Add(type); o.Add(flags);
            o.Add((byte)(sid >> 24)); o.Add((byte)(sid >> 16)); o.Add((byte)(sid >> 8)); o.Add((byte)sid);
        }
        private static void AddSetting(List<byte> s, int id, int value)
        {
            s.Add((byte)(id >> 8)); s.Add((byte)id);
            s.Add((byte)(value >> 24)); s.Add((byte)(value >> 16)); s.Add((byte)(value >> 8)); s.Add((byte)value);
        }
        private static void WriteHpackStr(List<byte> o, string s)
        {
            byte[] b = Encoding.ASCII.GetBytes(s);
            EncodeInt(o, b.Length, 7, 0x00);
            o.AddRange(b);
        }
        private static void EncodeInt(List<byte> o, int value, int prefixBits, int high)
        {
            int mask = (1 << prefixBits) - 1;
            if (value < mask) { o.Add((byte)(high | value)); return; }
            o.Add((byte)(high | mask));
            value -= mask;
            while (value >= 128) { o.Add((byte)((value & 0x7F) | 0x80)); value >>= 7; }
            o.Add((byte)value);
        }
        private static int HpackFindStatus(byte[] b, int start, int end)
        {
            int pos = start, status = -1;
            while (pos < end)
            {
                int cur = b[pos];
                if ((cur & 0x80) != 0) { int idx = DecodeInt(b, ref pos, 7); int s = StaticStatus(idx); if (s > 0) status = s; }
                else if ((cur & 0x40) != 0) { int ni = DecodeInt(b, ref pos, 6); if (ni == 0) SkipStr(b, ref pos); bool huff; byte[] val = ReadStr(b, ref pos, out huff); if (ni >= 8 && ni <= 14 && !huff) { int s = ParseAscii(val); if (s > 0) status = s; } }
                else if ((cur & 0x20) != 0) { DecodeInt(b, ref pos, 5); }
                else { int ni = DecodeInt(b, ref pos, 4); if (ni == 0) SkipStr(b, ref pos); bool huff; byte[] val = ReadStr(b, ref pos, out huff); if (ni >= 8 && ni <= 14 && !huff) { int s = ParseAscii(val); if (s > 0) status = s; } }
            }
            return status;
        }
        private static int StaticStatus(int idx)
        {
            switch (idx) { case 8: return 200; case 9: return 204; case 10: return 206; case 11: return 304; case 12: return 400; case 13: return 404; case 14: return 500; default: return -1; }
        }
        private static int ParseAscii(byte[] b)
        {
            if (b == null || b.Length == 0) return -1;
            int v = 0; foreach (byte c in b) { if (c < '0' || c > '9') return -1; v = v * 10 + (c - '0'); } return v;
        }
        private static byte[] ReadStr(byte[] b, ref int pos, out bool huff)
        {
            huff = (b[pos] & 0x80) != 0;
            int len = DecodeInt(b, ref pos, 7);
            byte[] r = new byte[len]; Array.Copy(b, pos, r, 0, len); pos += len; return r;
        }
        private static void SkipStr(byte[] b, ref int pos) { bool huff; ReadStr(b, ref pos, out huff); }
        private static int DecodeInt(byte[] b, ref int pos, int prefixBits)
        {
            int mask = (1 << prefixBits) - 1;
            int val = b[pos++] & mask;
            if (val < mask) return val;
            int m = 0, bb;
            do { bb = b[pos++]; val += (bb & 0x7F) << m; m += 7; } while ((bb & 0x80) != 0);
            return val;
        }
    }

    // Пул общих туннелей. Сейчас в конфиге один сервер, поэтому пул глобальный.
    internal static class H2MuxRegistry
    {
        private const int MaxConnsPerServer = 4;
        private const int SoftStreamCap = 60;

        private static readonly object _lock = new object();
        private static readonly List<H2MuxTransport> _pool = new List<H2MuxTransport>();

        public static async Task<H2Stream> AcquireStreamAsync(VlessConfig cfg)
        {
            for (int attempt = 0; attempt <= MaxConnsPerServer; attempt++)
            {
                H2MuxTransport t = PickOrCreate(cfg);
                if (t == null) return null;
                if (!await t.EnsureStartedAsync()) { Remove(t); continue; }
                H2Stream st = await t.OpenStreamAsync();
                if (st != null) return st;
                Remove(t);
            }
            return null;
        }

        private static H2MuxTransport PickOrCreate(VlessConfig cfg)
        {
            lock (_lock)
            {
                _pool.RemoveAll(x => x.Dead);

                H2MuxTransport best = null; int bestLoad = int.MaxValue;
                foreach (var t in _pool) { int l = t.Load; if (l < bestLoad) { bestLoad = l; best = t; } }

                if (best != null && best.TryReserve(SoftStreamCap)) return best;

                if (_pool.Count < MaxConnsPerServer)
                {
                    var nt = new H2MuxTransport(cfg);
                    _pool.Add(nt);
                    nt.TryReserve(SoftStreamCap);
                    return nt;
                }

                if (best != null) { best.ForceReserve(); return best; } // оверсабскрайб
                return null;
            }
        }

        public static void Remove(H2MuxTransport t) { lock (_lock) { _pool.Remove(t); } }

        public static void Reset()
        {
            List<H2MuxTransport> all;
            lock (_lock) { all = new List<H2MuxTransport>(_pool); _pool.Clear(); }
            foreach (var t in all) t.KillAll();
        }
    }
}
