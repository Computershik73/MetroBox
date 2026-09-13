using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace VlessVpnTask
{
    // Минимальный клиент HTTP/2 для xhttp stream-one.
    // Один H2-поток (stream id = 1) на одно Reality-соединение.
    // I/O-free: строит байты для отправки и разбирает входящие кадры.
    // Реальную запись/чтение через Reality делает VlessConnection.
    internal sealed class Http2Conn
    {
        // ---- настройки нашего приёмного окна ----
        private const int RecvWindow = 512 * 1024;   // 8 МБ на поток и на соединение

        private static readonly byte[] Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        private readonly string _authority;
        private readonly string _path;
        private readonly string _referer;

        // приёмный буфер сырого H2 (plaintext после расшифровки Reality)
        private byte[] _buf = new byte[65536];
        private int _bufLen = 0;

        // готовые к отправке управляющие кадры (ACK SETTINGS, WINDOW_UPDATE, PING ACK)
        private readonly List<byte> _pending = new List<byte>();

        // распарсенный downstream (полезные данные DATA на stream 1)
        private readonly Queue<byte[]> _downstream = new Queue<byte[]>();
        private long _rxDataTotal; // всего принято downstream-байт (диагностика)
        private long _txDataTotal; // всего отправлено upstream-байт (диагностика)

        // окна отправки (сколько МЫ можем послать); server INITIAL_WINDOW_SIZE по умолчанию 65535
        private readonly object _wlock = new object();
        private int _connSend = 65535;
        private int _streamSend = 65535;
        private int _curInit = 65535;     // текущее значение server INITIAL_WINDOW_SIZE
        private int _peerMaxFrame = 16384; // server MAX_FRAME_SIZE
        private TaskCompletionSource<bool> _winTcs;

        public bool HeadersDone { get; private set; }
        public int Status { get; private set; } = -1;
        public bool StreamClosed { get; private set; }
        public int PeerMaxFrame { get { return _peerMaxFrame; } }

        public Http2Conn(VlessConfig cfg)
        {
            string host = !string.IsNullOrEmpty(cfg.Host) ? cfg.Host
                        : (!string.IsNullOrEmpty(cfg.Sni) ? cfg.Sni : cfg.Address);
            _authority = host;

            string p = string.IsNullOrEmpty(cfg.Path) ? "/" : cfg.Path;
            if (!p.EndsWith("/")) p += "/";
            _path = p;

            int padMin = cfg.XPaddingMin > 0 ? cfg.XPaddingMin : 100;
            int padMax = cfg.XPaddingMax > padMin ? cfg.XPaddingMax : 1000;
            int padLen = new Random().Next(padMin, padMax + 1);
            _referer = "https://" + host + "/?x_padding=" + new string('X', padLen);
        }

        // ===== ОТПРАВКА (строим байты) =====

        // preface + наш SETTINGS + WINDOW_UPDATE на соединение
        public byte[] BuildClientHandshake()
        {
            var o = new List<byte>();
            o.AddRange(Preface);

            var s = new List<byte>();
            AddSetting(s, 0x1, 0);            // HEADER_TABLE_SIZE = 0 (запрет динамической индексации сервером)
            AddSetting(s, 0x2, 0);            // ENABLE_PUSH = 0
            AddSetting(s, 0x4, RecvWindow);   // INITIAL_WINDOW_SIZE (наши приёмные потоки)
            WriteFrameHeader(o, s.Count, 0x4, 0x0, 0);
            o.AddRange(s);

            // увеличиваем окно соединения сверх дефолтных 65535
            int inc = RecvWindow - 65535;
            WriteFrameHeader(o, 4, 0x8, 0x0, 0);
            o.Add((byte)(inc >> 24)); o.Add((byte)(inc >> 16)); o.Add((byte)(inc >> 8)); o.Add((byte)inc);

            return o.ToArray();
        }

        // HEADERS для POST stream-one на stream 1 (END_HEADERS, без END_STREAM)
        public byte[] BuildHeaders()
        {
            var h = new List<byte>();
            h.Add(0x83);                              // :method POST   (static idx 3)
            h.Add(0x87);                              // :scheme https  (static idx 7)
            h.Add(0x01); WriteHpackStr(h, _authority); // :authority (static name idx 1)
            h.Add(0x04); WriteHpackStr(h, _path);      // :path      (static name idx 4)
            h.Add(0x00); WriteHpackStr(h, "content-type"); WriteHpackStr(h, "application/octet-stream");
            h.Add(0x00); WriteHpackStr(h, "referer"); WriteHpackStr(h, _referer);

            var o = new List<byte>();
            WriteFrameHeader(o, h.Count, 0x1, 0x4, 1); // type=HEADERS, flags=END_HEADERS
            o.AddRange(h);
            return o.ToArray();
        }

        // DATA-кадр на stream 1 (payload[off..off+len])
        public byte[] FrameData(byte[] data, int off, int len, bool endStream)
        {
            _txDataTotal += len;
            var o = new List<byte>(9 + len);
            WriteFrameHeader(o, len, 0x0, (byte)(endStream ? 0x1 : 0x0), 1);
            for (int i = 0; i < len; i++) o.Add(data[off + i]);
            return o.ToArray();
        }

        // ===== контроль окна отправки =====

        public bool TryReserveSend(int len)
        {
            lock (_wlock)
            {
                if (StreamClosed) return true; // пусть писатель сам проверит StreamClosed и выйдет
                if (_connSend >= len && _streamSend >= len)
                {
                    _connSend -= len;
                    _streamSend -= len;
                    return true;
                }
                return false;
            }
        }

        public Task WaitWindowAsync()
        {
            lock (_wlock)
            {
                if (_winTcs == null || _winTcs.Task.IsCompleted)
                    _winTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                return _winTcs.Task;
            }
        }

        private void SignalWindow()
        {
            lock (_wlock)
            {
                if (_winTcs != null && !_winTcs.Task.IsCompleted) _winTcs.TrySetResult(true);
            }
        }

        // ===== ПРИЁМ =====

        public byte[] TakePending()
        {
            if (_pending.Count == 0) return null;
            byte[] r = _pending.ToArray();
            _pending.Clear();
            return r;
        }

        public byte[] Pull()
        {
            return _downstream.Count > 0 ? _downstream.Dequeue() : null;
        }

        public void Feed(byte[] plain)
        {
            if (plain != null && plain.Length > 0)
            {
                if (_bufLen + plain.Length > _buf.Length)
                {
                    int newCap = _buf.Length * 2;
                    while (newCap < _bufLen + plain.Length) newCap *= 2;
                    Array.Resize(ref _buf, newCap);
                }
                Buffer.BlockCopy(plain, 0, _buf, _bufLen, plain.Length);
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
                Buffer.BlockCopy(_buf, fp, payload, 0, len);

                HandleFrame(type, flags, sid, payload);
                p = fp + len;
            }

            if (p > 0)
            {
                _bufLen -= p;
                if (_bufLen > 0) Buffer.BlockCopy(_buf, p, _buf, 0, _bufLen);
            }
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

                        int buffered = 0;
                        if (sid == 1 && dataLen > 0)
                        {
                            byte[] d = new byte[dataLen];
                            Array.Copy(payload, dataStart, d, 0, dataLen);
                            _downstream.Enqueue(d);
                            buffered = dataLen;
                            _rxDataTotal += dataLen;
                        }

                        // Окно возвращаем СРАЗУ только на часть кадра, которую не держим в памяти
                        // (padding, padlen-байт). Данные, осевшие в _downstream, кредитуем ПОЗЖЕ —
                        // после доставки в ОС. Это и есть back-pressure: сервер не зальёт нас быстрее,
                        // чем мы успеваем отдавать в туннель, и буфер не растёт до OOM.
                        int immediate = payload.Length - buffered;
                        if (immediate > 0)
                        {
                            QueueWindowUpdate(0, immediate);                 // окно соединения
                            if (sid == 1) QueueWindowUpdate(1, immediate);   // окно потока
                        }

                        if (sid == 1 && (flags & 0x1) != 0)
                        {
                            FileLog.Important($"[H2] поток закрыт сервером (END_STREAM), downstream={_rxDataTotal}b, upstream={_txDataTotal}b, статус={Status}");
                            StreamClosed = true; SignalWindow();
                        }
                        break;
                    }
                case 0x1: // HEADERS
                    {
                        int pos = 0;
                        int blockEnd = payload.Length;
                        if ((flags & 0x8) != 0) // PADDED
                        {
                            int padLen = payload.Length > 0 ? payload[0] : 0;
                            pos = 1;
                            blockEnd = payload.Length - padLen;
                        }
                        if ((flags & 0x20) != 0) pos += 5; // PRIORITY: 5 байт

                        int st = HpackFindStatus(payload, pos, blockEnd);
                        if (st > 0) Status = st;
                        HeadersDone = true; // считаем END_HEADERS установленным (мелкие заголовки)
                        if ((flags & 0x1) != 0) { StreamClosed = true; SignalWindow(); }
                        break;
                    }
                case 0x3: // RST_STREAM
                    {
                        int err = payload.Length >= 4
                            ? ((payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]) : -1;
                        FileLog.Important($"[H2] <<< RST_STREAM sid={sid} error={err}, downstream={_rxDataTotal}b, upstream={_txDataTotal}b, статус={Status} (сервер сбросил поток)");
                        if (sid == 1) { StreamClosed = true; SignalWindow(); }
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
                        int lastId = payload.Length >= 4
                            ? ((payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3]) : -1;
                        int err = payload.Length >= 8
                            ? ((payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]) : -1;
                        FileLog.Important($"[H2] <<< GOAWAY lastStream={lastId} error={err} (сервер закрыл соединение)");
                        StreamClosed = true; SignalWindow();
                        break;
                    }
                case 0x8: // WINDOW_UPDATE
                    {
                        int inc = ((payload[0] & 0x7F) << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
                        lock (_wlock)
                        {
                            if (sid == 0) _connSend += inc;
                            else if (sid == 1) _streamSend += inc;
                        }
                        SignalWindow();
                        break;
                    }
                default:
                    break; // PRIORITY/CONTINUATION/PUSH — игнор
            }
        }

        // Вызывается из read-loop ПОСЛЕ того, как чанк отдан в ОС.
        public void CreditConsumed(int n)
        {
            if (n <= 0) return;
            QueueWindowUpdate(0, n);  // окно соединения
            QueueWindowUpdate(1, n);  // окно потока
        }

        private void ApplyServerSettings(byte[] p)
        {
            for (int i = 0; i + 6 <= p.Length; i += 6)
            {
                int id = (p[i] << 8) | p[i + 1];
                long v = ((long)p[i + 2] << 24) | ((long)p[i + 3] << 16) | ((long)p[i + 4] << 8) | p[i + 5];
                if (id == 0x4) // INITIAL_WINDOW_SIZE -> наше окно отправки на поток
                {
                    lock (_wlock)
                    {
                        int delta = (int)(v - _curInit);
                        _streamSend += delta;
                        _curInit = (int)v;
                    }
                    SignalWindow();
                }
                else if (id == 0x5) // MAX_FRAME_SIZE
                {
                    _peerMaxFrame = (int)v;
                }
            }
        }

        // ===== HPACK (минимум: пропуск + поиск :status) =====

        private static int HpackFindStatus(byte[] b, int start, int end)
        {
            int pos = start, status = -1;
            while (pos < end)
            {
                int cur = b[pos];
                if ((cur & 0x80) != 0) // Indexed
                {
                    int idx = DecodeInt(b, ref pos, 7);
                    int s = StaticStatus(idx);
                    if (s > 0) status = s;
                }
                else if ((cur & 0x40) != 0) // Literal incremental, name idx 6-bit
                {
                    int ni = DecodeInt(b, ref pos, 6);
                    if (ni == 0) SkipStr(b, ref pos);
                    bool huff; byte[] val = ReadStr(b, ref pos, out huff);
                    if (ni >= 8 && ni <= 14 && !huff) { int s = ParseAscii(val); if (s > 0) status = s; }
                }
                else if ((cur & 0x20) != 0) // Dynamic table size update
                {
                    DecodeInt(b, ref pos, 5);
                }
                else // Literal without/never indexing, name idx 4-bit
                {
                    int ni = DecodeInt(b, ref pos, 4);
                    if (ni == 0) SkipStr(b, ref pos);
                    bool huff; byte[] val = ReadStr(b, ref pos, out huff);
                    if (ni >= 8 && ni <= 14 && !huff) { int s = ParseAscii(val); if (s > 0) status = s; }
                }
            }
            return status;
        }

        private static int StaticStatus(int idx)
        {
            switch (idx)
            {
                case 8: return 200;
                case 9: return 204;
                case 10: return 206;
                case 11: return 304;
                case 12: return 400;
                case 13: return 404;
                case 14: return 500;
                default: return -1;
            }
        }

        private static int ParseAscii(byte[] b)
        {
            int v = 0;
            if (b == null || b.Length == 0) return -1;
            foreach (byte c in b) { if (c < '0' || c > '9') return -1; v = v * 10 + (c - '0'); }
            return v;
        }

        private static byte[] ReadStr(byte[] b, ref int pos, out bool huff)
        {
            huff = (b[pos] & 0x80) != 0;
            int len = DecodeInt(b, ref pos, 7);
            byte[] r = new byte[len];
            Array.Copy(b, pos, r, 0, len);
            pos += len;
            return r;
        }

        private static void SkipStr(byte[] b, ref int pos)
        {
            bool huff; ReadStr(b, ref pos, out huff);
        }

        private static int DecodeInt(byte[] b, ref int pos, int prefixBits)
        {
            int mask = (1 << prefixBits) - 1;
            int val = b[pos++] & mask;
            if (val < mask) return val;
            int m = 0, bb;
            do { bb = b[pos++]; val += (bb & 0x7F) << m; m += 7; } while ((bb & 0x80) != 0);
            return val;
        }

        // ===== вспомогательное построение =====

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
            EncodeInt(o, b.Length, 7, 0x00); // huff=0
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

        private void QueueSettingsAck() { WriteFrameHeader(_pending, 0, 0x4, 0x1, 0); }

        private void QueuePingAck(byte[] payload)
        {
            WriteFrameHeader(_pending, 8, 0x6, 0x1, 0);
            for (int i = 0; i < 8 && i < payload.Length; i++) _pending.Add(payload[i]);
            for (int i = payload.Length; i < 8; i++) _pending.Add(0);
        }

        private void QueueWindowUpdate(int sid, int inc)
        {
            WriteFrameHeader(_pending, 4, 0x8, 0x0, sid);
            _pending.Add((byte)(inc >> 24)); _pending.Add((byte)(inc >> 16));
            _pending.Add((byte)(inc >> 8)); _pending.Add((byte)inc);
        }
    }
}