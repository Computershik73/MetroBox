using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace VlessVpnTask
{
    /// <summary>
    /// XHTTP stream-one (H1): один двунаправленный POST.
    /// Upstream  = тело POST, chunked.
    /// Downstream = тело ответа, chunked.
    /// Сидит МЕЖДУ vless/mux-потоком и Reality-шифрованием, NatEngine не трогает.
    /// </summary>
    internal class XhttpStreamOne
    {
        private readonly VlessConfig _cfg;
        private readonly Random _rnd = new Random();

        public string SessionId { get; private set; }
        public bool Chunked { get; private set; } = true;   // выставляется из ответа

        // ---- состояние де-чанкера ----
        private enum S { Size, Data, AfterCR, AfterLF, Done }
        private S _state = S.Size;
        private int _need;
        private readonly StringBuilder _sizeAcc = new StringBuilder();
        private byte[] _buf = new byte[65536];
        private int _bufLen = 0;
        private bool _headDone;

        public XhttpStreamOne(VlessConfig cfg)
        {
            _cfg = cfg;
            SessionId = Guid.NewGuid().ToString("N");
        }

        // ===================== REQUEST HEAD =====================
        public byte[] BuildRequestHead()
        {
            // приоритет host: host > sni > address
            string host = !string.IsNullOrEmpty(_cfg.Host) ? _cfg.Host
                        : (!string.IsNullOrEmpty(_cfg.Sni) ? _cfg.Sni : _cfg.Address);

            string path = string.IsNullOrEmpty(_cfg.Path) ? "/" : _cfg.Path;
            if (!path.EndsWith("/")) path += "/";   // stream-one всегда c завершающим '/'

            int padLen = _rnd.Next(_cfg.XPaddingMin, _cfg.XPaddingMax + 1);
            string pad = new string('X', padLen);   // 'X' = 8 бит в huffman, как в спеке

            var sb = new StringBuilder();
            sb.Append("POST ").Append(path).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(host).Append("\r\n");
            sb.Append("User-Agent: Go-http-client/1.1\r\n");
            sb.Append("Transfer-Encoding: chunked\r\n");
            // gRPC-маскировка по умолчанию ВЫКЛ — чистый октет-стрим (см. конфиг сервера ниже)
            sb.Append("Content-Type: ").Append(_cfg.NoGrpcHeader ? "application/octet-stream" : "application/grpc").Append("\r\n");
            // header padding кладём в Referer (как в спеке), чтобы не плодить OPTIONS
            sb.Append("Referer: https://").Append(host).Append("/?x_padding=").Append(pad).Append("\r\n");
            sb.Append("Accept-Encoding: identity\r\n");
            sb.Append("\r\n");

            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        // ===================== UPSTREAM CHUNK =====================
        // Оборачивает кусок (vless-header + mux-кадр) в HTTP-chunk.
        public byte[] WrapChunk(byte[] data)
        {
            if (data == null || data.Length == 0) return new byte[0];
            byte[] head = Encoding.ASCII.GetBytes(data.Length.ToString("x") + "\r\n");
            byte[] outp = new byte[head.Length + data.Length + 2];
            Buffer.BlockCopy(head, 0, outp, 0, head.Length);
            Buffer.BlockCopy(data, 0, outp, head.Length, data.Length);
            outp[outp.Length - 2] = 0x0D;
            outp[outp.Length - 1] = 0x0A;
            return outp;
        }

        // ===================== RESPONSE HEAD =====================
        // Скармливаем расшифрованный TLS-плейнтекст, пока не найдём \r\n\r\n.
        public bool TryConsumeResponseHead(byte[] tlsPlain, out string statusLine, out List<string> headers)
        {
            statusLine = null; headers = null;
            Feed(tlsPlain);

            int idx = IndexOfDoubleCrlf(_buf, _bufLen);
            if (idx < 0) return false;

            string head = Encoding.ASCII.GetString(_buf, 0, idx);
            string[] lines = head.Split(new[] { "\r\n" }, StringSplitOptions.None);
            statusLine = lines.Length > 0 ? lines[0] : "";
            headers = new List<string>();
            for (int i = 1; i < lines.Length; i++)
                if (lines[i].Length > 0) headers.Add(lines[i]);

            int removeLen = idx + 4;
            _bufLen -= removeLen;
            if (_bufLen > 0) Buffer.BlockCopy(_buf, removeLen, _buf, 0, _bufLen);

            _headDone = true;
            return true;
        }

        public void ConfigureFromResponse(List<string> headers)
        {
            bool te = false;
            foreach (var h in headers)
            {
                int c = h.IndexOf(':');
                if (c < 0) continue;
                string k = h.Substring(0, c).Trim().ToLowerInvariant();
                string v = h.Substring(c + 1).Trim();
                if (k == "transfer-encoding" && v.ToLowerInvariant().Contains("chunked")) te = true;
                if (k == "content-type") FileLog.Important($"[XHTTP] Content-Type ответа: {v}");
            }
            Chunked = te;
            if (!te) FileLog.Important("[XHTTP] ВНИМАНИЕ: ответ без 'Transfer-Encoding: chunked' — включаю raw-passthrough.");
        }

        // ===================== DOWNSTREAM DE-CHUNK =====================
        public void Feed(byte[] tlsPlain)
        {
            if (tlsPlain != null && tlsPlain.Length > 0)
            {
                if (_bufLen + tlsPlain.Length > _buf.Length)
                {
                    int newCap = _buf.Length * 2;
                    while (newCap < _bufLen + tlsPlain.Length) newCap *= 2;
                    Array.Resize(ref _buf, newCap);
                }
                Buffer.BlockCopy(tlsPlain, 0, _buf, _bufLen, tlsPlain.Length);
                _bufLen += tlsPlain.Length;
            }
        }

        // Достаёт распарсенные данные из накопленного буфера. Может вернуть пустой массив.
        public byte[] Pull()
        {
            if (!Chunked)
            {
                if (_bufLen == 0) return new byte[0];
                byte[] all = new byte[_bufLen];
                Buffer.BlockCopy(_buf, 0, all, 0, _bufLen);
                _bufLen = 0;
                return all;
            }

            var outp = new List<byte>();
            int i = 0;
            while (i < _bufLen && _state != S.Done)
            {
                if (_state == S.Size)
                {
                    byte b = _buf[i++];
                    if (b == (byte)'\n')
                    {
                        string line = _sizeAcc.ToString().Trim();
                        _sizeAcc.Clear();
                        int semi = line.IndexOf(';');
                        if (semi >= 0) line = line.Substring(0, semi);
                        int sz;
                        try { sz = Convert.ToInt32(line, 16); }
                        catch { FileLog.Important($"[XHTTP ERROR] Битый chunk-size: '{line}'"); _state = S.Done; break; }

                        if (sz == 0) { _state = S.Done; break; }
                        _need = sz;
                        _state = S.Data;
                    }
                    else if (b != (byte)'\r')
                    {
                        _sizeAcc.Append((char)b);
                        if (_sizeAcc.Length > 16) { _state = S.Done; break; }
                    }
                }
                else if (_state == S.Data)
                {
                    int take = Math.Min(_bufLen - i, _need);
                    for (int k = 0; k < take; k++) outp.Add(_buf[i + k]);
                    i += take; _need -= take;
                    if (_need == 0) _state = S.AfterCR;
                }
                else if (_state == S.AfterCR)
                {
                    byte b = _buf[i++];
                    if (b == (byte)'\n') _state = S.Size;
                    else _state = S.AfterLF;
                }
                else if (_state == S.AfterLF)
                {
                    i++;
                    _state = S.Size;
                }
            }

            if (i > 0)
            {
                _bufLen -= i;
                if (_bufLen > 0) Buffer.BlockCopy(_buf, i, _buf, 0, _bufLen);
            }
            return outp.Count == 0 ? new byte[0] : outp.ToArray();
        }

        public bool StreamClosed => _state == S.Done;

        private static int IndexOfDoubleCrlf(byte[] b, int length)
        {
            for (int i = 0; i + 3 < length; i++)
                if (b[i] == 0x0D && b[i + 1] == 0x0A && b[i + 2] == 0x0D && b[i + 3] == 0x0A)
                    return i;
            return -1;
        }
    }
}