using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    // VLESS-over-WebSocket-over-TLS. TLS делает система (UpgradeToSslAsync) — валидный
    // отпечаток ОС, никакого рукописного Reality. Мы отвечаем только за WS-апгрейд (RFC 6455)
    // и кадрирование. Один канал: один WS = одно TCP-соединение (в direct-режиме на каждый
    // поток от ОС). Конкурентного read+write на сокете нет (пишем и читаем в разных местах,
    // но НЕ одновременно из двух потоков в одну сторону — сериализуем запись _writeLock'ом).
    internal sealed class WsTransport
    {
        private readonly VlessConfig _cfg;
        private StreamSocket _socket;
        private Stream _out;              // поверх зашифрованного OutputStream
        private DataReader _reader;

        private readonly System.Threading.SemaphoreSlim _writeLock =
            new System.Threading.SemaphoreSlim(1, 1);
        private readonly Random _rnd = new Random();

        // приёмный буфер для дефрагментации WS-кадров
        private byte[] _rx = new byte[65536];
        private int _rxLen;

        public bool Closed { get; private set; }

        public WsTransport(VlessConfig cfg) { _cfg = cfg; }

        public async Task<bool> ConnectAsync(int timeoutMs = 8000)
        {
            try
            {
                string targetHost = string.IsNullOrEmpty(VlessVpnPlugin.ServerIp)
                    ? _cfg.Address : VlessVpnPlugin.ServerIp;
                string sni = !string.IsNullOrEmpty(_cfg.Sni) ? _cfg.Sni : _cfg.Address;

                _socket = new StreamSocket();
                _socket.Control.NoDelay = true;
                _socket.Control.KeepAlive = true;

                // TLS-имя проверки берём из SNI (validationHostName), но коннектимся по IP/хосту.
                var connectOp = _socket.ConnectAsync(
                    new HostName(targetHost), _cfg.Port.ToString(),
                    SocketProtectionLevel.PlainSocket);

                var ct = connectOp.AsTask();
                if (await Task.WhenAny(ct, Task.Delay(timeoutMs)) != ct)
                { try { connectOp.Cancel(); } catch { } Close(); return false; }
                await ct;

                // === TLS: система выполняет полноценный handshake под именем SNI ===
                var sslOp = _socket.UpgradeToSslAsync(SocketProtectionLevel.Tls12, new HostName(sni));
                var st = sslOp.AsTask();
                if (await Task.WhenAny(st, Task.Delay(timeoutMs)) != st)
                { try { sslOp.Cancel(); } catch { } Close(); return false; }
                await st;

                _out = _socket.OutputStream.AsStreamForWrite(81920);
                _reader = new DataReader(_socket.InputStream);
                _reader.InputStreamOptions = InputStreamOptions.Partial;

                FileLog.Important($"[WS] TLS поднят системой к {sni}:{_cfg.Port}. Апгрейд WebSocket...");
                if (!await DoUpgradeAsync()) { Close(); return false; }
                FileLog.Important("[WS] WebSocket-соединение установлено.");
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[WS ERROR] Connect: {ex.Message}");
                Close();
                return false;
            }
        }

        private async Task<bool> DoUpgradeAsync()
        {
            byte[] keyBytes = Tls13Crypto.RandomBytes(16);
            string secKey = Convert.ToBase64String(keyBytes);
            string host = !string.IsNullOrEmpty(_cfg.Host) ? _cfg.Host
                        : (!string.IsNullOrEmpty(_cfg.Sni) ? _cfg.Sni : _cfg.Address);
            string path = string.IsNullOrEmpty(_cfg.Path) ? "/" : _cfg.Path;

            var sb = new StringBuilder();
            sb.Append("GET ").Append(path).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(host).Append("\r\n");
            sb.Append("User-Agent: Mozilla/5.0\r\n");
            sb.Append("Connection: Upgrade\r\n");
            sb.Append("Upgrade: websocket\r\n");
            sb.Append("Sec-WebSocket-Version: 13\r\n");
            sb.Append("Sec-WebSocket-Key: ").Append(secKey).Append("\r\n");
            sb.Append("\r\n");

            byte[] req = Encoding.ASCII.GetBytes(sb.ToString());
            _out.Write(req, 0, req.Length);
            await _out.FlushAsync();

            // читаем ответ до \r\n\r\n
            var head = new List<byte>();
            var deadline = DateTime.UtcNow.AddSeconds(10);
            int hdrEnd = -1;
            while (hdrEnd < 0)
            {
                if (DateTime.UtcNow > deadline)
                { FileLog.Important("[WS ERROR] Таймаут ответа на апгрейд."); return false; }
                if (!await LoadSomeAsync()) return false;
                DrainReaderInto(head);
                hdrEnd = FindDoubleCrlf(head);
            }

            string resp = Encoding.ASCII.GetString(head.ToArray(), 0, hdrEnd);
            string statusLine = resp.Split(new[] { "\r\n" }, StringSplitOptions.None)[0];
            FileLog.Important($"[WS] <<< {statusLine}");

            if (statusLine.IndexOf("101", StringComparison.Ordinal) < 0)
            {
                FileLog.Important("[WS ERROR] Сервер не принял апгрейд (ожидался 101). Проверьте path/host.");
                return false;
            }

            // проверка Sec-WebSocket-Accept
            string expect = Convert.ToBase64String(Tls13Crypto.Sha256(
                Encoding.ASCII.GetBytes(secKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
            bool okAccept = resp.IndexOf(expect, StringComparison.OrdinalIgnoreCase) >= 0;
            if (!okAccept)
                FileLog.Important("[WS] ВНИМАНИЕ: Sec-WebSocket-Accept не совпал (продолжаю, некоторые CDN его опускают).");

            // байты тела, пришедшие вместе с заголовком, оставляем в _rx как начало WS-потока
            int rest = head.Count - (hdrEnd + 4);
            if (rest > 0) FeedRx(head.GetRange(hdrEnd + 4, rest).ToArray());
            return true;
        }

        // ===== запись: одно WS-сообщение (binary) с маскированием =====
        public async Task SendAsync(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            await _writeLock.WaitAsync();
            try
            {
                byte[] frame = BuildFrame(0x2, data); // opcode 0x2 = binary
                _out.Write(frame, 0, frame.Length);
                await _out.FlushAsync();
            }
            finally { _writeLock.Release(); }
        }

        private byte[] BuildFrame(byte opcode, byte[] payload)
        {
            int n = payload.Length;
            var ms = new MemoryStream();
            ms.WriteByte((byte)(0x80 | opcode)); // FIN + opcode

            byte maskBit = 0x80; // клиент ОБЯЗАН маскировать
            if (n < 126) ms.WriteByte((byte)(maskBit | n));
            else if (n <= 0xFFFF)
            {
                ms.WriteByte((byte)(maskBit | 126));
                ms.WriteByte((byte)(n >> 8)); ms.WriteByte((byte)n);
            }
            else
            {
                ms.WriteByte((byte)(maskBit | 127));
                for (int i = 7; i >= 0; i--) ms.WriteByte((byte)((long)n >> (8 * i)));
            }

            byte[] mask = new byte[4];
            lock (_rnd) _rnd.NextBytes(mask);
            ms.Write(mask, 0, 4);

            byte[] masked = new byte[n];
            for (int i = 0; i < n; i++) masked[i] = (byte)(payload[i] ^ mask[i & 3]);
            ms.Write(masked, 0, n);
            return ms.ToArray();
        }

        // ===== чтение: возвращает payload одного или нескольких склеенных data-кадров =====
        // Возвращает распакованные прикладные байты (VLESS-поток), null при закрытии.
        public async Task<byte[]> ReceiveAsync()
        {
            while (true)
            {
                byte[] parsed = TryParseFrames();
                if (parsed == null) { Closed = true; return null; } // получен Close
                if (parsed.Length > 0) return parsed;

                // не хватает данных — дочитываем из сокета
                if (!await LoadSomeAsync()) { Closed = true; return null; }
                DrainReaderIntoRx();
            }
        }

        // Разбирает все полные кадры в _rx. Данные аккумулирует, служебные обрабатывает.
        // Возврат: собранные data-байты (может быть пусто, если пришёл только ping/неполный кадр),
        // либо null если пришёл Close.
        private byte[] TryParseFrames()
        {
            var outp = new List<byte>();
            int p = 0;

            while (true)
            {
                if (_rxLen - p < 2) break;
                byte b0 = _rx[p];
                byte b1 = _rx[p + 1];
                bool fin = (b0 & 0x80) != 0;
                int opcode = b0 & 0x0F;
                bool masked = (b1 & 0x80) != 0; // сервер->клиент маскирования быть не должно
                long len = b1 & 0x7F;
                int hdr = 2;

                if (len == 126)
                {
                    if (_rxLen - p < 4) break;
                    len = (_rx[p + 2] << 8) | _rx[p + 3];
                    hdr = 4;
                }
                else if (len == 127)
                {
                    if (_rxLen - p < 10) break;
                    len = 0;
                    for (int i = 0; i < 8; i++) len = (len << 8) | _rx[p + 2 + i];
                    hdr = 10;
                }

                int maskLen = masked ? 4 : 0;
                if (_rxLen - p < hdr + maskLen + len) break; // кадр не целиком

                int dataOff = p + hdr + maskLen;
                byte[] frameData = new byte[len];
                if (masked)
                {
                    byte[] m = new byte[4];
                    Array.Copy(_rx, p + hdr, m, 0, 4);
                    for (int i = 0; i < len; i++) frameData[i] = (byte)(_rx[dataOff + i] ^ m[i & 3]);
                }
                else
                {
                    Array.Copy(_rx, dataOff, frameData, 0, (int)len);
                }

                p += (int)(hdr + maskLen + len);

                switch (opcode)
                {
                    case 0x0: // continuation
                    case 0x1: // text (не ждём, но принимаем как данные)
                    case 0x2: // binary
                        outp.AddRange(frameData);
                        break;
                    case 0x8: // close
                        ConsumeRx(p);
                        return null;
                    case 0x9: // ping -> pong
                        _ = SendControlAsync(0xA, frameData);
                        break;
                    case 0xA: // pong
                        break;
                    default:
                        break;
                }
                // fin нам не важен: и континуацию, и отдельные кадры просто конкатенируем
            }

            ConsumeRx(p);
            return outp.Count == 0 ? new byte[0] : outp.ToArray();
        }

        private async Task SendControlAsync(byte opcode, byte[] payload)
        {
            try
            {
                await _writeLock.WaitAsync();
                try
                {
                    byte[] frame = BuildFrame(opcode, payload ?? new byte[0]);
                    _out.Write(frame, 0, frame.Length);
                    await _out.FlushAsync();
                }
                finally { _writeLock.Release(); }
            }
            catch { }
        }

        // ===== буфер приёма =====
        private void FeedRx(byte[] data)
        {
            EnsureRx(data.Length);
            System.Buffer.BlockCopy(data, 0, _rx, _rxLen, data.Length);
            _rxLen += data.Length;
        }

        private void EnsureRx(int extra)
        {
            if (_rxLen + extra <= _rx.Length) return;
            int cap = _rx.Length * 2;
            while (cap < _rxLen + extra) cap *= 2;
            Array.Resize(ref _rx, cap);
        }

        private void ConsumeRx(int n)
        {
            if (n <= 0) return;
            _rxLen -= n;
            if (_rxLen > 0) System.Buffer.BlockCopy(_rx, n, _rx, 0, _rxLen);
        }

        private async Task<bool> LoadSomeAsync()
        {
            try
            {
                uint got = await _reader.LoadAsync(16384);
                return got != 0;
            }
            catch { return false; }
        }

        private void DrainReaderIntoRx()
        {
            uint avail = _reader.UnconsumedBufferLength;
            if (avail == 0) return;
            byte[] tmp = new byte[avail];
            _reader.ReadBytes(tmp);
            FeedRx(tmp);
        }

        private void DrainReaderInto(List<byte> sink)
        {
            uint avail = _reader.UnconsumedBufferLength;
            if (avail == 0) return;
            byte[] tmp = new byte[avail];
            _reader.ReadBytes(tmp);
            sink.AddRange(tmp);
        }

        private static int FindDoubleCrlf(List<byte> b)
        {
            for (int i = 0; i + 3 < b.Count; i++)
                if (b[i] == 0x0D && b[i + 1] == 0x0A && b[i + 2] == 0x0D && b[i + 3] == 0x0A)
                    return i;
            return -1;
        }

        public void Close()
        {
            Closed = true;
            try { _out?.Dispose(); } catch { }
            try { _reader?.Dispose(); } catch { }
            try { _socket?.Dispose(); } catch { }
        }
    }
}