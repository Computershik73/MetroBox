using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    // Reality-обёрнутый H1-сокет для xhttp split-режимов. Отдельный от VlessConnection,
    // чтобы не задевать рабочие mux/tcp/stream-one пути. Пишет/читает прикладные (расшифрованные)
    // байты. Конкурентного read+write на одном канале НЕТ (сериализуем на уровне выше).
    internal sealed class RealityChannel
    {
        private readonly VlessConfig _cfg;
        private StreamSocket _socket;
        private DataWriter _writer;
        private DataReader _reader;
        private RealityTls13Stream _reality;
        private Stream _outStream;

        public string NegotiatedAlpn => _reality != null ? _reality.NegotiatedAlpn : "";

        public RealityChannel(VlessConfig cfg) { _cfg = cfg; }

        public async Task<bool> ConnectAsync(int timeoutMs = 8000)
        {
            try
            {
                string targetHost = string.IsNullOrEmpty(VlessVpnPlugin.ServerIp)
                    ? _cfg.Address : VlessVpnPlugin.ServerIp;

                _socket = new StreamSocket();
                _socket.Control.NoDelay = true;
                _socket.Control.KeepAlive = true;

                Windows.Foundation.IAsyncAction connectOp;
                if (VlessVpnPlugin.PhysicalIp != null)
                {
                    var epp = new EndpointPair(VlessVpnPlugin.PhysicalIp, "",
                        new HostName(targetHost), _cfg.Port.ToString());
                    connectOp = _socket.ConnectAsync(epp, SocketProtectionLevel.PlainSocket);
                }
                else
                {
                    connectOp = _socket.ConnectAsync(new HostName(targetHost),
                        _cfg.Port.ToString(), SocketProtectionLevel.PlainSocket);
                }

                var ct = connectOp.AsTask();
                if (await Task.WhenAny(ct, Task.Delay(timeoutMs)) != ct)
                { try { connectOp.Cancel(); } catch { } Close(); return false; }
                await ct;

                _writer = new DataWriter(_socket.OutputStream);
                _reader = new DataReader(_socket.InputStream);
                _reader.InputStreamOptions = InputStreamOptions.Partial;

                // split всегда H1 -> просим ALPN только http/1.1
                _reality = new RealityTls13Stream(_cfg) { OfferH1Only = true };
                var hs = _reality.EstablishHandshakeAsync(_writer, _reader);
                if (await Task.WhenAny(hs, Task.Delay(timeoutMs)) != hs || !await hs)
                { Close(); return false; }
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[XHTTP SPLIT] RealityChannel connect fail: {ex.Message}");
                Close();
                return false;
            }
        }

        public async Task WriteAppAsync(byte[] data)
        {
            byte[] enc = _reality.EncryptRecord(data);
            if (_outStream == null) _outStream = _socket.OutputStream.AsStreamForWrite(81920);
            _outStream.Write(enc, 0, enc.Length);
            await _outStream.FlushAsync();
        }

        // Возвращает очередной расшифрованный plaintext (тип 23), пропуская CCS и тикеты.
        public async Task<byte[]> ReadPlaintextAsync()
        {
            while (true)
            {
                if (!await ReadExactAsync(5)) return null;
                byte[] header = new byte[5];
                _reader.ReadBytes(header);
                int len = (header[3] << 8) | header[4];
                if (len <= 0) continue;
                if (!await ReadExactAsync((uint)len)) return null;
                byte[] payload = new byte[len];
                _reader.ReadBytes(payload);

                if (header[0] == 20) continue; // ChangeCipherSpec
                byte innerType;
                byte[] plain = _reality.DecryptRecordExplicit(header, payload, out innerType);
                if (plain == null) return null;
                if (innerType == 23) return plain; // application data
                // иначе служебное (NewSessionTicket и т.п.) — пропускаем
            }
        }

        private async Task<bool> ReadExactAsync(uint count)
        {
            try
            {
                uint loaded = _reader.UnconsumedBufferLength;
                while (loaded < count)
                {
                    uint r = await _reader.LoadAsync(count - loaded);
                    if (r == 0) return false;
                    loaded += r;
                }
                return true;
            }
            catch { return false; }
        }

        public void Close()
        {
            try { _writer?.Dispose(); } catch { }
            try { _reader?.Dispose(); } catch { }
            try { _outStream?.Dispose(); } catch { }
            try { _socket?.Dispose(); } catch { }
        }
    }

    // Дечанкер HTTP/1.1 (вынесен, чтобы не связываться с XhttpStreamOne).
    internal sealed class ChunkedDecoder
    {
        public bool Chunked = true;
        private enum St { Size, Data, AfterCR, AfterLF, Done }
        private St _s = St.Size;
        private int _need;
        private readonly StringBuilder _sizeAcc = new StringBuilder();
        private byte[] _buf = new byte[65536];
        private int _len;

        public bool Done => _s == St.Done;

        public void Feed(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            if (_len + data.Length > _buf.Length)
            {
                int cap = _buf.Length * 2;
                while (cap < _len + data.Length) cap *= 2;
                Array.Resize(ref _buf, cap);
            }
            System.Buffer.BlockCopy(data, 0, _buf, _len, data.Length);
            _len += data.Length;
        }

        public byte[] Pull()
        {
            if (!Chunked)
            {
                if (_len == 0) return new byte[0];
                byte[] all = new byte[_len];
                System.Buffer.BlockCopy(_buf, 0, all, 0, _len);
                _len = 0;
                return all;
            }

            var outp = new List<byte>();
            int i = 0;
            while (i < _len && _s != St.Done)
            {
                if (_s == St.Size)
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
                        catch { _s = St.Done; break; }
                        if (sz == 0) { _s = St.Done; break; }
                        _need = sz; _s = St.Data;
                    }
                    else if (b != (byte)'\r')
                    {
                        _sizeAcc.Append((char)b);
                        if (_sizeAcc.Length > 16) { _s = St.Done; break; }
                    }
                }
                else if (_s == St.Data)
                {
                    int take = Math.Min(_len - i, _need);
                    for (int k = 0; k < take; k++) outp.Add(_buf[i + k]);
                    i += take; _need -= take;
                    if (_need == 0) _s = St.AfterCR;
                }
                else if (_s == St.AfterCR)
                {
                    byte b = _buf[i++];
                    if (b == (byte)'\n') _s = St.Size; else _s = St.AfterLF;
                }
                else if (_s == St.AfterLF) { i++; _s = St.Size; }
            }
            if (i > 0)
            {
                _len -= i;
                if (_len > 0) System.Buffer.BlockCopy(_buf, i, _buf, 0, _len);
            }
            return outp.Count == 0 ? new byte[0] : outp.ToArray();
        }
    }

    // Клиент xhttp stream-up / packet-up: отдельные download-GET и upload-POST соединения.
    internal sealed class XhttpSplitClient
    {
        private readonly VlessConfig _cfg;
        private readonly bool _packetUp;         // true=packet-up, false=stream-up
        private readonly string _sessionId;
        private readonly string _host;
        private readonly string _basePath;       // напр. "/xhttp" (без хвостового '/')
        private readonly byte[] _vlessHeader;    // ставится в начало upstream на первом write
        private readonly Random _rnd = new Random();
        private readonly string _modeName;

        private RealityChannel _down;
        private RealityChannel _up;

        private readonly ChunkedDecoder _dec = new ChunkedDecoder();
        private readonly SemaphoreSlim _upLock = new SemaphoreSlim(1, 1);

        private bool _headerSent;
        private bool _upStreamStarted;           // stream-up: chunked POST начат
        private long _seq;                        // packet-up: номер пакета
        private long _postRespCount;

        public bool DownClosed { get; private set; }

        public XhttpSplitClient(VlessConfig cfg, bool packetUp, byte[] vlessHeader)
        {
            _cfg = cfg;
            _packetUp = packetUp;
            _vlessHeader = vlessHeader ?? new byte[0];
            _modeName = packetUp ? "packet-up" : "stream-up";
            _sessionId = Guid.NewGuid().ToString("N");
            _host = !string.IsNullOrEmpty(cfg.Host) ? cfg.Host
                   : (!string.IsNullOrEmpty(cfg.Sni) ? cfg.Sni : cfg.Address);
            string p = string.IsNullOrEmpty(cfg.Path) ? "/" : cfg.Path;
            if (p.EndsWith("/")) p = p.TrimEnd('/');
            _basePath = p; // "" если был "/"
        }

        public async Task<bool> StartAsync()
        {
            FileLog.Important($"[XHTTP {_modeName}] старт: host={_host} path='{_basePath}' session={_sessionId}");

            // 1) download GET (сервер Xray отдаёт 200 сразу, не дожидаясь upload)
            _down = new RealityChannel(_cfg);
            if (!await _down.ConnectAsync())
            { FileLog.Important($"[XHTTP {_modeName}] download: Reality FAIL"); return false; }
            FileLog.Important($"[XHTTP {_modeName}] download ALPN='{_down.NegotiatedAlpn}'");

            await _down.WriteAppAsync(BuildDownloadGet());
            if (!await ReadDownloadHeadAsync()) return false;

            // 2) upload-канал (данные пойдут при первом WriteUpAsync)
            _up = new RealityChannel(_cfg);
            if (!await _up.ConnectAsync())
            { FileLog.Important($"[XHTTP {_modeName}] upload: Reality FAIL"); return false; }
            FileLog.Important($"[XHTTP {_modeName}] upload ALPN='{_up.NegotiatedAlpn}'");

            return true;
        }

        private async Task<bool> ReadDownloadHeadAsync()
        {
            var buf = new List<byte>();
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (true)
            {
                byte[] plain = await _down.ReadPlaintextAsync();
                if (plain == null)
                { FileLog.Important($"[XHTTP {_modeName}] download закрыт до заголовков"); return false; }
                buf.AddRange(plain);

                int idx = IndexOfDoubleCrlf(buf);
                if (idx >= 0)
                {
                    string head = Encoding.ASCII.GetString(buf.ToArray(), 0, idx);
                    string[] lines = head.Split(new[] { "\r\n" }, StringSplitOptions.None);
                    string status = lines.Length > 0 ? lines[0] : "";
                    bool chunked = false; string ctype = "";
                    for (int i = 1; i < lines.Length; i++)
                    {
                        int c = lines[i].IndexOf(':'); if (c < 0) continue;
                        string k = lines[i].Substring(0, c).Trim().ToLowerInvariant();
                        string v = lines[i].Substring(c + 1).Trim();
                        if (k == "transfer-encoding" && v.ToLowerInvariant().Contains("chunked")) chunked = true;
                        if (k == "content-type") ctype = v;
                    }
                    FileLog.Important($"[XHTTP {_modeName}] download <<< {status}");
                    FileLog.Important($"[XHTTP {_modeName}] download Content-Type='{ctype}' chunked={chunked}");

                    if (!status.Contains(" 200"))
                    {
                        FileLog.Important($"[XHTTP {_modeName}] СЕРВЕР НЕ ПРИНЯЛ download (не 200). " +
                                          $"Вероятно сервер не в режиме {_modeName} или неверный path/session.");
                        return false;
                    }

                    _dec.Chunked = chunked;
                    int rem = idx + 4;
                    if (buf.Count > rem)
                        _dec.Feed(buf.GetRange(rem, buf.Count - rem).ToArray());
                    return true;
                }

                if (DateTime.UtcNow > deadline)
                {
                    FileLog.Important($"[XHTTP {_modeName}] таймаут заголовков download (15с). " +
                                      $"Если ALPN='h2' — сервер форсит HTTP/2, split-over-h1 не пройдёт.");
                    return false;
                }
            }
        }

        // Возвращает сырые down-байты (VLESS-ответ ещё с заголовком, стрип делает VlessConnection).
        public async Task<byte[]> ReadDownAsync()
        {
            while (true)
            {
                byte[] outp = _dec.Pull();
                if (outp != null && outp.Length > 0) return outp;
                if (_dec.Done) { DownClosed = true; return null; }
                byte[] plain = await _down.ReadPlaintextAsync();
                if (plain == null) { DownClosed = true; return null; }
                _dec.Feed(plain);
            }
        }

        public async Task WriteUpAsync(byte[] payload)
        {
            await _upLock.WaitAsync();
            try
            {
                byte[] data = payload ?? new byte[0];
                if (!_headerSent)
                {
                    _headerSent = true;
                    byte[] combined = new byte[_vlessHeader.Length + data.Length];
                    System.Buffer.BlockCopy(_vlessHeader, 0, combined, 0, _vlessHeader.Length);
                    if (data.Length > 0)
                        System.Buffer.BlockCopy(data, 0, combined, _vlessHeader.Length, data.Length);
                    data = combined;
                }
                if (data.Length == 0) return;

                if (_packetUp)
                {
                    long seq = _seq++;
                    byte[] head = BuildUploadPostPacket(seq, data.Length);
                    byte[] rec = new byte[head.Length + data.Length];
                    System.Buffer.BlockCopy(head, 0, rec, 0, head.Length);
                    System.Buffer.BlockCopy(data, 0, rec, head.Length, data.Length);
                    await _up.WriteAppAsync(rec);
                    await DrainPostResponseAsync(); // синхронно ждём 200 (keep-alive синхронизация)
                }
                else
                {
                    if (!_upStreamStarted)
                    {
                        _upStreamStarted = true;
                        await _up.WriteAppAsync(BuildUploadPostStreamHead());
                    }
                    await _up.WriteAppAsync(WrapChunk(data));
                }
            }
            finally { _upLock.Release(); }
        }

        // Читает и отбрасывает ответ на packet-up POST (обычно 200 Content-Length: 0).
        private async Task DrainPostResponseAsync()
        {
            var buf = new List<byte>();
            int headEnd = -1;
            while (headEnd < 0)
            {
                byte[] plain = await _up.ReadPlaintextAsync();
                if (plain == null) throw new Exception("upload-соединение закрыто");
                buf.AddRange(plain);
                headEnd = IndexOfDoubleCrlf(buf);
            }

            string head = Encoding.ASCII.GetString(buf.ToArray(), 0, headEnd);
            string[] lines = head.Split(new[] { "\r\n" }, StringSplitOptions.None);
            string status = lines.Length > 0 ? lines[0] : "";
            if (_postRespCount++ == 0)
            {
                FileLog.Important($"[XHTTP packet-up] upload POST <<< {status}");
                if (!status.Contains(" 200"))
                    FileLog.Important("[XHTTP packet-up] СЕРВЕР НЕ ПРИНЯЛ upload (не 200). Проверьте режим на сервере.");
            }

            int contentLen = 0; bool chunked = false;
            for (int i = 1; i < lines.Length; i++)
            {
                int c = lines[i].IndexOf(':'); if (c < 0) continue;
                string k = lines[i].Substring(0, c).Trim().ToLowerInvariant();
                string v = lines[i].Substring(c + 1).Trim();
                if (k == "content-length") int.TryParse(v, out contentLen);
                if (k == "transfer-encoding" && v.ToLowerInvariant().Contains("chunked")) chunked = true;
            }

            int already = buf.Count - (headEnd + 4);
            if (chunked)
            {
                var cd = new ChunkedDecoder { Chunked = true };
                if (already > 0) cd.Feed(buf.GetRange(headEnd + 4, already).ToArray());
                while (!cd.Done)
                {
                    cd.Pull();
                    if (cd.Done) break;
                    byte[] p = await _up.ReadPlaintextAsync();
                    if (p == null) break;
                    cd.Feed(p);
                }
            }
            else
            {
                // Content-Length: 0 у Xray -> тела нет, already==0. На всякий случай дочитываем.
                int need = contentLen - already;
                while (need > 0)
                {
                    byte[] p = await _up.ReadPlaintextAsync();
                    if (p == null) break;
                    need -= p.Length; // допущение: сервер шлёт ровно тело (для CL:0 цикл не входит)
                }
            }
        }

        private byte[] BuildDownloadGet()
        {
            string pad = RandPad();
            var sb = new StringBuilder();
            sb.Append("GET ").Append(_basePath).Append('/').Append(_sessionId).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(_host).Append("\r\n");
            sb.Append("User-Agent: Go-http-client/1.1\r\n");
            sb.Append("Accept-Encoding: identity\r\n");
            sb.Append("Referer: https://").Append(_host).Append("/?x_padding=").Append(pad).Append("\r\n");
            sb.Append("Connection: keep-alive\r\n\r\n");
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        private byte[] BuildUploadPostPacket(long seq, int contentLen)
        {
            string pad = RandPad();
            var sb = new StringBuilder();
            sb.Append("POST ").Append(_basePath).Append('/').Append(_sessionId)
              .Append('/').Append(seq).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(_host).Append("\r\n");
            sb.Append("User-Agent: Go-http-client/1.1\r\n");
            sb.Append("Content-Type: application/octet-stream\r\n");
            sb.Append("Content-Length: ").Append(contentLen).Append("\r\n");
            sb.Append("Referer: https://").Append(_host).Append("/?x_padding=").Append(pad).Append("\r\n");
            sb.Append("Connection: keep-alive\r\n\r\n");
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        private byte[] BuildUploadPostStreamHead()
        {
            string pad = RandPad();
            var sb = new StringBuilder();
            sb.Append("POST ").Append(_basePath).Append('/').Append(_sessionId).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(_host).Append("\r\n");
            sb.Append("User-Agent: Go-http-client/1.1\r\n");
            sb.Append("Content-Type: application/octet-stream\r\n");
            sb.Append("Transfer-Encoding: chunked\r\n");
            sb.Append("Referer: https://").Append(_host).Append("/?x_padding=").Append(pad).Append("\r\n");
            sb.Append("Connection: keep-alive\r\n\r\n");
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        private string RandPad()
        {
            int min = _cfg.XPaddingMin > 0 ? _cfg.XPaddingMin : 100;
            int max = _cfg.XPaddingMax > min ? _cfg.XPaddingMax : 1000;
            return new string('X', _rnd.Next(min, max + 1));
        }

        private static byte[] WrapChunk(byte[] data)
        {
            byte[] head = Encoding.ASCII.GetBytes(data.Length.ToString("x") + "\r\n");
            byte[] outp = new byte[head.Length + data.Length + 2];
            System.Buffer.BlockCopy(head, 0, outp, 0, head.Length);
            System.Buffer.BlockCopy(data, 0, outp, head.Length, data.Length);
            outp[outp.Length - 2] = 0x0D;
            outp[outp.Length - 1] = 0x0A;
            return outp;
        }

        private static int IndexOfDoubleCrlf(List<byte> b)
        {
            for (int i = 0; i + 3 < b.Count; i++)
                if (b[i] == 0x0D && b[i + 1] == 0x0A && b[i + 2] == 0x0D && b[i + 3] == 0x0A)
                    return i;
            return -1;
        }

        public void Close()
        {
            try { _down?.Close(); } catch { }
            try { _up?.Close(); } catch { }
        }
    }
}