using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using System.Runtime.InteropServices.WindowsRuntime;

namespace VlessVpnTask
{
    // Общий контракт персонального (per-flow) соединения в DIRECT-режиме NatEngine.
    // Его реализуют VlessConnection и SsConnection, поэтому движок одинаково работает
    // и с VLESS, и с Shadowsocks/Outline.
    internal interface IDirectConn
    {
        void ConfigureDirectIp(byte[] ip, bool isIpv6, ushort port);
        void ConfigureDirectDomain(string domain, ushort port);
        Task<bool> StartAsync();
        Task WriteUnderlyingAsync(byte[] data);
        Task<byte[]> ReadPayloadAsync();
        void Close();
    }

    // Параметры AEAD-шифра Shadowsocks (SIP004/SIP007).
    internal sealed class SsCipherSpec
    {
        public string Name;
        public int KeyLen;
        public int SaltLen;   // для классического AEAD длина соли == длине ключа
        public bool IsChaCha;

        // Возвращает null для неподдерживаемого шифра (в т.ч. для устаревших
        // потоковых rc4/aes-cfb и для Shadowsocks-2022, где нужен BLAKE3).
        public static SsCipherSpec Resolve(string method)
        {
            string m = (method ?? "").Trim().ToLowerInvariant();
            switch (m)
            {
                case "chacha20-ietf-poly1305":
                case "chacha20-poly1305":
                    return new SsCipherSpec { Name = m, KeyLen = 32, SaltLen = 32, IsChaCha = true };
                case "aes-256-gcm":
                    return new SsCipherSpec { Name = m, KeyLen = 32, SaltLen = 32, IsChaCha = false };
                case "aes-192-gcm":
                    return new SsCipherSpec { Name = m, KeyLen = 24, SaltLen = 24, IsChaCha = false };
                case "aes-128-gcm":
                    return new SsCipherSpec { Name = m, KeyLen = 16, SaltLen = 16, IsChaCha = false };
                default:
                    return null;
            }
        }

        public static bool IsSupported(string method) { return Resolve(method) != null; }
    }

    internal static class SsCrypto
    {
        // Мастер-ключ Shadowsocks выводится из пароля по схеме OpenSSL EVP_BytesToKey
        // (MD5 без соли, одна итерация) — так делают все клиенты, менять нельзя.
        public static byte[] EvpBytesToKey(string password, int keyLen)
        {
            byte[] pw = Encoding.UTF8.GetBytes(password ?? "");
            var md5 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);

            byte[] key = new byte[keyLen];
            byte[] prev = new byte[0];
            int filled = 0;
            while (filled < keyLen)
            {
                byte[] input = new byte[prev.Length + pw.Length];
                System.Buffer.BlockCopy(prev, 0, input, 0, prev.Length);
                System.Buffer.BlockCopy(pw, 0, input, prev.Length, pw.Length);

                prev = md5.HashData(CryptographicBuffer.CreateFromByteArray(input)).ToArray();

                int take = Math.Min(prev.Length, keyLen - filled);
                System.Buffer.BlockCopy(prev, 0, key, filled, take);
                filled += take;
            }
            return key;
        }

        public static byte[] HmacSha1(byte[] key, byte[] data)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);
            var cryptoKey = provider.CreateKey(CryptographicBuffer.CreateFromByteArray(key));
            return CryptographicEngine.Sign(cryptoKey, CryptographicBuffer.CreateFromByteArray(data)).ToArray();
        }

        // HKDF-SHA1 — им Shadowsocks выводит сессионный подключ из мастер-ключа и соли.
        public static byte[] HkdfSha1(byte[] ikm, byte[] salt, byte[] info, int outLen)
        {
            byte[] prk = HmacSha1(salt, ikm);

            byte[] okm = new byte[outLen];
            byte[] t = new byte[0];
            int pos = 0;
            byte counter = 1;
            while (pos < outLen)
            {
                byte[] input = new byte[t.Length + info.Length + 1];
                System.Buffer.BlockCopy(t, 0, input, 0, t.Length);
                System.Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
                input[input.Length - 1] = counter;

                t = HmacSha1(prk, input);

                int take = Math.Min(t.Length, outLen - pos);
                System.Buffer.BlockCopy(t, 0, okm, pos, take);
                pos += take;
                counter++;
            }
            return okm;
        }
    }

    // Одно направление AEAD-потока: подключ + 12-байтовый little-endian счётчик nonce,
    // который увеличивается после КАЖДОЙ операции (отдельно для блока длины и для данных).
    internal sealed class SsAeadBox
    {
        private readonly SsCipherSpec _spec;
        private readonly byte[] _key;
        private readonly byte[] _nonce = new byte[12];
        private readonly CryptographicKey _aesKey;

        public SsAeadBox(SsCipherSpec spec, byte[] subkey)
        {
            _spec = spec;
            _key = subkey;
            if (!spec.IsChaCha)
            {
                var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);
                _aesKey = provider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(subkey));
            }
        }

        private void IncrementNonce()
        {
            for (int i = 0; i < _nonce.Length; i++)
            {
                if (++_nonce[i] != 0) break;
            }
        }

        public byte[] Seal(byte[] plain, int offset, int length)
        {
            byte[] slice = new byte[length];
            System.Buffer.BlockCopy(plain, offset, slice, 0, length);

            byte[] result;
            if (_spec.IsChaCha)
            {
                result = AwgCrypto.Seal(_key, _nonce, null, slice);
            }
            else
            {
                var enc = CryptographicEngine.EncryptAndAuthenticate(
                    _aesKey,
                    CryptographicBuffer.CreateFromByteArray(slice),
                    CryptographicBuffer.CreateFromByteArray(_nonce),
                    null);
                byte[] c = enc.EncryptedData.ToArray();
                byte[] tag = enc.AuthenticationTag.ToArray();
                result = new byte[c.Length + tag.Length];
                System.Buffer.BlockCopy(c, 0, result, 0, c.Length);
                System.Buffer.BlockCopy(tag, 0, result, c.Length, tag.Length);
            }
            IncrementNonce();
            return result;
        }

        // Возвращает null, если тег не сошёлся (порванная сессия / неверный пароль).
        public byte[] Open(byte[] cipherAndTag)
        {
            if (cipherAndTag == null || cipherAndTag.Length < 16) return null;

            byte[] plain;
            if (_spec.IsChaCha)
            {
                plain = AwgCrypto.Open(_key, _nonce, null, cipherAndTag);
            }
            else
            {
                int ctLen = cipherAndTag.Length - 16;
                byte[] c = new byte[ctLen];
                byte[] tag = new byte[16];
                System.Buffer.BlockCopy(cipherAndTag, 0, c, 0, ctLen);
                System.Buffer.BlockCopy(cipherAndTag, ctLen, tag, 0, 16);
                try
                {
                    plain = CryptographicEngine.DecryptAndAuthenticate(
                        _aesKey,
                        CryptographicBuffer.CreateFromByteArray(c),
                        CryptographicBuffer.CreateFromByteArray(_nonce),
                        CryptographicBuffer.CreateFromByteArray(tag),
                        null).ToArray();
                }
                catch { plain = null; }
            }

            if (plain == null) return null;
            IncrementNonce();
            return plain;
        }
    }

    // Клиент Shadowsocks AEAD (SIP004/SIP007) поверх обычного TCP.
    // Одно соединение = один flow: адрес назначения в SOCKS5-формате уходит первым
    // куском полезной нагрузки, дальше — прозрачный поток.
    internal sealed class SsConnection : IDirectConn
    {
        private const int MaxChunk = 0x3FFF;          // потолок длины куска в протоколе
        private static readonly byte[] SubkeyInfo = Encoding.ASCII.GetBytes("ss-subkey");

        private readonly VlessConfig _cfg;
        private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);

        private StreamSocket _socket;
        private DataReader _reader;
        private Stream _outStream;

        private SsCipherSpec _spec;
        private byte[] _masterKey;
        private byte[] _salt;
        private SsAeadBox _enc;
        private SsAeadBox _dec;
        private bool _headerSent;

        private byte _addrType;       // 0x01 IPv4, 0x03 домен, 0x04 IPv6 (нумерация SOCKS5)
        private byte[] _addrBytes;
        private string _domain;
        private ushort _port;

        public SsConnection(VlessConfig config)
        {
            _cfg = config;
        }

        public void ConfigureDirectIp(byte[] ip, bool isIpv6, ushort port)
        {
            _addrType = isIpv6 ? (byte)0x04 : (byte)0x01;
            _addrBytes = ip;
            _port = port;
        }

        public void ConfigureDirectDomain(string domain, ushort port)
        {
            _addrType = 0x03;
            _domain = domain;
            _port = port;
        }

        private byte[] BuildTargetAddress()
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(_addrType);
                if (_addrType == 0x03)
                {
                    byte[] d = Encoding.UTF8.GetBytes(_domain ?? "");
                    ms.WriteByte((byte)d.Length);
                    ms.Write(d, 0, d.Length);
                }
                else
                {
                    ms.Write(_addrBytes, 0, _addrBytes.Length);
                }
                ms.WriteByte((byte)(_port >> 8));
                ms.WriteByte((byte)(_port & 0xFF));
                return ms.ToArray();
            }
        }

        // Outline умеет маскировать начало потока: заданные байты подставляются
        // в НАЧАЛО соли (остаток остаётся случайным), сервер использует соль как есть.
        private byte[] GenerateSalt()
        {
            byte[] salt = Tls13Crypto.RandomBytes(_spec.SaltLen);
            byte[] prefix = DecodePrefix(_cfg.SsPrefix);
            if (prefix != null && prefix.Length > 0 && prefix.Length <= salt.Length)
                System.Buffer.BlockCopy(prefix, 0, salt, 0, prefix.Length);
            return salt;
        }

        // Приложение кладёт префикс в настройки в HEX (среди байтов бывает 0x00).
        private static byte[] DecodePrefix(string hex)
        {
            if (string.IsNullOrEmpty(hex) || (hex.Length % 2) != 0) return null;
            try
            {
                byte[] bytes = new byte[hex.Length / 2];
                for (int i = 0; i < bytes.Length; i++)
                    bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                return bytes;
            }
            catch { return null; }
        }

        public async Task<bool> StartAsync()
        {
            try
            {
                _spec = SsCipherSpec.Resolve(_cfg.Method);
                if (_spec == null)
                {
                    FileLog.Important($"[SS] Шифр '{_cfg.Method}' не поддерживается " +
                                      "(нужен aes-128/192/256-gcm или chacha20-ietf-poly1305).");
                    return false;
                }

                _masterKey = SsCrypto.EvpBytesToKey(_cfg.Password, _spec.KeyLen);
                _salt = GenerateSalt();
                _enc = new SsAeadBox(_spec, SsCrypto.HkdfSha1(_masterKey, _salt, SubkeyInfo, _spec.KeyLen));

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
                    connectOp = _socket.ConnectAsync(new HostName(targetHost), _cfg.Port.ToString(),
                                                     SocketProtectionLevel.PlainSocket);
                }

                var connectTask = connectOp.AsTask();
                if (await Task.WhenAny(connectTask, Task.Delay(8000)) != connectTask)
                {
                    try { connectOp.Cancel(); } catch { }
                    FileLog.W("[SS] Таймаут TCP-подключения к Shadowsocks-серверу (8с).");
                    Close();
                    return false;
                }
                await connectTask;

                _reader = new DataReader(_socket.InputStream);
                _reader.InputStreamOptions = InputStreamOptions.Partial;

                if (FileLog.Verbose)
                    FileLog.W($"[SS] TCP до {targetHost}:{_cfg.Port} поднят, шифр {_spec.Name}.");
                return true;
            }
            catch (Exception ex)
            {
                FileLog.W($"[SS] Ошибка подключения: {ex.Message}");
                Close();
                return false;
            }
        }

        public async Task WriteUnderlyingAsync(byte[] data)
        {
            byte[] payload = data ?? new byte[0];

            await _writeLock.WaitAsync();
            try
            {
                var ms = new MemoryStream();

                if (!_headerSent)
                {
                    _headerSent = true;
                    // Соль идёт открытым текстом, следом — первый зашифрованный кусок,
                    // который начинается с адреса назначения.
                    ms.Write(_salt, 0, _salt.Length);

                    byte[] target = BuildTargetAddress();
                    byte[] combined = new byte[target.Length + payload.Length];
                    System.Buffer.BlockCopy(target, 0, combined, 0, target.Length);
                    if (payload.Length > 0)
                        System.Buffer.BlockCopy(payload, 0, combined, target.Length, payload.Length);
                    payload = combined;
                }

                for (int off = 0; off < payload.Length; )
                {
                    int n = Math.Min(MaxChunk, payload.Length - off);

                    byte[] lenPlain = { (byte)(n >> 8), (byte)(n & 0xFF) };
                    byte[] lenSealed = _enc.Seal(lenPlain, 0, 2);
                    byte[] dataSealed = _enc.Seal(payload, off, n);

                    ms.Write(lenSealed, 0, lenSealed.Length);
                    ms.Write(dataSealed, 0, dataSealed.Length);
                    off += n;
                }

                byte[] all = ms.ToArray();
                if (all.Length == 0) return;

                if (_outStream == null) _outStream = _socket.OutputStream.AsStreamForWrite(81920);
                _outStream.Write(all, 0, all.Length);
                await _outStream.FlushAsync();

                if (FileLog.Verbose) FileLog.W($"[SS TX] {payload.Length}b -> {all.Length}b на проводе");
            }
            finally { _writeLock.Release(); }
        }

        private async Task<bool> LoadAtLeastAsync(uint count)
        {
            try
            {
                uint loaded = _reader.UnconsumedBufferLength;
                while (loaded < count)
                {
                    uint n = await _reader.LoadAsync(count - loaded);
                    if (n == 0) return false;
                    loaded += n;
                }
                return true;
            }
            catch { return false; }
        }

        public async Task<byte[]> ReadPayloadAsync()
        {
            try
            {
                // Первым делом сервер присылает свою соль — из неё выводим подключ приёма.
                if (_dec == null)
                {
                    if (!await LoadAtLeastAsync((uint)_spec.SaltLen)) return null;
                    byte[] salt = new byte[_spec.SaltLen];
                    _reader.ReadBytes(salt);
                    _dec = new SsAeadBox(_spec, SsCrypto.HkdfSha1(_masterKey, salt, SubkeyInfo, _spec.KeyLen));
                }

                if (!await LoadAtLeastAsync(2 + 16)) return null;
                byte[] lenBlock = new byte[2 + 16];
                _reader.ReadBytes(lenBlock);

                byte[] lenPlain = _dec.Open(lenBlock);
                if (lenPlain == null)
                {
                    FileLog.Important("[SS] Не сошёлся тег блока длины — неверный пароль/шифр или порванная сессия.");
                    return null;
                }

                int len = (lenPlain[0] << 8) | lenPlain[1];
                if (len <= 0 || len > MaxChunk)
                {
                    FileLog.Important($"[SS] Недопустимая длина куска: {len}.");
                    return null;
                }

                if (!await LoadAtLeastAsync((uint)(len + 16))) return null;
                byte[] dataBlock = new byte[len + 16];
                _reader.ReadBytes(dataBlock);

                byte[] plain = _dec.Open(dataBlock);
                if (plain == null)
                {
                    FileLog.Important("[SS] Не сошёлся тег блока данных.");
                    return null;
                }
                return plain;
            }
            catch (ObjectDisposedException) { return null; }
            catch (Exception ex)
            {
                if (FileLog.Verbose) FileLog.W($"[SS RX] {ex.Message}");
                return null;
            }
        }

        public void Close()
        {
            try { _reader?.Dispose(); } catch { }
            _reader = null;
            try { _outStream?.Dispose(); } catch { }
            _outStream = null;
            try { _socket?.Dispose(); } catch { }
            _socket = null;
        }
    }
}
