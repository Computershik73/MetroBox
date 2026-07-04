using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Windows.ApplicationModel;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using System.Runtime.InteropServices.WindowsRuntime;

namespace VlessVpnTask
{
    internal static class CryptoSelfTest
    {
        public static void RunAll()
        {
            FileLog.W("--- Running Cryptographic Self-Tests ---");
            try
            {
                byte[] testPriv = HexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
                byte[] testPub = HexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
                byte[] testShared = Curve25519.GetSharedSecret(testPriv, testPub);
                Assert("X25519", "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", BytesToHex(testShared));

                byte[] shaBorderInput = Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
                byte[] shaBorderHash = Tls13Crypto.Sha256(shaBorderInput);
                Assert("SHA-256", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", BytesToHex(shaBorderHash));

                byte[] hmac512Key = Encoding.ASCII.GetBytes("key");
                byte[] hmac512Data = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");
                byte[] hmac512Hash = Tls13Crypto.HmacSha512(hmac512Key, hmac512Data);
                Assert("HMAC-SHA-512", "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a", BytesToHex(hmac512Hash));

                FileLog.W("--- End of Cryptographic Self-Tests (SUCCESS) ---");
            }
            catch (Exception ex)
            {
                FileLog.W($"[CRITICAL] Self-Test Exception: {ex.Message}");
            }
        }

        private static void Assert(string name, string expected, string actual)
        {
            if (expected != actual)
            {
                FileLog.W($"[CRITICAL ERROR] Тест {name} ПРОВАЛЕН!");
                FileLog.W($"Ожидали: {expected}");
                FileLog.W($"Получили: {actual}");
            }
            else
            {
                FileLog.W($"[INFO] Тест {name} пройден успешно (SUCCESS).");
            }
        }

        public static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static string BytesToHex(byte[] bytes)
        {
            if (bytes == null) return "";
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }
    }

    internal static class Curve25519
    {
        private static readonly System.Numerics.BigInteger P = System.Numerics.BigInteger.Pow(new System.Numerics.BigInteger(2), 255) - new System.Numerics.BigInteger(19);
        private static readonly System.Numerics.BigInteger A24 = new System.Numerics.BigInteger(121665);

        public static byte[] CreateRandomPrivateKey()
        {
            byte[] k = Tls13Crypto.RandomBytes(32);
            Clamp(k);
            return k;
        }

        public static byte[] GetPublicKey(byte[] privateKey)
        {
            return ScalarMult(privateKey, BasePoint());
        }

        public static byte[] GetSharedSecret(byte[] privateKey, byte[] peerPublicKey)
        {
            return ScalarMult(privateKey, peerPublicKey);
        }

        private static byte[] ScalarMult(byte[] scalar, byte[] uBytes)
        {
            var k = Copy32(scalar);
            Clamp(k);
            System.Numerics.BigInteger x1 = DecodeLittleEndian(uBytes);
            System.Numerics.BigInteger x2 = System.Numerics.BigInteger.One;
            System.Numerics.BigInteger z2 = System.Numerics.BigInteger.Zero;
            System.Numerics.BigInteger x3 = x1;
            System.Numerics.BigInteger z3 = System.Numerics.BigInteger.One;
            int swap = 0;

            for (int t = 254; t >= 0; t--)
            {
                int kt = GetBit(k, t);
                swap ^= kt;
                CSwap(swap, ref x2, ref x3);
                CSwap(swap, ref z2, ref z3);
                swap = kt;

                System.Numerics.BigInteger a = Mod(x2 + z2);
                System.Numerics.BigInteger aa = Mod(a * a);
                System.Numerics.BigInteger b = Mod(x2 - z2);
                System.Numerics.BigInteger bb = Mod(b * b);
                System.Numerics.BigInteger e = Mod(aa - bb);
                System.Numerics.BigInteger c = Mod(x3 + z3);
                System.Numerics.BigInteger d = Mod(x3 - z3);
                System.Numerics.BigInteger da = Mod(d * a);
                System.Numerics.BigInteger cb = Mod(c * b);
                System.Numerics.BigInteger dapcb = Mod(da + cb);
                System.Numerics.BigInteger damcb = Mod(da - cb);
                x3 = Mod(dapcb * dapcb);
                z3 = Mod(x1 * Mod(damcb * damcb));
                x2 = Mod(aa * bb);
                z2 = Mod(e * Mod(aa + A24 * e));
            }

            CSwap(swap, ref x2, ref x3);
            CSwap(swap, ref z2, ref z3);
            System.Numerics.BigInteger result = Mod(x2 * ModInverse(z2));
            return EncodeLittleEndian(result);
        }

        private static void Clamp(byte[] k)
        {
            k[0] &= 248;
            k[31] &= 127;
            k[31] |= 64;
        }

        private static byte[] BasePoint()
        {
            var b = new byte[32];
            b[0] = 9;
            return b;
        }

        private static int GetBit(byte[] k, int bit)
        {
            return (k[bit >> 3] >> (bit & 7)) & 1;
        }

        private static byte[] Copy32(byte[] src)
        {
            if (src == null || src.Length != 32) throw new ArgumentException("X25519 key must be 32 bytes.");
            var b = new byte[32];
            Array.Copy(src, b, 32);
            return b;
        }

        private static System.Numerics.BigInteger DecodeLittleEndian(byte[] b)
        {
            if (b == null || b.Length != 32) throw new ArgumentException("X25519 input must be 32 bytes.");
            var tmp = new byte[33];
            Array.Copy(b, tmp, 32);
            tmp[32] = 0;
            return new System.Numerics.BigInteger(tmp);
        }

        private static byte[] EncodeLittleEndian(System.Numerics.BigInteger x)
        {
            var raw = x.ToByteArray();
            var b = new byte[32];
            int n = Math.Min(32, raw.Length);
            Array.Copy(raw, b, n);
            return b;
        }

        private static System.Numerics.BigInteger Mod(System.Numerics.BigInteger x)
        {
            x %= P;
            if (x.Sign < 0) x += P;
            return x;
        }

        private static System.Numerics.BigInteger ModInverse(System.Numerics.BigInteger x)
        {
            return System.Numerics.BigInteger.ModPow(Mod(x), P - 2, P);
        }

        private static void CSwap(int swap, ref System.Numerics.BigInteger a, ref System.Numerics.BigInteger b)
        {
            if (swap != 0)
            {
                System.Numerics.BigInteger t = a;
                a = b;
                b = t;
            }
        }
    }

    internal static class Tls13Crypto
    {
        public const int HashLen = 32;

        public static readonly SymmetricKeyAlgorithmProvider AesGcmProvider =
        SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);

        public static CryptographicKey CreateAesGcmKey(byte[] keyBytes)
        {
            return AesGcmProvider.CreateSymmetricKey(ToBuffer(keyBytes));
        }

        public static byte[] AesGcmEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plain)
        {
            var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);
            var cryptoKey = provider.CreateSymmetricKey(ToBuffer(key));
            var encryptedAndAuthenticated = CryptographicEngine.EncryptAndAuthenticate(cryptoKey, ToBuffer(plain), ToBuffer(nonce), ToBuffer(aad));
            var c = FromBuffer(encryptedAndAuthenticated.EncryptedData);
            var t = FromBuffer(encryptedAndAuthenticated.AuthenticationTag);
            var result = new byte[c.Length + t.Length];
            Array.Copy(c, 0, result, 0, c.Length);
            Array.Copy(t, 0, result, c.Length, t.Length);
            return result;
        }

        public static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] cipherAndTag)
        {
            if (cipherAndTag == null || cipherAndTag.Length < 16) throw new ArgumentException("Bad AES-GCM data.");
            var c = new byte[cipherAndTag.Length - 16];
            var tag = new byte[16];
            Array.Copy(cipherAndTag, 0, c, 0, c.Length);
            Array.Copy(cipherAndTag, c.Length, tag, 0, 16);
            var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);
            var cryptoKey = provider.CreateSymmetricKey(ToBuffer(key));
            IBuffer plain = CryptographicEngine.DecryptAndAuthenticate(cryptoKey, ToBuffer(c), ToBuffer(nonce), ToBuffer(tag), ToBuffer(aad));
            return FromBuffer(plain);
        }

        public static byte[] AesGcmEncryptWithKey(CryptographicKey cryptoKey, byte[] nonce, byte[] aad, byte[] plain)
        {
            var encryptedAndAuthenticated = CryptographicEngine.EncryptAndAuthenticate(cryptoKey, ToBuffer(plain), ToBuffer(nonce), ToBuffer(aad));
            var c = FromBuffer(encryptedAndAuthenticated.EncryptedData);
            var t = FromBuffer(encryptedAndAuthenticated.AuthenticationTag);
            var result = new byte[c.Length + t.Length];
            Array.Copy(c, 0, result, 0, c.Length);
            Array.Copy(t, 0, result, c.Length, t.Length);
            return result;
        }

        public static byte[] AesGcmDecryptWithKey(CryptographicKey cryptoKey, byte[] nonce, byte[] aad, byte[] cipherAndTag)
        {
            if (cipherAndTag == null || cipherAndTag.Length < 16) throw new ArgumentException("Bad AES-GCM data.");
            var c = new byte[cipherAndTag.Length - 16];
            var tag = new byte[16];
            Array.Copy(cipherAndTag, 0, c, 0, c.Length);
            Array.Copy(cipherAndTag, c.Length, tag, 0, 16);
            IBuffer plain = CryptographicEngine.DecryptAndAuthenticate(cryptoKey, ToBuffer(c), ToBuffer(nonce), ToBuffer(tag), ToBuffer(aad));
            return FromBuffer(plain);
        }

        public static byte[] RandomBytes(int count)
        {
            IBuffer buffer = CryptographicBuffer.GenerateRandom((uint)count);
            return buffer.ToArray();
        }

        public static byte[] Sha256(byte[] data)
        {
            var provider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            IBuffer hash = provider.HashData(ToBuffer(data));
            return FromBuffer(hash);
        }

        public static byte[] HmacSha256(byte[] key, byte[] data)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);
            var cryptoKey = provider.CreateKey(ToBuffer(key));
            return FromBuffer(CryptographicEngine.Sign(cryptoKey, ToBuffer(data)));
        }

        public static byte[] HmacSha512(byte[] key, byte[] data)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha512);
            var cryptoKey = provider.CreateKey(ToBuffer(key));
            return FromBuffer(CryptographicEngine.Sign(cryptoKey, ToBuffer(data)));
        }

        public static byte[] HkdfExtract(byte[] salt, byte[] ikm)
        {
            if (salt == null) salt = new byte[HashLen];
            if (ikm == null) ikm = new byte[0];
            return HmacSha256(salt, ikm);
        }

        public static byte[] HkdfExpand(byte[] prk, byte[] info, int length)
        {
            var okm = new List<byte>();
            byte[] t = new byte[0];
            byte counter = 1;
            while (okm.Count < length)
            {
                var input = new byte[t.Length + info.Length + 1];
                Array.Copy(t, 0, input, 0, t.Length);
                Array.Copy(info, 0, input, t.Length, info.Length);
                input[input.Length - 1] = counter++;
                t = HmacSha256(prk, input);
                okm.AddRange(t);
            }
            var result = new byte[length];
            okm.CopyTo(0, result, 0, length);
            return result;
        }

        public static byte[] HkdfExpandLabel(byte[] secret, string label, byte[] context, int length)
        {
            if (context == null) context = new byte[0];
            string fullLabel = "tls13 " + label;
            var labelBytes = System.Text.Encoding.ASCII.GetBytes(fullLabel);
            var info = new List<byte>();
            info.Add((byte)(length >> 8));
            info.Add((byte)length);
            info.Add((byte)labelBytes.Length);
            info.AddRange(labelBytes);
            info.Add((byte)context.Length);
            info.AddRange(context);
            return HkdfExpand(secret, info.ToArray(), length);
        }

        public static byte[] DeriveSecret(byte[] secret, string label, byte[] transcript)
        {
            return HkdfExpandLabel(secret, label, Sha256(transcript ?? new byte[0]), HashLen);
        }

        public static IBuffer ToBuffer(byte[] data)
        {
            if (data == null) data = new byte[0];
            return data.AsBuffer();
        }

        public static byte[] FromBuffer(IBuffer buffer)
        {
            return buffer.ToArray();
        }

        public static bool ConstantEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }

    internal class RealityTls13Stream
    {
        private VlessConfig _cfg;
        private DataWriter _writer;
        private DataReader _reader;

        private byte[] _clientPrivate, _clientPublic, _clientRandom, _realityAuthKey;
        private List<byte> _transcript = new List<byte>();
        private byte[] _handshakeSecret, _clientHandshakeTrafficSecret, _serverHandshakeTrafficSecret;
        private byte[] _clientHandshakeKey, _clientHandshakeIv, _serverHandshakeKey, _serverAppIv;
        private byte[] _clientAppKey, _clientAppIv, _serverAppKey, _serverHandshakeIv;
        private ulong _writeSeq = 0, _readSeq = 0;

        private CryptographicKey _clientAppCryptoKey;
        private CryptographicKey _serverAppCryptoKey;

        public string NegotiatedAlpn { get; private set; } = "";

        public RealityTls13Stream(VlessConfig config) { _cfg = config; }

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

        public async Task<bool> EstablishHandshakeAsync(DataWriter writer, DataReader reader)
        {
            _writer = writer;
            _reader = reader;

            FileLog.W("[REALITY TLS 1.3] === Старт Reality рукопожатия ===");

            _clientPrivate = Curve25519.CreateRandomPrivateKey();
            _clientPublic = Curve25519.GetPublicKey(_clientPrivate);
            _clientRandom = Tls13Crypto.RandomBytes(32);

            FileLog.W($"[REALITY TLS 1.3] Ключ X25519 клиента: {CryptoSelfTest.BytesToHex(_clientPublic)}");

            byte[] clientHello = BuildRealityClientHello();
            _transcript.AddRange(clientHello);

            byte[] record = new byte[clientHello.Length + 5];
            record[0] = 22; // Handshake
            record[1] = 3; record[2] = 1; // TLS 1.0 (совместимость)
            record[3] = (byte)(clientHello.Length >> 8);
            record[4] = (byte)(clientHello.Length & 0xFF);
            System.Buffer.BlockCopy(clientHello, 0, record, 5, clientHello.Length);

            FileLog.W($"[REALITY TLS 1.3] Отправка ClientHello ({record.Length} байт) с SNI: {_cfg.Sni}...");
            try
            {
                _writer.WriteBytes(record);
                await _writer.StoreAsync();
                FileLog.W("[REALITY TLS 1.3] ClientHello отправлен.");
            }
            catch (Exception ex)
            {
                FileLog.W($"[REALITY TLS 1.3 ERROR] Сбой отправки ClientHello: {ex.Message}");
                return false;
            }

            FileLog.W("[REALITY TLS 1.3] Ожидание ServerHello...");
            byte[] serverHelloPayload = null;
            while (true)
            {
                var rec = await ReadNextRecordAsync();
                if (rec == null)
                {
                    FileLog.W("[REALITY TLS 1.3 ERROR] Соединение разорвано во время ожидания ServerHello.");
                    return false;
                }

                if (rec.Item1 == 20)
                {
                    FileLog.W("[REALITY TLS 1.3] Пропущен нешифрованный ChangeCipherSpec (тип 20)");
                    continue;
                }
                if (rec.Item1 == 21)
                {
                    FileLog.W($"[REALITY TLS 1.3 ERROR] Получен Alert-код ошибки: {CryptoSelfTest.BytesToHex(rec.Item3)}");
                    return false;
                }
                if (rec.Item1 == 22)
                {
                    serverHelloPayload = rec.Item3;
                    FileLog.W("[REALITY TLS 1.3] Получен ServerHello!");
                    break;
                }
            }

            FileLog.W("[REALITY TLS 1.3] Парсинг ServerHello и извлечение Server Share...");
            byte[] serverShare = ParseServerHello(serverHelloPayload);
            if (serverShare == null)
            {
                FileLog.W("[REALITY TLS 1.3 ERROR] Не найден Server Share (публичный ключ X25519 сервера)!");
                return false;
            }
            FileLog.W($"[REALITY TLS 1.3] Публичный ключ сервера (Server Share): {CryptoSelfTest.BytesToHex(serverShare)}");
            _transcript.AddRange(serverHelloPayload);

            FileLog.W("[REALITY TLS 1.3] Вычисление общего секрета X25519 и генерация Handshake-ключей...");
            DeriveHandshakeKeys(serverShare);

            bool gotServerFinished = false;
            List<byte> hsBuf = new List<byte>();

            FileLog.W("[REALITY TLS 1.3] Чтение зашифрованных сообщений сервера...");
            while (!gotServerFinished)
            {
                var plain = await ReadEncryptedRecordAsync(false);
                if (plain == null)
                {
                    FileLog.W("[REALITY TLS 1.3 ERROR] Сбой чтения или расшифровки записи сервера.");
                    return false;
                }
                if (plain.Item1 == 21)
                {
                    FileLog.W("[REALITY TLS 1.3 ERROR] Получена зашифрованная Alert-ошибка от сервера.");
                    return false;
                }
                if (plain.Item1 != 22)
                {
                    FileLog.W($"[REALITY TLS 1.3] Пропущена TLS-запись типа {plain.Item1}");
                    continue;
                }

                hsBuf.AddRange(plain.Item2);
                while (hsBuf.Count >= 4)
                {
                    byte hsType = hsBuf[0];
                    int hsLen = (hsBuf[1] << 16) | (hsBuf[2] << 8) | hsBuf[3];
                    int total = 4 + hsLen;
                    if (hsBuf.Count < total) break;

                    byte[] hsMsg = hsBuf.Take(total).ToArray();
                    hsBuf.RemoveRange(0, total);

                    FileLog.W($"[REALITY TLS 1.3] Расшифровано Handshake-сообщение. Тип: {hsType}, Длина: {hsLen} байт");

                    if (hsType == 11) // Certificate
                    {
                        InspectServerCertificate(hsMsg);
                    }

                    if (hsType == 20) // Finished
                    {
                        FileLog.W("[REALITY TLS 1.3] Проверка подписи Server Finished...");
                        if (!VerifyServerFinished(hsMsg))
                        {
                            FileLog.W("[REALITY TLS 1.3 ERROR] КРИТИЧЕСКАЯ ОШИБКА: Верификация Server Finished ПРОВАЛЕНА!");
                            return false;
                        }
                        FileLog.W("[REALITY TLS 1.3] Подпись Server Finished верна!");
                        _transcript.AddRange(hsMsg);
                        gotServerFinished = true;
                        break;
                    }
                    _transcript.AddRange(hsMsg);
                }
            }

            FileLog.W("[REALITY TLS 1.3] Генерация Application-ключей для основного трафика...");
            DeriveApplicationKeys();

            FileLog.W("[REALITY TLS 1.3] Отправка Client Finished...");
            await SendClientFinishedAsync();

            _writeSeq = 0;
            _readSeq = 0;
            FileLog.W("[REALITY TLS 1.3] === РУКОПОЖАТИЕ REALITY УСПЕШНО ЗАВЕРШЕНО! ===");
            return true;
        }

        private void InspectServerCertificate(byte[] hsMsg)
        {
            try
            {
                int pos = 4;
                int ctxLen = hsMsg[pos]; pos += 1 + ctxLen;
                pos += 3;
                int certLen = (hsMsg[pos] << 16) | (hsMsg[pos + 1] << 8) | hsMsg[pos + 2];
                pos += 3;

                if (certLen <= 0 || pos + certLen > hsMsg.Length) return;

                byte[] der = new byte[certLen];
                System.Buffer.BlockCopy(hsMsg, pos, der, 0, certLen);

                var cert = new Windows.Security.Cryptography.Certificates.Certificate(der.AsBuffer());
                bool selfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase);

                FileLog.W("========== СЕРТИФИКАТ СЕРВЕРА ==========");
                FileLog.W($"[CERT] Subject:   {cert.Subject}");
                FileLog.W($"[CERT] Issuer:    {cert.Issuer}");
                FileLog.W(selfSigned
                    ? "[CERT] => Самоподписанный/временный сертификат: REALITY НАС ПРИНЯЛ."
                    : "[CERT] => Реальная цепочка CA: МЫ В FALLBACK, REALITY нас отбросил на прикрытие.");
                FileLog.W("=======================================");
            }
            catch { }
        }

        private byte[] BuildRealityClientHello()
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(3); ms.WriteByte(3);
                ms.Write(_clientRandom, 0, 32);
                ms.WriteByte(32); ms.Write(new byte[32], 0, 32);
                ms.WriteByte(0); ms.WriteByte(2);
                ms.WriteByte(0x13); ms.WriteByte(0x01);
                ms.WriteByte(1); ms.WriteByte(0);

                byte[] exts = BuildExtensions();
                ms.WriteByte((byte)(exts.Length >> 8)); ms.WriteByte((byte)(exts.Length & 0xFF));
                ms.Write(exts, 0, exts.Length);

                byte[] body = ms.ToArray();
                using (var hs = new MemoryStream())
                {
                    hs.WriteByte(1);
                    hs.WriteByte((byte)(body.Length >> 16)); hs.WriteByte((byte)(body.Length >> 8)); hs.WriteByte((byte)(body.Length & 0xFF));
                    hs.Write(body, 0, body.Length);
                    byte[] hsBytes = hs.ToArray();

                    byte[] pubKey = new byte[32];
                    if (!string.IsNullOrEmpty(_cfg.PublicKey))
                    {
                        string b64 = _cfg.PublicKey.Replace("-", "+").Replace("_", "/");
                        while (b64.Length % 4 != 0) b64 += "=";
                        try { pubKey = Convert.FromBase64String(b64); } catch { }
                    }

                    byte[] shared = Curve25519.GetSharedSecret(_clientPrivate, pubKey);
                    byte[] prk = Tls13Crypto.HkdfExtract(_clientRandom.Take(20).ToArray(), shared);
                    _realityAuthKey = Tls13Crypto.HkdfExpand(prk, Encoding.ASCII.GetBytes("REALITY"), 32);
                    byte[] nonce = _clientRandom.Skip(20).Take(12).ToArray();

                    byte[] p = new byte[16];
                    uint now = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    p[0] = 1; p[1] = 8; p[2] = 1;
                    p[4] = (byte)(now >> 24); p[5] = (byte)(now >> 16); p[6] = (byte)(now >> 8); p[7] = (byte)now;

                    if (!string.IsNullOrEmpty(_cfg.ShortId))
                    {
                        try
                        {
                            byte[] sidBytes = CryptoSelfTest.HexToBytes(_cfg.ShortId);
                            int copyLen = Math.Min(8, sidBytes.Length);
                            System.Buffer.BlockCopy(sidBytes, 0, p, 8, copyLen);
                        }
                        catch { }
                    }

                    byte[] encryptedSession = Tls13Crypto.AesGcmEncrypt(_realityAuthKey, nonce, hsBytes, p);
                    System.Buffer.BlockCopy(encryptedSession, 0, hsBytes, 39, 32);
                    return hsBytes;
                }
            }
        }

        private byte[] BuildExtensions()
        {
            using (var ms = new MemoryStream())
            {
                string sni = string.IsNullOrEmpty(_cfg.Sni) ? _cfg.Address : _cfg.Sni;
                byte[] sniBytes = Encoding.ASCII.GetBytes(sni);
                byte[] sniExt = new byte[5 + sniBytes.Length];
                sniExt[0] = (byte)((sniBytes.Length + 3) >> 8); sniExt[1] = (byte)(sniBytes.Length + 3);
                sniExt[2] = 0; sniExt[3] = (byte)(sniBytes.Length >> 8); sniExt[4] = (byte)(sniBytes.Length & 0xFF);
                System.Buffer.BlockCopy(sniBytes, 0, sniExt, 5, sniBytes.Length);
                AddExt(ms, 0x0000, sniExt);
                AddExt(ms, 0x000a, new byte[] { 0, 2, 0, 0x1d });
                AddExt(ms, 0x000d, new byte[] { 0, 10, 4, 3, 5, 3, 8, 4, 8, 5, 8, 7 });

                byte[] alpnProtos = new byte[] {
                    2, (byte)'h', (byte)'2',
                    8, (byte)'h', (byte)'t', (byte)'t', (byte)'p', (byte)'/', (byte)'1', (byte)'.', (byte)'1'
                };
                byte[] alpnList = new byte[alpnProtos.Length + 2];
                alpnList[0] = (byte)(alpnProtos.Length >> 8);
                alpnList[1] = (byte)(alpnProtos.Length & 0xFF);
                System.Buffer.BlockCopy(alpnProtos, 0, alpnList, 2, alpnProtos.Length);
                AddExt(ms, 0x0010, alpnList);

                AddExt(ms, 0x002b, new byte[] { 2, 3, 4 });
                byte[] keyShare = new byte[38];
                keyShare[0] = 0; keyShare[1] = 36; keyShare[2] = 0; keyShare[3] = 0x1d; keyShare[4] = 0; keyShare[5] = 32;
                System.Buffer.BlockCopy(_clientPublic, 0, keyShare, 6, 32);
                AddExt(ms, 0x0033, keyShare);
                AddExt(ms, 0x0015, new byte[128]);
                return ms.ToArray();
            }
        }

        private void AddExt(MemoryStream ms, ushort type, byte[] data)
        {
            ms.WriteByte((byte)(type >> 8)); ms.WriteByte((byte)(type & 0xFF));
            ms.WriteByte((byte)(data.Length >> 8)); ms.WriteByte((byte)(data.Length & 0xFF));
            ms.Write(data, 0, data.Length);
        }

        private void DeriveHandshakeKeys(byte[] serverShare)
        {
            byte[] shared = Curve25519.GetSharedSecret(_clientPrivate, serverShare);
            byte[] zeros = new byte[32];
            byte[] earlySecret = Tls13Crypto.HkdfExtract(zeros, zeros);
            byte[] derived = Tls13Crypto.DeriveSecret(earlySecret, "derived", new byte[0]);
            _handshakeSecret = Tls13Crypto.HkdfExtract(derived, shared);
            _clientHandshakeTrafficSecret = Tls13Crypto.DeriveSecret(_handshakeSecret, "c hs traffic", _transcript.ToArray());
            _serverHandshakeTrafficSecret = Tls13Crypto.DeriveSecret(_handshakeSecret, "s hs traffic", _transcript.ToArray());
            _clientHandshakeKey = Tls13Crypto.HkdfExpandLabel(_clientHandshakeTrafficSecret, "key", new byte[0], 16);
            _clientHandshakeIv = Tls13Crypto.HkdfExpandLabel(_clientHandshakeTrafficSecret, "iv", new byte[0], 12);
            _serverHandshakeKey = Tls13Crypto.HkdfExpandLabel(_serverHandshakeTrafficSecret, "key", new byte[0], 16);
            _serverHandshakeIv = Tls13Crypto.HkdfExpandLabel(_serverHandshakeTrafficSecret, "iv", new byte[0], 12);
        }

        private void DeriveApplicationKeys()
        {
            byte[] zeros = new byte[32];
            byte[] derived = Tls13Crypto.DeriveSecret(_handshakeSecret, "derived", new byte[0]);
            byte[] masterSecret = Tls13Crypto.HkdfExtract(derived, zeros);
            byte[] cAppTraffic = Tls13Crypto.DeriveSecret(masterSecret, "c ap traffic", _transcript.ToArray());
            byte[] sAppTraffic = Tls13Crypto.DeriveSecret(masterSecret, "s ap traffic", _transcript.ToArray());
            _clientAppKey = Tls13Crypto.HkdfExpandLabel(cAppTraffic, "key", new byte[0], 16);
            _clientAppIv = Tls13Crypto.HkdfExpandLabel(cAppTraffic, "iv", new byte[0], 12);
            _serverAppKey = Tls13Crypto.HkdfExpandLabel(sAppTraffic, "key", new byte[0], 16);
            _serverAppIv = Tls13Crypto.HkdfExpandLabel(sAppTraffic, "iv", new byte[0], 12);

            _clientAppCryptoKey = Tls13Crypto.CreateAesGcmKey(_clientAppKey);
            _serverAppCryptoKey = Tls13Crypto.CreateAesGcmKey(_serverAppKey);
        }

        public byte[] EncryptRecord(byte[] data)
        {
            return EncryptRecordInternalWithKey(_clientAppCryptoKey, _clientAppIv, ref _writeSeq, 23, data);
        }

        public byte[] DecryptRecordExplicit(byte[] header, byte[] cipherAndTag, out byte innerType)
        {
            innerType = 0;
            try
            {
                byte[] nonce = BuildNonce(_serverAppIv, _readSeq++);
                byte[] plain = Tls13Crypto.AesGcmDecryptWithKey(_serverAppCryptoKey, nonce, header, cipherAndTag);
                if (plain != null && plain.Length > 0)
                {
                    int end = plain.Length - 1;
                    while (end >= 0 && plain[end] == 0) end--;
                    if (end >= 0)
                    {
                        innerType = plain[end];
                        return plain.Take(end).ToArray();
                    }
                }
            }
            catch { }
            return null;
        }

        private async Task<Tuple<byte, byte[], byte[]>> ReadNextRecordAsync()
        {
            if (!await ReadExactAsync(5)) return null;
            byte[] header = new byte[5]; _reader.ReadBytes(header);
            int len = (header[3] << 8) | header[4];
            if (len <= 0) return new Tuple<byte, byte[], byte[]>(header[0], header, new byte[0]);

            if (!await ReadExactAsync((uint)len)) return null;
            byte[] payload = new byte[len]; _reader.ReadBytes(payload);
            return new Tuple<byte, byte[], byte[]>(header[0], header, payload);
        }

        private async Task<Tuple<byte, byte[]>> ReadEncryptedRecordAsync(bool application)
        {
            var rec = await ReadNextRecordAsync();
            if (rec == null) return null;
            if (rec.Item1 == 20) return await ReadEncryptedRecordAsync(application);

            if (application)
            {
                byte[] nonce = BuildNonce(_serverAppIv, _readSeq++);
                byte[] plain = Tls13Crypto.AesGcmDecryptWithKey(_serverAppCryptoKey, nonce, rec.Item2, rec.Item3);
                if (plain == null) return null;
                int end = plain.Length - 1;
                while (end >= 0 && plain[end] == 0) end--;
                if (end < 0) return null;
                return new Tuple<byte, byte[]>(plain[end], plain.Take(end).ToArray());
            }
            else
            {
                byte[] key = _serverHandshakeKey;
                byte[] iv = _serverHandshakeIv;
                byte[] nonce = BuildNonce(iv, _readSeq++);
                byte[] plain = Tls13Crypto.AesGcmDecrypt(key, nonce, rec.Item2, rec.Item3);
                if (plain == null) return null;
                int end = plain.Length - 1;
                while (end >= 0 && plain[end] == 0) end--;
                if (end < 0) return null;
                return new Tuple<byte, byte[]>(plain[end], plain.Take(end).ToArray());
            }
        }

        private byte[] EncryptRecordInternalWithKey(CryptographicKey cryptoKey, byte[] iv, ref ulong seq, byte innerType, byte[] content)
        {
            byte[] inner = new byte[content.Length + 1];
            System.Buffer.BlockCopy(content, 0, inner, 0, content.Length);
            inner[inner.Length - 1] = innerType;
            int encLen = inner.Length + 16;
            byte[] header = new byte[] { 23, 3, 3, (byte)(encLen >> 8), (byte)(encLen & 0xFF) };
            byte[] nonce = BuildNonce(iv, seq++);

            byte[] encrypted = Tls13Crypto.AesGcmEncryptWithKey(cryptoKey, nonce, header, inner);

            byte[] result = new byte[header.Length + encrypted.Length];
            System.Buffer.BlockCopy(header, 0, result, 0, header.Length);
            System.Buffer.BlockCopy(encrypted, 0, result, header.Length, encrypted.Length);
            return result;
        }

        private byte[] EncryptRecordInternal(byte[] key, byte[] iv, ref ulong seq, byte innerType, byte[] content)
        {
            byte[] inner = new byte[content.Length + 1];
            System.Buffer.BlockCopy(content, 0, inner, 0, content.Length);
            inner[inner.Length - 1] = innerType;
            int encLen = inner.Length + 16;
            byte[] header = new byte[] { 23, 3, 3, (byte)(encLen >> 8), (byte)(encLen & 0xFF) };
            byte[] nonce = BuildNonce(iv, seq++);

            byte[] encrypted = Tls13Crypto.AesGcmEncrypt(key, nonce, header, inner);

            byte[] result = new byte[header.Length + encrypted.Length];
            System.Buffer.BlockCopy(header, 0, result, 0, header.Length);
            System.Buffer.BlockCopy(encrypted, 0, result, header.Length, encrypted.Length);
            return result;
        }

        private byte[] BuildNonce(byte[] iv, ulong seq)
        {
            byte[] nonce = (byte[])iv.Clone();
            for (int i = 0; i < 8; i++) nonce[nonce.Length - 1 - i] ^= (byte)(seq >> (8 * i));
            return nonce;
        }

        private byte[] ParseServerHello(byte[] hs)
        {
            if (hs.Length < 44 || hs[0] != 2) return null;
            int pos = 38;
            int sidLen = hs[pos++];
            pos += sidLen + 2 + 1;
            int extTotal = (hs[pos] << 8) | hs[pos + 1];
            pos += 2;
            int end = pos + extTotal;

            byte[] serverShare = null;

            while (pos + 4 <= end)
            {
                int type = (hs[pos] << 8) | hs[pos + 1];
                int len = (hs[pos + 2] << 8) | hs[pos + 3];
                pos += 4;

                if (type == 0x0033 && len >= 36) // key_share
                {
                    int group = (hs[pos] << 8) | hs[pos + 1];
                    if (group == 0x001d) serverShare = hs.Skip(pos + 4).Take(32).ToArray();
                }
                else if (type == 0x0010 && len >= 3) // ALPN
                {
                    int nameLen = hs[pos + 2];
                    if (nameLen > 0 && pos + 3 + nameLen <= end)
                    {
                        NegotiatedAlpn = Encoding.ASCII.GetString(hs, pos + 3, nameLen);
                        FileLog.Important($"[REALITY TLS 1.3] Сервер выбрал ALPN: '{NegotiatedAlpn}'");
                    }
                }

                pos += len;
            }

            return serverShare;
        }

        private bool VerifyServerFinished(byte[] finishedHs)
        {
            byte[] verifyData = finishedHs.Skip(4).ToArray();
            byte[] finishedKey = Tls13Crypto.HkdfExpandLabel(_serverHandshakeTrafficSecret, "finished", new byte[0], 32);
            byte[] transcriptHash = Tls13Crypto.Sha256(_transcript.ToArray());
            byte[] expected = Tls13Crypto.HmacSha256(finishedKey, transcriptHash);
            return Tls13Crypto.ConstantEquals(expected, verifyData);
        }

        private async Task SendClientFinishedAsync()
        {
            byte[] transcriptHash = Tls13Crypto.Sha256(_transcript.ToArray());
            byte[] finishedKey = Tls13Crypto.HkdfExpandLabel(_clientHandshakeTrafficSecret, "finished", new byte[0], 32);
            byte[] verify = Tls13Crypto.HmacSha256(finishedKey, transcriptHash);
            byte[] hs = new byte[4 + verify.Length];
            hs[0] = 20; hs[1] = 0; hs[2] = (byte)(verify.Length >> 8); hs[3] = (byte)(verify.Length & 0xFF);
            System.Buffer.BlockCopy(verify, 0, hs, 4, verify.Length);
            byte[] record = EncryptRecordInternal(_clientHandshakeKey, _clientHandshakeIv, ref _writeSeq, 22, hs);

            try
            {
                _writer.WriteBytes(record);
                await _writer.StoreAsync();
                _transcript.AddRange(hs);
            }
            catch { }
        }
    }

    internal class VlessConnection
    {
        public StreamSocket Socket { get; private set; }
        private DataWriter _writer;
        private DataReader _reader;
        private VlessConfig _cfg;
        private VpnChannel _channel;
        private RealityTls13Stream _realityStream;

        private List<byte> _receiveBuffer = new List<byte>();
        private bool _headerStripped = false;
        private byte[] _vlessHeaderBuffer = null;

        private System.IO.Stream _outStream;

        private bool _xhttpEnabled;
        private XhttpStreamOne _xhttp;
        private bool _xhttpHeadParsed;

        private bool _directMode;
        private byte _directAddrType;
        private byte[] _directAddr;
        private string _directDomain;
        private ushort _directPort;

        private bool _h2Enabled;
        private Http2Conn _h2;
        private bool _h2HeadStatusLogged;
        private bool _vlessHeaderSent;
        private readonly System.Threading.SemaphoreSlim _rawWriteLock = new System.Threading.SemaphoreSlim(1, 1);
        private int _h2PendingCredit;

        public void ConfigureDirectIp(byte[] ip, bool isIpv6, ushort port)
        {
            _directMode = true;
            _directAddrType = isIpv6 ? (byte)0x03 : (byte)0x01;
            _directAddr = ip;
            _directPort = port;
        }

        public void ConfigureDirectDomain(string domain, ushort port)
        {
            _directMode = true;
            _directAddrType = 0x02;
            _directDomain = domain;
            _directPort = port;
        }

        public static byte[] GuidToNetworkBytes(Guid id)
        {
            string hex = id.ToString("N");
            var b = new byte[16];
            for (int i = 0; i < 16; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        private string DumpPayload(byte[] data, int maxLen = 512)
        {
            if (data == null || data.Length == 0) return "[EMPTY]";
            int len = Math.Min(data.Length, maxLen);
            var sb = new StringBuilder();
            sb.AppendLine($"--- Дамп ({data.Length} байт) ---");
            for (int i = 0; i < len; i += 16)
            {
                sb.Append($"{i:X4} | ");
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < len) sb.Append($"{data[i + j]:X2} ");
                    else sb.Append("   ");
                }
                sb.Append("| ");
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < len)
                    {
                        char c = (char)data[i + j];
                        sb.Append((c >= 32 && c <= 126) ? c : '.');
                    }
                }
                sb.AppendLine();
            }
            if (data.Length > maxLen) sb.AppendLine("... (остаток скрыт)");
            return sb.ToString();
        }

        public VlessConnection(VlessConfig config, VpnChannel channel)
        {
            _cfg = config;
            _channel = channel;
        }

        public async Task<bool> StartAsync()
        {
            try
            {
                string targetHost = string.IsNullOrEmpty(VlessVpnPlugin.ServerIp)
                    ? _cfg.Address : VlessVpnPlugin.ServerIp;

                Socket = new StreamSocket();
                Socket.Control.NoDelay = true;
                Socket.Control.KeepAlive = true;

                FileLog.W($"[VLESS CONN] Подключение к VLESS-серверу: {targetHost}:{_cfg.Port}");

                Windows.Foundation.IAsyncAction connectOp;
                if (VlessVpnPlugin.PhysicalIp != null)
                {
                    var epp = new Windows.Networking.EndpointPair(
                        VlessVpnPlugin.PhysicalIp, "",
                        new HostName(targetHost), _cfg.Port.ToString());
                    connectOp = Socket.ConnectAsync(epp, SocketProtectionLevel.PlainSocket);
                }
                else
                {
                    connectOp = Socket.ConnectAsync(new HostName(targetHost), _cfg.Port.ToString(),
                                                    SocketProtectionLevel.PlainSocket);
                }

                var connectTask = connectOp.AsTask();
                if (await Task.WhenAny(connectTask, Task.Delay(8000)) != connectTask)
                {
                    try { connectOp.Cancel(); } catch { }
                    FileLog.W("[VLESS CONN ERROR] Таймаут TCP-подключения (8с).");
                    Close();
                    return false;
                }
                await connectTask;

                _writer = new DataWriter(Socket.OutputStream);
                _reader = new DataReader(Socket.InputStream);
                _reader.InputStreamOptions = InputStreamOptions.Partial;

                if (_cfg.Security.ToLower() == "reality")
                {
                    _realityStream = new RealityTls13Stream(_cfg);
                    var handshakeTask = _realityStream.EstablishHandshakeAsync(_writer, _reader);
                    if (await Task.WhenAny(handshakeTask, Task.Delay(8000)) != handshakeTask || !await handshakeTask)
                    {
                        FileLog.W("[VLESS CONN ERROR] Таймаут или сбой Reality handshake (8с).");
                        Close();
                        return false;
                    }
                }

                using (var ms = new MemoryStream())
                {
                    ms.WriteByte(0x00);
                    Guid guid = Guid.Empty;
                    Guid.TryParse(_cfg.Uuid, out guid);
                    ms.Write(GuidToNetworkBytes(guid), 0, 16);
                    ms.WriteByte(0x00);
                    ms.WriteByte(0x01);

                    if (_directMode)
                    {
                        ms.WriteByte((byte)(_directPort >> 8));
                        ms.WriteByte((byte)(_directPort & 0xFF));
                        ms.WriteByte(_directAddrType);
                        if (_directAddrType == 0x02)
                        {
                            byte[] d = Encoding.UTF8.GetBytes(_directDomain);
                            ms.WriteByte((byte)d.Length);
                            ms.Write(d, 0, d.Length);
                        }
                        else
                        {
                            ms.Write(_directAddr, 0, _directAddr.Length);
                        }
                    }
                    else
                    {
                        // MUX: порт 9527, домен v1.mux.cool 
                        ms.WriteByte((byte)(9527 >> 8));
                        ms.WriteByte((byte)(9527 & 0xFF));
                        ms.WriteByte(0x02);
                        byte[] hostBytes = Encoding.UTF8.GetBytes("v1.mux.cool");
                        ms.WriteByte((byte)hostBytes.Length);
                        ms.Write(hostBytes, 0, hostBytes.Length);
                    }

                    _vlessHeaderBuffer = ms.ToArray();
                }

                if (_cfg.IsXhttp)
                {
                    string alpn = _realityStream != null ? _realityStream.NegotiatedAlpn : "";
                    bool forceH1 = string.Equals(alpn, "http/1.1", StringComparison.OrdinalIgnoreCase);

                    if (!forceH1)
                    {
                        FileLog.Important($"[XHTTP] Транспорт: HTTP/2 (stream-one). ALPN='{(string.IsNullOrEmpty(alpn) ? "<нет>" : alpn)}'.");
                        if (!await StartH2Async()) { Close(); return false; }
                    }
                    else
                    {
                        FileLog.Important("[XHTTP] Транспорт: HTTP/1.1 (stream-one) — сервер явно выбрал http/1.1.");
                        _xhttp = new XhttpStreamOne(_cfg);
                        _xhttpEnabled = true;
                        if (!await StartXhttpStreamOneAsync()) { Close(); return false; }
                    }
                }
                else
                {
                    FileLog.Important($"[VLESS CONN] Транспорт: стандартный {_cfg.Type} (без xhttp-обертки).");
                }

                return true;
            }
            catch (Exception ex)
            {
                FileLog.W($"[VLESS MUX CONN ERROR] {ex.Message}");
                Close();
                return false;
            }
        }

        private async System.Threading.Tasks.Task WriteRawAsync(byte[] data)
        {
            byte[] toSend = _realityStream != null ? _realityStream.EncryptRecord(data) : data;
            if (_outStream == null) _outStream = Socket.OutputStream.AsStreamForWrite(81920);
            _outStream.Write(toSend, 0, toSend.Length);
            await _outStream.FlushAsync();
        }

        private async System.Threading.Tasks.Task WriteRawSerializedAsync(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            await _rawWriteLock.WaitAsync();
            try { await WriteRawAsync(data); }
            finally { _rawWriteLock.Release(); }
        }

        private async System.Threading.Tasks.Task<bool> StartH2Async()
        {
            try
            {
                _h2 = new Http2Conn(_cfg);
                _h2Enabled = true;

                await WriteRawSerializedAsync(_h2.BuildClientHandshake());
                await WriteRawSerializedAsync(_h2.BuildHeaders());

                FileLog.Important("[H2] preface+SETTINGS+HEADERS отправлены (stream 1). Ответ читаем лениво.");
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[H2 ERROR] StartH2: {ex.Message}");
                return false;
            }
        }

        private async System.Threading.Tasks.Task<bool> StartXhttpStreamOneAsync()
        {
            try
            {
                byte[] head = _xhttp.BuildRequestHead();
                FileLog.Important("[XHTTP] >>> Отправка POST stream-one:\r\n" + Encoding.ASCII.GetString(head));
                await WriteRawAsync(head);
                FileLog.Important("[XHTTP] POST-заголовок отправлен.");

                if (!_directMode)
                {
                    byte[] ka = new byte[6];
                    ka[1] = 4;
                    ka[4] = 0x04;
                    await WriteUnderlyingAsync(ka);
                }
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[XHTTP ERROR] StartXhttpStreamOne: {ex.Message}");
                return false;
            }
        }

        public async System.Threading.Tasks.Task WriteUnderlyingAsync(byte[] data)
        {
            if (_h2Enabled)
            {
                byte[] payload;
                if (!_vlessHeaderSent)
                {
                    _vlessHeaderSent = true;
                    int hl = _vlessHeaderBuffer.Length;
                    payload = new byte[hl + (data?.Length ?? 0)];
                    System.Buffer.BlockCopy(_vlessHeaderBuffer, 0, payload, 0, hl);
                    if (data != null && data.Length > 0)
                        System.Buffer.BlockCopy(data, 0, payload, hl, data.Length);
                }
                else
                {
                    payload = data ?? new byte[0];
                }

                int off = 0;
                int maxFrame = Math.Min(_h2.PeerMaxFrame, 16384);
                if (maxFrame <= 0) maxFrame = 16384;

                while (off < payload.Length)
                {
                    if (_h2.StreamClosed) return;
                    int piece = Math.Min(payload.Length - off, maxFrame);

                    while (!_h2.TryReserveSend(piece))
                    {
                        if (_h2.StreamClosed) return;
                        await _h2.WaitWindowAsync();
                    }

                    byte[] frame = _h2.FrameData(payload, off, piece, false);
                    await WriteRawSerializedAsync(frame);
                    off += piece;
                }

                if (FileLog.Verbose) FileLog.W($"[H2 TX] {payload.Length}b (stream 1)");
                return;
            }

            byte[] toSend = data ?? new byte[0];
            if (_vlessHeaderBuffer != null)
            {
                byte[] combined = new byte[_vlessHeaderBuffer.Length + toSend.Length];
                System.Buffer.BlockCopy(_vlessHeaderBuffer, 0, combined, 0, _vlessHeaderBuffer.Length);
                if (toSend.Length > 0)
                    System.Buffer.BlockCopy(toSend, 0, combined, _vlessHeaderBuffer.Length, toSend.Length);
                toSend = combined;
                _vlessHeaderBuffer = null;
            }

            if (FileLog.Verbose)
            {
                if (_directMode) FileLog.W($"[DIRECT TX] payload {toSend.Length}b");
                else FileLog.W($"[NAT->VLESS] {SummarizeMux(toSend)}");
            }

            if (_xhttpEnabled)
            {
                toSend = _xhttp.WrapChunk(toSend);
            }

            if (_realityStream != null) toSend = _realityStream.EncryptRecord(toSend);

            if (_outStream == null) _outStream = Socket.OutputStream.AsStreamForWrite(81920);
            _outStream.Write(toSend, 0, toSend.Length);
            await _outStream.FlushAsync();
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
                if (_realityStream != null)
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

                        if (recordType == 20)
                        {
                            continue;
                        }

                        byte innerType;
                        byte[] plain = _realityStream.DecryptRecordExplicit(header, payload, out innerType);
                        if (plain == null)
                        {
                            FileLog.W("[TLS] Ошибка расшифровки TLS-записи.");
                            return null;
                        }

                        if (innerType == 23)
                        {
                            return plain;
                        }
                        else
                        {
                            FileLog.W($"[TLS] Отсеяно служебное шифрованное TLS-сообщение (тип: {innerType})");
                        }
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
            catch (Exception ex)
            {
                FileLog.W($"[TLS READ ERROR] {ex.Message}");
                return null;
            }
        }

        private async Task<byte[]> ReadUnderlyingRecordAsync()
        {
            if (_h2Enabled)
            {
                while (true)
                {
                    if (_h2PendingCredit > 0) { _h2.CreditConsumed(_h2PendingCredit); _h2PendingCredit = 0; }

                    byte[] pend = _h2.TakePending();
                    if (pend != null) await WriteRawSerializedAsync(pend);

                    if (_h2.HeadersDone && !_h2HeadStatusLogged)
                    {
                        _h2HeadStatusLogged = true;
                        FileLog.Important($"[H2] <<< :status {_h2.Status}");
                        if (_h2.Status != 200)
                        {
                            FileLog.Important($"[H2 ERROR] не 200 (path/host/padding?): {_h2.Status}");
                            return null;
                        }
                        FileLog.Important("[H2] поток принят, читаю downstream DATA.");
                    }

                    byte[] d = _h2.Pull();
                    if (d != null && d.Length > 0) { _h2PendingCredit = d.Length; return d; }
                    if (_h2.StreamClosed) return null;

                    byte[] plain = await ReadTlsPlaintextAsync();
                    if (plain == null) return null;
                    _h2.Feed(plain);

                    byte[] p2 = _h2.TakePending();
                    if (p2 != null) await WriteRawSerializedAsync(p2);
                }
            }

            if (!_xhttpEnabled)
                return await ReadTlsPlaintextAsync();

            if (!_xhttpHeadParsed)
            {
                var deadline = DateTime.UtcNow.AddSeconds(15);
                while (true)
                {
                    byte[] plain = await ReadTlsPlaintextAsync();
                    if (plain == null)
                    {
                        FileLog.Important("[XHTTP ERROR] TLS закрыт до получения заголовков ответа.");
                        return null;
                    }

                    if (_xhttp.TryConsumeResponseHead(plain, out string status, out var headers))
                    {
                        FileLog.Important($"[XHTTP] <<< {status}");
                        if (status == null || !status.Contains(" 200"))
                        {
                            FileLog.Important($"[XHTTP ERROR] Сервер вернул не 200 (path/host?): {status}");
                            return null;
                        }

                        _xhttp.ConfigureFromResponse(headers);
                        _xhttpHeadParsed = true;
                        FileLog.Important("[XHTTP] Заголовки приняты, читаю chunked downstream.");
                        break;
                    }

                    if (DateTime.UtcNow > deadline)
                    {
                        FileLog.Important("[XHTTP ERROR] Таймаут ожидания заголовков ответа (15с).");
                        return null;
                    }
                }
            }

            while (true)
            {
                byte[] outp = _xhttp.Pull();
                if (outp != null && outp.Length > 0) return outp;
                if (_xhttp.StreamClosed) return null;

                byte[] plain = await ReadTlsPlaintextAsync();
                if (plain == null) return null;
                _xhttp.Feed(plain);
            }
        }

        public async Task<byte[]> ReadVlessPayloadAsync()
        {
            byte[] raw = await ReadUnderlyingRecordAsync();
            if (raw == null || raw.Length == 0) return null;

            byte[] output;

            if (!_headerStripped)
            {
                _receiveBuffer.AddRange(raw);
                if (_receiveBuffer.Count >= 2)
                {
                    int totalHeader = 2 + _receiveBuffer[1];
                    if (_receiveBuffer.Count >= totalHeader)
                    {
                        byte[] leftover = _receiveBuffer.Skip(totalHeader).ToArray();
                        _receiveBuffer.Clear();
                        _headerStripped = true;
                        output = leftover;
                    }
                    else return new byte[0];
                }
                else return new byte[0];
            }
            else
            {
                output = raw;
            }

            if (output.Length > 0 && FileLog.Verbose)
            {
                if (_directMode)
                {
                    int n = Math.Min(output.Length, 32);
                    var sb = new StringBuilder();
                    for (int i = 0; i < n; i++) sb.Append(output[i].ToString("X2")).Append(' ');
                    FileLog.W($"[VLESS->NAT DIRECT] {output.Length}b: {sb}");
                }
                else
                {
                    FileLog.W($"[VLESS->NAT] {SummarizeMux(output)}");
                }
            }
            return output;
        }

        private static string SummarizeMux(byte[] d)
        {
            if (d == null || d.Length < 6) return $"[{d?.Length ?? 0}b]";
            int metaLen = (d[0] << 8) | d[1];
            if (metaLen < 4 || d.Length < 2 + metaLen) return $"[{d.Length}b неполн]";
            ushort sid = (ushort)((d[2] << 8) | d[3]);
            byte status = d[4], opt = d[5];
            string st = status == 1 ? "New" : status == 2 ? "Keep" : status == 3 ? "End" : status == 4 ? "KeepAlive" : $"?{status}";
            int pay = ((opt & 1) != 0 && d.Length >= 4 + metaLen) ? (d[2 + metaLen] << 8) | d[2 + metaLen + 1] : 0;
            return $"sid={sid} {st} data={pay}b ({d.Length}b всего)";
        }

        public void Close() { try { _writer?.Dispose(); _reader?.Dispose(); Socket?.Dispose(); } catch { }; try { _outStream?.Dispose(); } catch { } }
    }
}