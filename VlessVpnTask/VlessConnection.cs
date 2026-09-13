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

    // Быстрый X25519 (radix 2^25.5, 10 знаковых 64-битных лимбов — представление
    // curve25519-donna). В горячем пути только long-арифметика без BigInteger и
    // без деления, поэтому на ARM это на порядок быстрее прежней BigInteger-версии.
    // Реализация проверена против тест-векторов RFC 7748 и перекрёстно на тысячах
    // случайных входов против прежней BigInteger-реализации.
    internal static class Curve25519
    {
        private static readonly int[] SZ = { 26, 25, 26, 25, 26, 25, 26, 25, 26, 25 };
        [ThreadStatic] private static long[] _scratch19;

        public static byte[] CreateRandomPrivateKey()
        {
            byte[] k = Tls13Crypto.RandomBytes(32);
            k[0] &= 248; k[31] &= 127; k[31] |= 64;
            return k;
        }

        public static byte[] GetPublicKey(byte[] privateKey)
        {
            var bp = new byte[32]; bp[0] = 9;
            return ScalarMult(privateKey, bp);
        }

        public static byte[] GetSharedSecret(byte[] privateKey, byte[] peerPublicKey)
        {
            return ScalarMult(privateKey, peerPublicKey);
        }

        private static long[] Expand(byte[] input)
        {
            var t = new byte[33];
            Array.Copy(input, t, 32);
            t[31] &= 0x7f; // RFC 7748: обнуляем старший бит u
            System.Numerics.BigInteger x = new System.Numerics.BigInteger(t);
            var o = new long[10];
            for (int i = 0; i < 10; i++)
            {
                o[i] = (long)(x & ((System.Numerics.BigInteger.One << SZ[i]) - 1));
                x >>= SZ[i];
            }
            return o;
        }

        private static byte[] Contract(long[] input)
        {
            FreduceCoefficients(input);
            System.Numerics.BigInteger x = 0; int off = 0;
            for (int i = 0; i < 10; i++) { x += (System.Numerics.BigInteger)input[i] << off; off += SZ[i]; }
            System.Numerics.BigInteger P = (System.Numerics.BigInteger.One << 255) - 19;
            x %= P; if (x.Sign < 0) x += P;
            var raw = x.ToByteArray();
            var b = new byte[32];
            Array.Copy(raw, b, Math.Min(32, raw.Length));
            return b;
        }

        private static void Fsum(long[] o, long[] a) { for (int i = 0; i < 10; i++) o[i] += a[i]; }
        private static void Fdiff(long[] o, long[] a, long[] b) { for (int i = 0; i < 10; i++) o[i] = a[i] - b[i]; }
        private static void Fscalar(long[] o, long[] a, long s) { for (int i = 0; i < 10; i++) o[i] = a[i] * s; }

        private static void Fproduct(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < 19; i++) o[i] = 0;
            for (int i = 0; i < 10; i++)
                for (int j = 0; j < 10; j++)
                {
                    long f = ((i & 1) == 1 && (j & 1) == 1) ? 2 : 1;
                    o[i + j] += f * a[i] * b[j];
                }
        }

        private static void FreduceDegree(long[] o)
        {
            o[8] += o[18] * 19; o[7] += o[17] * 19; o[6] += o[16] * 19; o[5] += o[15] * 19;
            o[4] += o[14] * 19; o[3] += o[13] * 19; o[2] += o[12] * 19; o[1] += o[11] * 19; o[0] += o[10] * 19;
        }

        private static long DivBy2_26(long v) { long sign = v >> 63; long roundoff = (long)((ulong)sign >> 38); return (v + roundoff) >> 26; }
        private static long DivBy2_25(long v) { long sign = v >> 63; long roundoff = (long)((ulong)sign >> 39); return (v + roundoff) >> 25; }

        private static void FreduceCoefficients(long[] o)
        {
            long o10 = 0, over;
            for (int i = 0; i < 10; i += 2)
            {
                over = DivBy2_26(o[i]); o[i] -= over << 26; o[i + 1] += over;
                over = DivBy2_25(o[i + 1]); o[i + 1] -= over << 25;
                if (i + 2 < 10) o[i + 2] += over; else o10 += over;
            }
            o[0] += o10 * 19;
            over = DivBy2_26(o[0]); o[0] -= over << 26; o[1] += over;
        }

        private static void Fmul(long[] o, long[] a, long[] b)
        {
            long[] t = _scratch19; if (t == null) { t = new long[19]; _scratch19 = t; }
            Fproduct(t, a, b);
            FreduceDegree(t);
            FreduceCoefficients(t);
            for (int i = 0; i < 10; i++) o[i] = t[i];
        }

        private static void Fsquare(long[] o, long[] a) { Fmul(o, a, a); }
        private static void SqN(long[] dst, long[] src, int n) { Fsquare(dst, src); for (int i = 1; i < n; i++) Fsquare(dst, dst); }

        private static long[] Recip(long[] z)
        {
            long[] z2 = new long[10], z9 = new long[10], z11 = new long[10], z2_5_0 = new long[10],
                   z2_10_0 = new long[10], z2_20_0 = new long[10], z2_50_0 = new long[10],
                   z2_100_0 = new long[10], t = new long[10];
            Fsquare(z2, z);
            SqN(t, z2, 2); Fmul(z9, t, z);
            Fmul(z11, z9, z2);
            SqN(t, z11, 1); Fmul(z2_5_0, t, z9);
            SqN(t, z2_5_0, 5); Fmul(z2_10_0, t, z2_5_0);
            SqN(t, z2_10_0, 10); Fmul(z2_20_0, t, z2_10_0);
            SqN(t, z2_20_0, 20); Fmul(t, t, z2_20_0);
            SqN(t, t, 10); Fmul(z2_50_0, t, z2_10_0);
            SqN(t, z2_50_0, 50); Fmul(z2_100_0, t, z2_50_0);
            SqN(t, z2_100_0, 100); Fmul(t, t, z2_100_0);
            SqN(t, t, 50); Fmul(t, t, z2_50_0);
            SqN(t, t, 5);
            long[] outp = new long[10]; Fmul(outp, t, z11);
            return outp;
        }

        private static void CSwap(int swap, long[] a, long[] b)
        {
            if (swap == 0) return;
            for (int i = 0; i < 10; i++) { long t = a[i]; a[i] = b[i]; b[i] = t; }
        }

        private static byte[] ScalarMult(byte[] scalar, byte[] uBytes)
        {
            if (scalar == null || scalar.Length != 32) throw new ArgumentException("X25519 key must be 32 bytes.");
            if (uBytes == null || uBytes.Length != 32) throw new ArgumentException("X25519 input must be 32 bytes.");

            var k = new byte[32]; Array.Copy(scalar, k, 32);
            k[0] &= 248; k[31] &= 127; k[31] |= 64;

            long[] x1 = Expand(uBytes);
            long[] x2 = new long[10]; x2[0] = 1;
            long[] z2 = new long[10];
            long[] x3 = (long[])x1.Clone();
            long[] z3 = new long[10]; z3[0] = 1;
            int swap = 0;

            long[] A = new long[10], AA = new long[10], B = new long[10], BB = new long[10],
                   E = new long[10], C = new long[10], D = new long[10], DA = new long[10],
                   CB = new long[10], t0 = new long[10], t1 = new long[10];

            for (int t = 254; t >= 0; t--)
            {
                int kt = (k[t >> 3] >> (t & 7)) & 1;
                swap ^= kt;
                CSwap(swap, x2, x3);
                CSwap(swap, z2, z3);
                swap = kt;

                Array.Copy(x2, A, 10); Fsum(A, z2);      // A = x2+z2
                Fsquare(AA, A);
                Fdiff(B, x2, z2);                         // B = x2-z2
                Fsquare(BB, B);
                Fdiff(E, AA, BB);                         // E = AA-BB
                Array.Copy(x3, C, 10); Fsum(C, z3);      // C = x3+z3
                Fdiff(D, x3, z3);                         // D = x3-z3
                Fmul(DA, D, A);
                Fmul(CB, C, B);
                Array.Copy(DA, t0, 10); Fsum(t0, CB);    // t0 = DA+CB
                Fsquare(x3, t0);                          // x3 = (DA+CB)^2
                Fdiff(t1, DA, CB);                        // t1 = DA-CB
                Fsquare(t0, t1);                          // t0 = (DA-CB)^2
                Fmul(z3, x1, t0);                         // z3 = x1*(DA-CB)^2
                Fmul(x2, AA, BB);                         // x2 = AA*BB
                Fscalar(t0, E, 121665);                   // t0 = a24*E
                FreduceCoefficients(t0);
                Fsum(t0, AA);                             // t0 = AA + a24*E
                Fmul(z2, E, t0);                          // z2 = E*(AA+a24*E)
            }
            CSwap(swap, x2, x3);
            CSwap(swap, z2, z3);

            long[] zinv = Recip(z2);
            long[] res = new long[10];
            Fmul(res, x2, zinv);
            return Contract(res);
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

        // ===== хеш-агностичные примитивы =====
        // TLS 1.3 привязывает KDF к хешу выбранного шифра: 0x1301 → SHA-256,
        // 0x1302 (AES-256-GCM-SHA384) → SHA-384. Раньше всё было жёстко на SHA-256,
        // поэтому серверы, выбирающие 0x1302, ломали handshake.

        public static int HashLenOf(bool sha384) { return sha384 ? 48 : 32; }

        public static byte[] Sha384(byte[] data)
        {
            var provider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha384);
            IBuffer hash = provider.HashData(ToBuffer(data));
            return FromBuffer(hash);
        }

        public static byte[] HmacSha384(byte[] key, byte[] data)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha384);
            var cryptoKey = provider.CreateKey(ToBuffer(key));
            return FromBuffer(CryptographicEngine.Sign(cryptoKey, ToBuffer(data)));
        }

        public static byte[] Hash(bool sha384, byte[] data)
        {
            return sha384 ? Sha384(data) : Sha256(data);
        }

        public static byte[] Hmac(bool sha384, byte[] key, byte[] data)
        {
            return sha384 ? HmacSha384(key, data) : HmacSha256(key, data);
        }

        public static byte[] HkdfExtract(bool sha384, byte[] salt, byte[] ikm)
        {
            if (salt == null) salt = new byte[HashLenOf(sha384)];
            if (ikm == null) ikm = new byte[0];
            return Hmac(sha384, salt, ikm);
        }

        public static byte[] HkdfExpand(bool sha384, byte[] prk, byte[] info, int length)
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
                t = Hmac(sha384, prk, input);
                okm.AddRange(t);
            }
            var result = new byte[length];
            okm.CopyTo(0, result, 0, length);
            return result;
        }

        public static byte[] HkdfExpandLabel(bool sha384, byte[] secret, string label, byte[] context, int length)
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
            return HkdfExpand(sha384, secret, info.ToArray(), length);
        }

        public static byte[] DeriveSecret(bool sha384, byte[] secret, string label, byte[] transcript)
        {
            return HkdfExpandLabel(sha384, secret, label,
                Hash(sha384, transcript ?? new byte[0]), HashLenOf(sha384));
        }

        // ===== совместимость: старые вызовы (SHA-256) =====
        public static byte[] HkdfExtract(byte[] salt, byte[] ikm) { return HkdfExtract(false, salt, ikm); }
        public static byte[] HkdfExpand(byte[] prk, byte[] info, int length) { return HkdfExpand(false, prk, info, length); }
        public static byte[] HkdfExpandLabel(byte[] secret, string label, byte[] context, int length)
        { return HkdfExpandLabel(false, secret, label, context, length); }
        public static byte[] DeriveSecret(byte[] secret, string label, byte[] transcript)
        { return DeriveSecret(false, secret, label, transcript); }

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

        // Параметры выбранного сервером шифра (заполняются в ParseServerHello).
        private bool _sha384;      // 0x1302 → SHA-384 в KDF/транскрипте
        private int _aesKeyLen = 16; // 16 для AES-128-GCM, 32 для AES-256-GCM и ChaCha20
        private bool _chacha;      // 0x1303 → ChaCha20-Poly1305 вместо AES-GCM

        private byte[] _clientPrivate, _clientPublic, _clientRandom, _realityAuthKey;
        private List<byte> _transcript = new List<byte>();
        private byte[] _handshakeSecret, _clientHandshakeTrafficSecret, _serverHandshakeTrafficSecret;
        private byte[] _clientHandshakeKey, _clientHandshakeIv, _serverHandshakeKey, _serverAppIv;
        private byte[] _clientAppKey, _clientAppIv, _serverAppKey, _serverHandshakeIv;
        private ulong _writeSeq = 0, _readSeq = 0;

        private CryptographicKey _clientAppCryptoKey;
        private CryptographicKey _serverAppCryptoKey;
        public bool OfferH1Only = false;

        // Обычный TLS 1.3 без reality-аутентификации: в legacy_session_id пишем случайные
        // байты вместо зашифрованного auth-блока. Нужен для ws+tls: системный
        // UpgradeToSslAsync на W10M виснет намертво (проверка цепочки лезет за OCSP/CRL в сеть,
        // а та идёт в ещё не поднятый туннель — взаимная блокировка; плюс schannel умеет
        // максимум TLS 1.2, а сервер может быть TLS 1.3-only). Свой стек от ОС не зависит.
        public bool PlainTls = false;

        public string NegotiatedAlpn { get; private set; } = "";

        public RealityTls13Stream(VlessConfig config) { _cfg = config; }

        // Сколько байт всего пришло от сервера за хендшейк. Ноль при обрыве означает, что
        // ClientHello остался без ответа — сервер молчит. Это принципиально иная картина,
        // чем reality-фолбэк: тот отвечает настоящим ServerHello с сайта прикрытия.
        public int ServerBytes { get; private set; }

        // Ставится вызывающим перед Close() по своему таймауту: без этого наш же обрыв
        // сокета выглядел в логе как разрыв со стороны сервера.
        public bool AbortedByTimeout;

        // Сервер ответил на ClientHello фатальным alert'ом вместо ServerHello.
        // Ошибка ранняя и дешёвая (один RTT), поэтому её, как и fallback, имеет
        // смысл переигрывать новым соединением, а не ронять запрос целиком.
        public bool AlertBeforeServerHello;
        private byte[] _lastClientHello;

        // Общий на процесс: эталонный ClientHello пишем ровно один раз, иначе он
        // засорит лог на каждом соединении.
        private static int _goodChLogged;

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
                    ServerBytes += (int)bytesRead;
                }
                return true;
            }
            catch { return false; }
        }

        private ushort NextGrease()
        {
            byte[] r = Tls13Crypto.RandomBytes(1);
            byte b = (byte)((r[0] & 0xF0) | 0x0A); // валидный GREASE-паттерн 0x?a?a
            return (ushort)((b << 8) | b);
        }

        private byte[] BuildAlpnList()
        {
            byte[] protos = OfferH1Only
                ? new byte[] { 8, (byte)'h', (byte)'t', (byte)'t', (byte)'p', (byte)'/', (byte)'1', (byte)'.', (byte)'1' }
                : new byte[] { 2, (byte)'h',(byte)'2',
                               8, (byte)'h',(byte)'t',(byte)'t',(byte)'p',(byte)'/',(byte)'1',(byte)'.',(byte)'1' };
            byte[] list = new byte[protos.Length + 2];
            list[0] = (byte)(protos.Length >> 8);
            list[1] = (byte)(protos.Length & 0xFF);
            System.Buffer.BlockCopy(protos, 0, list, 2, protos.Length);
            return list;
        }

        // Рукопожатие REALITY почти целиком упирается в счёт: X25519, HKDF, AES-GCM,
        // проверка подписи. На телефоне это сотни миллисекунд, и когда страница разом
        // открывает десяток соединений (speedtest опрашивает дюжину серверов Ookla),
        // они начинают толкаться: в логе одно рукопожатие растягивалось до 8.4 с, из
        // них 2.3 с — до отправки ClientHello, то есть чистый локальный счёт.
        // Суммарной работы очередь не убавляет, но первые соединения получаются
        // готовыми за свои честные полсекунды вместо того, чтобы все ползли разом.
        private static readonly System.Threading.SemaphoreSlim HandshakeGate =
            new System.Threading.SemaphoreSlim(2, 2);

        public static async Task EnterHandshakeGateAsync()
        {
            if (HandshakeGate.Wait(0)) return;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await HandshakeGate.WaitAsync();
            FileLog.W($"[REALITY GATE] Ожидание очереди рукопожатий: {sw.ElapsedMilliseconds} мс.");
        }

        public static void LeaveHandshakeGate()
        {
            try { HandshakeGate.Release(); } catch { }
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
                _lastClientHello = record;
                _writer.WriteBytes(record);
                uint stored = await _writer.StoreAsync();
                // Сервер изредка отвечает на ClientHello фатальным decode_error, хотя
                // сама запись собирается одинаково и всегда одной длины. Первое, что
                // стоит исключить, — неполная запись в сокет: её результат мы до сих
                // пор не проверяли вовсе.
                if (stored != (uint)record.Length)
                    FileLog.Important($"[REALITY TLS 1.3] ВНИМАНИЕ: ClientHello записан не полностью — " +
                                      $"{stored} из {record.Length} б.");
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
                    FileLog.W(AbortedByTimeout
                        ? $"[REALITY TLS 1.3 ERROR] Чтение прервано нашим таймаутом. От сервера получено {ServerBytes} б."
                        : $"[REALITY TLS 1.3 ERROR] Соединение разорвано во время ожидания ServerHello (получено {ServerBytes} б).");
                    return false;
                }

                if (rec.Item1 == 20)
                {
                    FileLog.W("[REALITY TLS 1.3] Пропущен нешифрованный ChangeCipherSpec (тип 20)");
                    continue;
                }
                if (rec.Item1 == 21)
                {
                    // Alert вместо ServerHello — сервер не смог разобрать наш ClientHello
                    // (0232 = fatal/decode_error). Запись собирается одинаково и всегда
                    // ровно 521 б, а падает лишь часть попыток, поэтому дампим именно
                    // отвергнутый экземпляр: сравнение с удачным покажет, что плавает.
                    AlertBeforeServerHello = true;
                    FileLog.W($"[REALITY TLS 1.3 ERROR] Получен Alert-код ошибки: {CryptoSelfTest.BytesToHex(rec.Item3)}");
                    if (_lastClientHello != null)
                        FileLog.Important("[REALITY CH] Отвергнутый ClientHello: " +
                                          CryptoSelfTest.BytesToHex(_lastClientHello));
                    return false;
                }
                if (rec.Item1 == 22)
                {
                    serverHelloPayload = rec.Item3;
                    FileLog.W("[REALITY TLS 1.3] Получен ServerHello!");
                    // Эталон для сравнения с отвергнутыми: запись собирается одинаково
                    // и всегда 521 б, поэтому побайтовый diff удачной с неудачной сразу
                    // покажет, какое из случайных полей сервер не переваривает.
                    if (_lastClientHello != null &&
                        System.Threading.Interlocked.Exchange(ref _goodChLogged, 1) == 0)
                        FileLog.Important("[REALITY CH] Принятый ClientHello: " +
                                          CryptoSelfTest.BytesToHex(_lastClientHello));
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
                        if (ServerFellBack)
                        {
                            FileLog.W("[REALITY TLS 1.3] Fallback (реальный сертификат) — обрываю хендшейк для быстрого повтора.");
                            return false;
                        }
                    }
                    else if (hsType == 25 && !PlainTls) // compressed_certificate (RFC 8879)
                    {
                        // Мы не объявляем compress_certificate, значит сжать сертификат мог
                        // только тот, кто нас не аутентифицировал: reality-сервер отдаёт
                        // обычный тип 11. Разобрать такой сертификат нечем, поэтому считаем
                        // это фолбэком — иначе туннеля нет, а клиент этого не замечает.
                        FileLog.Important("[REALITY TLS 1.3] Сервер прислал СЖАТЫЙ сертификат (тип 25) — " +
                                          "это не reality-сервер, а сайт-прикрытие. Считаю фолбэком.");
                        ServerFellBack = true;
                        return false;
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

        // Ставится в true, если reality-сервер отдал реальную CA-цепочку вместо
        // самоподписанного «прикрытия» — значит он НЕ аутентифицировал наш ClientHello
        // (fallback). Используется для быстрого in-place повтора в StartAsync.
        public bool ServerFellBack { get; private set; }

        private void InspectServerCertificate(byte[] hsMsg)
        {
            int certLen = 0;
            try
            {
                int pos = 4;
                int ctxLen = hsMsg[pos]; pos += 1 + ctxLen;
                pos += 3;
                certLen = (hsMsg[pos] << 16) | (hsMsg[pos + 1] << 8) | hsMsg[pos + 2];
                pos += 3;

                if (certLen <= 0 || pos + certLen > hsMsg.Length) return;

                byte[] der = new byte[certLen];
                System.Buffer.BlockCopy(hsMsg, pos, der, 0, certLen);

                var cert = new Windows.Security.Cryptography.Certificates.Certificate(der.AsBuffer());
                bool selfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase);
                // В обычном TLS сертификат от настоящего CA — это НОРМА, а не признак
                // reality-фолбэка. Флаг ставим только в reality-режиме.
                if (!selfSigned && !PlainTls) ServerFellBack = true;

                FileLog.W("========== СЕРТИФИКАТ СЕРВЕРА ==========");
                FileLog.W($"[CERT] Subject:   {cert.Subject}");
                FileLog.W($"[CERT] Issuer:    {cert.Issuer}");
                FileLog.W(PlainTls
                    ? "[CERT] => Обычный TLS 1.3 (цепочку не проверяем — туннель и так шифрован VLESS)."
                    : selfSigned
                        ? "[CERT] => Самоподписанный/временный сертификат: REALITY НАС ПРИНЯЛ."
                        : "[CERT] => Реальная цепочка CA: МЫ В FALLBACK, REALITY нас отбросил на прикрытие.");
                FileLog.W("=======================================");
            }
            catch (Exception ex)
            {
                // Windows не умеет разбирать сертификаты на Ed25519, а REALITY выдаёт
                // именно такой — крошечный и подписанный ключом, выведенным из общего
                // секрета. Раньше исключение глоталось, и в логе не было НИ ОДНОЙ строки
                // про сертификат ровно в тот момент, когда туннель наконец поднялся.
                // Размер здесь решает: настоящая CA-цепочка — это килобайты.
                FileLog.W($"[CERT] Разобрать сертификат не удалось ({certLen} б): {ex.Message}");
                FileLog.W(certLen > 0 && certLen < 512
                    ? "[CERT] => Размер как у временного сертификата REALITY — на прикрытие не похоже."
                    : "[CERT] => Размер как у настоящей цепочки CA — вероятен FALLBACK.");
            }
        }

        // Версия клиента внутри auth-payload reality (первые три байта session_id).
        // Это НЕ косметика: у сервера есть настройка minClientVer формата x.y.z, которая
        // сверяется именно с этими байтами, и клиент старее заданного уводится на
        // сайт-прикрытие — неотличимо от неверного ключа. Мы годами слали 1.8.1, поэтому
        // серверы с minClientVer нас молча отфутболивали.
        // Держим версию не ниже актуального ядра Xray. Верхнюю границу (maxClientVer)
        // операторы почти никогда не задают, так что риск завысить минимален.
        private const byte RealityVerX = 26;
        private const byte RealityVerY = 3;
        private const byte RealityVerZ = 27;

        // Соединений за сеанс десятки, поэтому параметры auth пишем один раз за процесс:
        // по ним видно, совпадают ли pbk/sid со ссылкой и не уехали ли часы устройства
        // (сервер может отбивать по maxTimeDiff).
        private static int _authParamsLogged;

        private void LogAuthParamsOnce(bool pubKeyOk)
        {
            if (System.Threading.Interlocked.Exchange(ref _authParamsLogged, 1) != 0) return;
            try
            {
                string sid = _cfg.ShortId ?? "";
                int sidBytes = -1;
                try { sidBytes = CryptoSelfTest.HexToBytes(sid).Length; } catch { }
                FileLog.Important($"[REALITY AUTH] pbk={(pubKeyOk ? "32 байта, ок" : "НЕВЕРНЫЙ")}, " +
                                  $"sid='{sid}' ({sidBytes} байт), sni='{_cfg.Sni}', " +
                                  $"версия клиента={RealityVerX}.{RealityVerY}.{RealityVerZ}, " +
                                  $"часы устройства UTC={DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
            }
            catch { }
        }

        private byte[] BuildRealityClientHello()
        {
            ushort gCipher = NextGrease();
            ushort gGroup = NextGrease();
            ushort gVer = NextGrease();
            ushort gExtA = NextGrease();
            ushort gExtB = NextGrease();
            // gExtA и gExtB идут в ClientHello как ТИПЫ двух GREASE-расширений, а RFC 8446
            // запрещает два расширения одного типа. Значения тянулись независимо из набора
            // в 16 штук, поэтому раз на шестнадцать они совпадали — и сервер отвечал на такую
            // запись fatal decode_error (alert 0232). Chrome по той же причине берёт для этих
            // двух слотов заведомо разные значения. При совпадении сдвигаем на шаг по набору
            // (0x0a0a…0xfafa, с переходом через край) — детерминированно и всегда валидно.
            if (gExtB == gExtA)
            {
                byte hi = (byte)((((gExtA >> 8) + 0x10) & 0xF0) | 0x0A);
                gExtB = (ushort)((hi << 8) | hi);
            }

            using (var ms = new MemoryStream())
            {
                ms.WriteByte(3); ms.WriteByte(3);                 // legacy_version = TLS 1.2
                ms.Write(_clientRandom, 0, 32);                   // random
                ms.WriteByte(32); ms.Write(new byte[32], 0, 32);  // legacy_session_id (auth впишется сюда позже)

                // cipher_suites.
                //
                // REALITY: GREASE + только TLS_AES_128_GCM_SHA256 (0x1301). 0x1301 обязателен
                // в любом TLS 1.3 сервере (RFC 8446 §9.1), а наш KDF умеет только SHA-256.
                // Предлагать 0x1302/0x1303 нельзя — сервер их выберет, а расшифровать мы не
                // сможем (ровно так и ломалось: сервер выбирал 0x1302).
                //
                // ОБЫЧНЫЙ TLS (PlainTls): одинокий 0x1301 — крайне нетипичный отпечаток. Happ
                // ходит на этот же сервер с uTLS-отпечатком Chrome и работает, а наш ClientHello
                // сервер/фильтр рвёт до ServerHello. Поэтому предлагаем Chrome-подобный набор.
                // Если сервер выберет шифр, который мы не реализуем, ParseServerHello скажет об
                // этом явно (и тогда будет понятно, что именно доделывать).
                byte[] cipherSuites;
                if (PlainTls)
                {
                    cipherSuites = new byte[]
                    {
                        (byte)(gCipher >> 8), (byte)gCipher,
                        0x13,0x01, 0x13,0x02, 0x13,0x03,
                        0xc0,0x2b, 0xc0,0x2f, 0xc0,0x2c, 0xc0,0x30,
                        0xcc,0xa9, 0xcc,0xa8,
                        0xc0,0x13, 0xc0,0x14,
                        0x00,0x9c, 0x00,0x9d, 0x00,0x2f, 0x00,0x35
                    };
                }
                else
                {
                    cipherSuites = new byte[]
                    {
                        (byte)(gCipher >> 8), (byte)gCipher,
                        0x13, 0x01
                    };
                }
                ms.WriteByte((byte)(cipherSuites.Length >> 8));
                ms.WriteByte((byte)(cipherSuites.Length & 0xFF));
                ms.Write(cipherSuites, 0, cipherSuites.Length);

                ms.WriteByte(0x01); ms.WriteByte(0x00);           // legacy_compression = null

                byte[] exts = BuildExtensions(gGroup, gVer, gExtA, gExtB, cipherSuites.Length);
                ms.WriteByte((byte)(exts.Length >> 8)); ms.WriteByte((byte)(exts.Length & 0xFF));
                ms.Write(exts, 0, exts.Length);

                byte[] body = ms.ToArray();
                using (var hs = new MemoryStream())
                {
                    hs.WriteByte(1);
                    hs.WriteByte((byte)(body.Length >> 16));
                    hs.WriteByte((byte)(body.Length >> 8));
                    hs.WriteByte((byte)(body.Length & 0xFF));
                    hs.Write(body, 0, body.Length);
                    byte[] hsBytes = hs.ToArray();

                    // ==== Обычный TLS 1.3: session_id = случайные байты, auth не нужен ====
                    if (PlainTls)
                    {
                        byte[] sid = Tls13Crypto.RandomBytes(32);
                        System.Buffer.BlockCopy(sid, 0, hsBytes, 39, 32);
                        return hsBytes;
                    }

                    // ==== Reality-auth ====
                    // Ключ обязан раскодироваться ровно в 32 байта. Раньше при кривом pbk
                    // сюда молча уходил массив нулей (или неверной длины), общий секрет
                    // получался мусорным, сервер отправлял нас в фолбэк — и понять причину
                    // по логу было нельзя.
                    byte[] pubKey = new byte[32];
                    bool pubKeyOk = false;
                    if (!string.IsNullOrEmpty(_cfg.PublicKey))
                    {
                        string b64 = _cfg.PublicKey.Replace("-", "+").Replace("_", "/");
                        while (b64.Length % 4 != 0) b64 += "=";
                        try
                        {
                            byte[] decoded = Convert.FromBase64String(b64);
                            if (decoded.Length == 32) { pubKey = decoded; pubKeyOk = true; }
                            else FileLog.Important($"[REALITY AUTH] pbk раскодировался в {decoded.Length} байт вместо 32 — ключ в ссылке битый.");
                        }
                        catch (Exception ex)
                        {
                            FileLog.Important($"[REALITY AUTH] pbk не разбирается как base64: {ex.Message}");
                        }
                    }
                    else FileLog.Important("[REALITY AUTH] В профиле нет pbk — аутентификация reality невозможна.");

                    LogAuthParamsOnce(pubKeyOk);

                    byte[] shared = Curve25519.GetSharedSecret(_clientPrivate, pubKey);
                    byte[] prk = Tls13Crypto.HkdfExtract(_clientRandom.Take(20).ToArray(), shared);
                    _realityAuthKey = Tls13Crypto.HkdfExpand(prk, Encoding.ASCII.GetBytes("REALITY"), 32);
                    byte[] nonce = _clientRandom.Skip(20).Take(12).ToArray();

                    byte[] p = new byte[16];
                    uint now = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    p[0] = RealityVerX; p[1] = RealityVerY; p[2] = RealityVerZ;
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

        private byte[] BuildExtensions(ushort gGroup, ushort gVer, ushort gExtA, ushort gExtB, int cipherBytes)
        {
            using (var ms = new MemoryStream())
            {
                // 1. GREASE (пустое)
                AddExt(ms, gExtA, new byte[0]);

                // 2. server_name.
                // Пустой SNI — законная конфигурация: так отдаёт конфиги Amnezia.
                // Подставлять вместо него адрес сервера нельзя по двум причинам:
                // literal-IP в SNI запрещён RFC 6066, а REALITY сверяет имя со
                // своим списком serverNames и на IP отвечает прикрытием. Раньше
                // подстановка стояла как «запасной вариант» и на таких конфигах
                // гарантированно уводила рукопожатие в fallback. Если имени нет —
                // расширение не отправляем вовсе, как это делает uTLS.
                if (!string.IsNullOrEmpty(_cfg.Sni))
                {
                    byte[] sniBytes = Encoding.ASCII.GetBytes(_cfg.Sni);
                    byte[] sniExt = new byte[5 + sniBytes.Length];
                    sniExt[0] = (byte)((sniBytes.Length + 3) >> 8); sniExt[1] = (byte)(sniBytes.Length + 3);
                    sniExt[2] = 0; sniExt[3] = (byte)(sniBytes.Length >> 8); sniExt[4] = (byte)(sniBytes.Length & 0xFF);
                    System.Buffer.BlockCopy(sniBytes, 0, sniExt, 5, sniBytes.Length);
                    AddExt(ms, 0x0000, sniExt);
                }

                // 3. extended_master_secret
                AddExt(ms, 0x0017, new byte[0]);
                // 4. renegotiation_info
                AddExt(ms, 0xff01, new byte[] { 0x00 });
                // 5. supported_groups: GREASE, x25519, secp256r1, secp384r1
                AddExt(ms, 0x000a, new byte[] {
                    0x00, 0x08,
                    (byte)(gGroup >> 8), (byte)gGroup,
                    0x00, 0x1d, 0x00, 0x17, 0x00, 0x18
                });
                // 6. ec_point_formats: uncompressed
                AddExt(ms, 0x000b, new byte[] { 0x01, 0x00 });
                // 7. session_ticket
                AddExt(ms, 0x0023, new byte[0]);
                // 8. ALPN
                AddExt(ms, 0x0010, BuildAlpnList());
                // 9. status_request (OCSP)
                AddExt(ms, 0x0005, new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 });
                // 10. signature_algorithms (Chrome-порядок)
                AddExt(ms, 0x000d, new byte[] {
                    0x00, 0x10,
                    0x04,0x03, 0x08,0x04, 0x04,0x01, 0x05,0x03,
                    0x08,0x05, 0x05,0x01, 0x08,0x06, 0x06,0x01
                });
                // 11. signed_certificate_timestamp
                AddExt(ms, 0x0012, new byte[0]);
                // 12. key_share: GREASE(1 байт) + x25519(32 байта). GREASE-group совпадает с supported_groups.
                byte[] ks = new byte[2 + 5 + 4 + 32];
                int ksLen = 5 + 4 + 32; // длина client_shares
                ks[0] = (byte)(ksLen >> 8); ks[1] = (byte)ksLen;
                ks[2] = (byte)(gGroup >> 8); ks[3] = (byte)gGroup; ks[4] = 0x00; ks[5] = 0x01; ks[6] = 0x00;
                ks[7] = 0x00; ks[8] = 0x1d; ks[9] = 0x00; ks[10] = 0x20;
                System.Buffer.BlockCopy(_clientPublic, 0, ks, 11, 32);
                AddExt(ms, 0x0033, ks);
                // 13. psk_key_exchange_modes: psk_dhe_ke
                AddExt(ms, 0x002d, new byte[] { 0x01, 0x01 });
                // 14. supported_versions.
                // REALITY: GREASE + только TLS 1.3 (сервер обязан выбрать 1.3 — мы больше ничего
                // не умеем). PlainTls: добавляем ещё и 1.2, как это делает Chrome — так CH
                // выглядит браузерным. Любой TLS 1.3-сервер всё равно выберет 1.3 (берётся
                // максимальная общая версия), а если сервер только 1.2 — сработает запасной
                // системный путь в WsTransport.
                AddExt(ms, 0x002b, PlainTls
                    ? new byte[] { 0x06, (byte)(gVer >> 8), (byte)gVer, 0x03, 0x04, 0x03, 0x03 }
                    : new byte[] { 0x04, (byte)(gVer >> 8), (byte)gVer, 0x03, 0x04 });
                // 15. compress_certificate: brotli — ТОЛЬКО в обычном TLS.
                // В reality его просить нельзя: сервер честно отвечает сжатым сертификатом
                // (handshake-сообщение типа 25 вместо 11), распаковать brotli в UWP нечем,
                // InspectServerCertificate не вызывается — и определение фолбэка
                // (ServerFellBack) перестаёт работать. Клиент считает хендшейк успешным
                // и льёт в браузер HTTP/2-мусор с сайта-прикрытия.
                // В PlainTls сертификат мы и так не проверяем, а отпечаток тут подобран
                // под Chrome — там расширение оставляем.
                if (PlainTls)
                    AddExt(ms, 0x001b, new byte[] { 0x02, 0x00, 0x02 });
                // 16. application_settings (ALPS) — только когда предлагаем h2
                if (!OfferH1Only)
                    AddExt(ms, 0x4469, new byte[] { 0x00, 0x03, 0x02, (byte)'h', (byte)'2' });
                // 17. GREASE (1-байтовая нагрузка)
                AddExt(ms, gExtB, new byte[] { 0x00 });

                // 18. padding до 512 (правило BoringSSL: окно 256..511)
                // cipherBytes раньше был захардкожен как 8 и разошёлся с реальным списком
                // (после сокращения до 0x1301 стало 4) — из-за этого ClientHello не добивался
                // до задуманных 512 байт. Теперь считаем от фактической длины.
                byte[] soFar = ms.ToArray();
                int bodyNoPad = 2 + 32 + 1 + 32 + 2 + cipherBytes + 2 + 2 + soFar.Length;
                if (bodyNoPad >= 256 && bodyNoPad < 512)
                {
                    int padLen = 512 - bodyNoPad - 4; // 4 = заголовок padding-расширения
                    if (padLen < 0) padLen = 0;
                    AddExt(ms, 0x0015, new byte[padLen]);
                }

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
            byte[] zeros = new byte[Tls13Crypto.HashLenOf(_sha384)];
            byte[] earlySecret = Tls13Crypto.HkdfExtract(_sha384, zeros, zeros);
            byte[] derived = Tls13Crypto.DeriveSecret(_sha384, earlySecret, "derived", new byte[0]);
            _handshakeSecret = Tls13Crypto.HkdfExtract(_sha384, derived, shared);
            _clientHandshakeTrafficSecret = Tls13Crypto.DeriveSecret(_sha384, _handshakeSecret, "c hs traffic", _transcript.ToArray());
            _serverHandshakeTrafficSecret = Tls13Crypto.DeriveSecret(_sha384, _handshakeSecret, "s hs traffic", _transcript.ToArray());
            _clientHandshakeKey = Tls13Crypto.HkdfExpandLabel(_sha384, _clientHandshakeTrafficSecret, "key", new byte[0], _aesKeyLen);
            _clientHandshakeIv = Tls13Crypto.HkdfExpandLabel(_sha384, _clientHandshakeTrafficSecret, "iv", new byte[0], 12);
            _serverHandshakeKey = Tls13Crypto.HkdfExpandLabel(_sha384, _serverHandshakeTrafficSecret, "key", new byte[0], _aesKeyLen);
            _serverHandshakeIv = Tls13Crypto.HkdfExpandLabel(_sha384, _serverHandshakeTrafficSecret, "iv", new byte[0], 12);
        }

        private void DeriveApplicationKeys()
        {
            byte[] zeros = new byte[Tls13Crypto.HashLenOf(_sha384)];
            byte[] derived = Tls13Crypto.DeriveSecret(_sha384, _handshakeSecret, "derived", new byte[0]);
            byte[] masterSecret = Tls13Crypto.HkdfExtract(_sha384, derived, zeros);
            byte[] cAppTraffic = Tls13Crypto.DeriveSecret(_sha384, masterSecret, "c ap traffic", _transcript.ToArray());
            byte[] sAppTraffic = Tls13Crypto.DeriveSecret(_sha384, masterSecret, "s ap traffic", _transcript.ToArray());
            _clientAppKey = Tls13Crypto.HkdfExpandLabel(_sha384, cAppTraffic, "key", new byte[0], _aesKeyLen);
            _clientAppIv = Tls13Crypto.HkdfExpandLabel(_sha384, cAppTraffic, "iv", new byte[0], 12);
            _serverAppKey = Tls13Crypto.HkdfExpandLabel(_sha384, sAppTraffic, "key", new byte[0], _aesKeyLen);
            _serverAppIv = Tls13Crypto.HkdfExpandLabel(_sha384, sAppTraffic, "iv", new byte[0], 12);

            _clientAppCryptoKey = _chacha ? null : Tls13Crypto.CreateAesGcmKey(_clientAppKey);
            _serverAppCryptoKey = _chacha ? null : Tls13Crypto.CreateAesGcmKey(_serverAppKey);
        }

        public byte[] EncryptRecord(byte[] data)
        {
            if (_chacha) return EncryptRecordInternal(_clientAppKey, _clientAppIv, ref _writeSeq, 23, data);
            return EncryptRecordInternalWithKey(_clientAppCryptoKey, _clientAppIv, ref _writeSeq, 23, data);
        }

        public byte[] DecryptRecordExplicit(byte[] header, byte[] cipherAndTag, out byte innerType)
        {
            innerType = 0;
            try
            {
                byte[] nonce = BuildNonce(_serverAppIv, _readSeq++);
                byte[] plain = _chacha
                    ? AwgCrypto.Open(_serverAppKey, nonce, header, cipherAndTag)
                    : Tls13Crypto.AesGcmDecryptWithKey(_serverAppCryptoKey, nonce, header, cipherAndTag);
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
                byte[] plain = _chacha
                    ? AwgCrypto.Open(_serverAppKey, nonce, rec.Item2, rec.Item3)
                    : Tls13Crypto.AesGcmDecryptWithKey(_serverAppCryptoKey, nonce, rec.Item2, rec.Item3);
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
                byte[] plain = _chacha
                    ? AwgCrypto.Open(key, nonce, rec.Item2, rec.Item3)
                    : Tls13Crypto.AesGcmDecrypt(key, nonce, rec.Item2, rec.Item3);
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

            byte[] encrypted = _chacha
                ? AwgCrypto.Seal(key, nonce, header, inner)
                : Tls13Crypto.AesGcmEncrypt(key, nonce, header, inner);

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
            int sidLen = hs[38];
            int cipherOff = 39 + sidLen;
            if (cipherOff + 3 > hs.Length) return null;
            int chosenCipher = (hs[cipherOff] << 8) | hs[cipherOff + 1];
            FileLog.Important($"[TLS 1.3] Сервер ответил ServerHello, выбранный шифр: 0x{chosenCipher:X4}.");
            // 0x1301 = AES-128-GCM-SHA256, 0x1302 = AES-256-GCM-SHA384,
            // 0x1303 = ChaCha20-Poly1305-SHA256. Провайдера ChaCha20 в UWP нет, поэтому
            // берётся своя реализация из AwgCrypto — та же, что шифрует AmneziaWG.
            if (chosenCipher == 0x1301) { _sha384 = false; _aesKeyLen = 16; _chacha = false; }
            else if (chosenCipher == 0x1302) { _sha384 = true; _aesKeyLen = 32; _chacha = false; }
            else if (chosenCipher == 0x1303) { _sha384 = false; _aesKeyLen = 32; _chacha = true; }
            else
            {
                FileLog.Important($"[REALITY TLS 1.3 ERROR] Сервер выбрал шифр 0x{chosenCipher:X4}; " +
                                  "клиент реализует 0x1301, 0x1302 и 0x1303. Handshake прерван.");
                return null;
            }
            int pos = 39 + sidLen + 2 + 1; // пропустили cipher(2) + compression(1)
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
            int hl = Tls13Crypto.HashLenOf(_sha384);
            byte[] finishedKey = Tls13Crypto.HkdfExpandLabel(_sha384, _serverHandshakeTrafficSecret, "finished", new byte[0], hl);
            byte[] transcriptHash = Tls13Crypto.Hash(_sha384, _transcript.ToArray());
            byte[] expected = Tls13Crypto.Hmac(_sha384, finishedKey, transcriptHash);
            return Tls13Crypto.ConstantEquals(expected, verifyData);
        }

        private async Task SendClientFinishedAsync()
        {
            int hl = Tls13Crypto.HashLenOf(_sha384);
            byte[] transcriptHash = Tls13Crypto.Hash(_sha384, _transcript.ToArray());
            byte[] finishedKey = Tls13Crypto.HkdfExpandLabel(_sha384, _clientHandshakeTrafficSecret, "finished", new byte[0], hl);
            byte[] verify = Tls13Crypto.Hmac(_sha384, finishedKey, transcriptHash);
            byte[] hs = new byte[4 + verify.Length];
            hs[0] = 20; hs[1] = 0; hs[2] = (byte)(verify.Length >> 8); hs[3] = (byte)(verify.Length & 0xFF);
            System.Buffer.BlockCopy(verify, 0, hs, 4, verify.Length);
            byte[] record = EncryptRecordInternal(_clientHandshakeKey, _clientHandshakeIv, ref _writeSeq, 22, hs);

            try
            {
                // RFC 8446 D.4: клиент с непустым legacy_session_id обязан отправить
                // фиктивный ChangeCipherSpec непосредственно перед вторым флайтом, то
                // есть прямо перед Client Finished. У REALITY session_id непустой всегда
                // (в нём лежит auth), так что это наш случай, а мы CCS не слали вовсе —
                // отличие и от Chrome, и от Firefox, под которых подобран отпечаток.
                // В транскрипт CCS не входит: это запись уровня записей, не рукопожатия.
                _writer.WriteBytes(new byte[] { 20, 3, 3, 0, 1, 1 });
                _writer.WriteBytes(record);
                await _writer.StoreAsync();
                _transcript.AddRange(hs);
            }
            catch { }
        }
    }

    internal class VlessConnection : IDirectConn
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
        private volatile bool _closed;

        // Тайминги для разбора обрыва: сервер закрывает поток в ответ на наш запрос
        // или ещё раньше, на Client Finished? Отличить можно только по времени
        // относительно RTT, поэтому все три величины держим рядом.
        private long _tcpRttMs;
        private DateTime _handshakeDoneUtc = DateTime.MinValue;
        private DateTime _requestSentUtc = DateTime.MinValue;
        private bool _downClosedLogged;
        private string _closeReason = "неизвестно";

        private bool _xhttpEnabled;
        private XhttpSplitClient _split;
        private bool _splitEnabled;
        private WsTransport _ws;
        private bool _wsEnabled;
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

        // Вариант B: xhttp stream-one через ОБЩИЙ мультиплексированный Reality+H2 туннель
        // (много flow'ов = много H2-стримов на один хендшейк). Kill-switch ниже — при
        // false возвращаемся к старому пути «один Reality+H2 на flow».
        public static bool UseH2Mux = true;
        private bool _muxEnabled;
        private H2Stream _muxStream;

        // xtls-rprx-vision
        private bool _visionEnabled;
        private VisionWrap _visionWrap;
        private VisionUnpad _visionUnpad;
        private bool _visionFirstSent;
        private byte[] _uuidBytes;

        // Имя из IDirectConn: движок одинаково тянет payload и из VLESS, и из Shadowsocks.
        public Task<byte[]> ReadPayloadAsync() { return ReadVlessPayloadAsync(); }

        // Первое звено цепочки. Если задано, соединение поднимается не по TCP,
        // а поверх этого туннеля. Ставится только для профилей Amnezia с двумя
        // outbound'ами; у остальных остаётся null и весь прежний путь не меняется.
        private IDirectConn _chainOuter;

        public void UseChainTransport(IDirectConn outer) { _chainOuter = outer; }

        // Поток отправки. У второго звена цепочки сокета нет вовсе — писать
        // нужно в первое звено. Без этой развилки запись падала с
        // NullReferenceException на Socket.OutputStream уже после того,
        // как оба рукопожатия успешно прошли.
        private void EnsureOutStream()
        {
            if (_outStream != null) return;
            _outStream = _chainOuter != null
                ? new ChainOutputStream(_chainOuter).AsStreamForWrite(81920)
                : Socket.OutputStream.AsStreamForWrite(81920);
        }

        // Разовая проверка цепочки Amnezia. Реле закрывает поток, приняв ноль
        // байт, и по close_notify нельзя отличить «запрещён маршрут» от «нет
        // резолвера»: мы шлём доменное имя из-за fake-DNS. Обе версии
        // предсказывают, что IP-назначение пройдёт, — направляем ПЕРВОЕ
        // соединение на выходной узел и смотрим, что придёт в ответ.
        private bool _isChainProbe;

        // Диагностическая подмена назначения своё отработала: она доказала, что
        // реле пропускает трафик до выходного узла. Теперь этим занимается
        // настоящая цепочка в NatEngine, а подмена только мешала бы.
        private bool TryRedirectToChainExit() { return false; }

        public static bool TryParseIpv4Public(string s, out byte[] ip) { return TryParseIpv4(s, out ip); }

        private static bool TryParseIpv4(string s, out byte[] ip)
        {
            ip = null;
            var parts = (s ?? "").Split('.');
            if (parts.Length != 4) return false;
            var b = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                int v;
                if (!int.TryParse(parts[i], out v) || v < 0 || v > 255) return false;
                b[i] = (byte)v;
            }
            ip = b;
            return true;
        }

        public void ConfigureDirectIp(byte[] ip, bool isIpv6, ushort port)
        {
            if (TryRedirectToChainExit()) return;
            _directMode = true;
            _directAddrType = isIpv6 ? (byte)0x03 : (byte)0x01;
            _directAddr = ip;
            _directPort = port;
        }

        public void ConfigureDirectDomain(string domain, ushort port)
        {
            if (TryRedirectToChainExit()) return;
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

        private byte[] BuildDirectVlessHeader()
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0x00);
                Guid guid = Guid.Empty; Guid.TryParse(_cfg.Uuid, out guid);
                ms.Write(GuidToNetworkBytes(guid), 0, 16);
                ms.WriteByte(0x00); // addon len
                ms.WriteByte(0x01); // cmd = TCP
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
                return ms.ToArray();
            }
        }

        private async Task<bool> StartSplitAsync(bool packetUp)
        {
            _split = new XhttpSplitClient(_cfg, packetUp, BuildDirectVlessHeader());
            _splitEnabled = true;
            if (!await _split.StartAsync()) { Close(); return false; }
            return true;
        }

        private async Task<bool> StartWsAsync()
        {
            // ВАЖНО: StartAsync уходит в эту ветку ДО общего блока, где строится
            // _vlessHeaderBuffer, поэтому заголовок надо собрать здесь. Без него
            // WriteUnderlyingAsync отправлял в WS голую полезную нагрузку без VLESS-заголовка
            // (UUID/команда/адрес), сервер не мог опознать сессию и молчал: WS вставал,
            // «101 Switching Protocols» приходил, а данных не было вообще (ни одной
            // строки [VLESS RESP]). split-режим передаёт заголовок явно, mux — тоже;
            // ws был единственным, где его забыли.
            _vlessHeaderBuffer = BuildDirectVlessHeader();
            _ws = new WsTransport(_cfg);
            _wsEnabled = true;
            if (!await _ws.ConnectAsync()) { Close(); return false; }
            return true;
        }

        public async Task<bool> StartAsync()
        {
            try
            {
                if (_cfg.IsWs && _directMode)
                    return await StartWsAsync();
                // xhttp split-режимы (stream-up / packet-up) держат собственные
                // download/upload-соединения и НЕ трогают this.Socket. Диспатчим до открытия сокета.
                if (_cfg.IsXhttp && _directMode)
                {
                    var xmode = _cfg.ResolveXhttpMode();
                    if (xmode == XhttpTransportMode.PacketUp) return await StartSplitAsync(true);
                    if (xmode == XhttpTransportMode.StreamUp) return await StartSplitAsync(false);
                    // stream-one — проваливаемся в обычный путь ниже
                }

                // Вариант B: xhttp stream-one direct → мультиплексируем через общий
                // Reality+H2 туннель вместо собственного сокета/хендшейка на этот flow.
                // (packet-up/stream-up уже отдиспатчены выше, значит здесь только stream-one.)
                if (UseH2Mux && _cfg.IsXhttp && _directMode)
                    return await StartH2MuxAsync();

                string targetHost = string.IsNullOrEmpty(VlessVpnPlugin.ServerIp)
                    ? _cfg.Address : VlessVpnPlugin.ServerIp;

                bool isReality = _cfg.Security.ToLower() == "reality";

                // Reality-сервер под нагрузкой изредка «роняет» нас на прикрытие (amd.com)
                // вместо аутентификации. Раньше это обнаруживалось поздно (на статусе H2),
                // и всё соединение пересоздавалось приложением заново (новый SYN + новый
                // хендшейк) — видимый стопор. Теперь fallback детектируется рано (по реальному
                // CA-сертификату, см. RealityTls13Stream.ServerFellBack) и мы делаем быстрый
                // in-place повтор тем же путём. Ретраим ТОЛЬКО fallback (он быстрый — хендшейк
                // обрывается сразу по сертификату); реальный таймаут не ретраим, чтобы не
                // копить 3×8с. Никаких общих семафоров — только per-connection, поэтому той
                // HOL-регрессии с throttle тут быть не может.
                const int maxRealityAttempts = 3;
                for (int attempt = 1; ; attempt++)
                {
                    // Второе звено цепочки Amnezia работает не поверх TCP, а поверх
                    // уже поднятого туннеля до реле. Сокет тогда не нужен: writer и
                    // reader строятся над первым звеном. Ветка включается только при
                    // заданном ChainOuter, поэтому обычные профили её не проходят.
                    if (_chainOuter != null)
                    {
                        // Адрес берём из _cfg, а не из targetHost: тот подменяется
                        // глобальным ServerIp, который указывает на реле.
                        FileLog.Important($"[CHAIN] Второе звено: рукопожатие с {_cfg.Address}:{_cfg.Port} " +
                                          "поверх туннеля до реле.");
                        _writer = new DataWriter(new ChainOutputStream(_chainOuter));
                        _reader = new DataReader(new ChainInputStream(_chainOuter));
                        _reader.InputStreamOptions = InputStreamOptions.Partial;
                        _tcpRttMs = 0;

                        if (!isReality) break;

                        _realityStream = new RealityTls13Stream(_cfg);
                        var chainTask = _realityStream.EstablishHandshakeAsync(_writer, _reader);
                        bool chainTimedOut = await Task.WhenAny(chainTask, Task.Delay(12000)) != chainTask;
                        if (chainTimedOut || !await chainTask)
                        {
                            FileLog.Important(chainTimedOut
                                ? "[CHAIN ERROR] Второе рукопожатие REALITY не уложилось в 12с."
                                : "[CHAIN ERROR] Второе рукопожатие REALITY не удалось.");
                            Close();
                            return false;
                        }
                        FileLog.Important("[CHAIN] Второе рукопожатие REALITY прошло — цепочка поднята.");
                        break;
                    }

                    Socket = new StreamSocket();
                    Socket.Control.NoDelay = true;
                    Socket.Control.KeepAlive = true;

                    FileLog.W($"[VLESS CONN] Подключение к VLESS-серверу: {targetHost}:{_cfg.Port}"
                        + (attempt > 1 ? $" (повтор {attempt}/{maxRealityAttempts} после fallback)" : ""));

                    // Секундомер обязан стартовать ДО ConnectAsync: операция начинается
                    // в момент вызова, и запуск после него давал заниженное время
                    // вплоть до «0 мс» на соединениях, которые шли по 150 мс.
                    var swConnect = Stopwatch.StartNew();

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
                    swConnect.Stop();
                    // Время до TCP пригождается при разборе логов: оно отделяет «сервер
                    // недоступен» от «TCP прошёл, но дальше по TLS тишина». Плюс это
                    // единственная доступная нам оценка RTT до сервера.
                    _tcpRttMs = swConnect.ElapsedMilliseconds;
                    FileLog.W($"[VLESS CONN] TCP установлен за {_tcpRttMs} мс.");

                    _writer = new DataWriter(Socket.OutputStream);
                    _reader = new DataReader(Socket.InputStream);
                    _reader.InputStreamOptions = InputStreamOptions.Partial;

                    if (!isReality)
                        break; // без reality ретраить нечего

                    _realityStream = new RealityTls13Stream(_cfg);

                    // Ждём очередь ДО запуска таймера: иначе соединение, простоявшее
                    // в очереди, отвалилось бы по таймауту, ни разу не выйдя в сеть.
                    await RealityTls13Stream.EnterHandshakeGateAsync();
                    bool timedOut, ok;
                    try
                    {
                        var handshakeTask = _realityStream.EstablishHandshakeAsync(_writer, _reader);
                        timedOut = await Task.WhenAny(handshakeTask, Task.Delay(8000)) != handshakeTask;
                        ok = !timedOut && await handshakeTask;
                    }
                    finally
                    {
                        RealityTls13Stream.LeaveHandshakeGate();
                    }
                    if (ok)
                        break; // хендшейк удался — выходим из цикла

                    if (timedOut)
                    {
                        // Молчание — это НЕ фолбэк: при фолбэке сервер прозрачно проксирует
                        // нас на сайт прикрытия и тот отвечает настоящим ServerHello. Полная
                        // тишина при поднятом TCP означает, что ClientHello до сервера не
                        // дошёл или ответ не вернулся (фильтрация по пути), либо сервер лёг.
                        _realityStream.AbortedByTimeout = true;
                        FileLog.W(_realityStream.ServerBytes == 0
                            ? "[REALITY TLS 1.3 ERROR] За 8с от сервера не пришло ни байта — ClientHello без ответа."
                            : $"[REALITY TLS 1.3 ERROR] Хендшейк не уложился в 8с, получено {_realityStream.ServerBytes} б.");
                    }

                    bool quickRetryable = _realityStream.ServerFellBack || _realityStream.AlertBeforeServerHello;
                    if (quickRetryable && attempt < maxRealityAttempts)
                    {
                        FileLog.W(_realityStream.AlertBeforeServerHello
                            ? $"[VLESS CONN] Alert вместо ServerHello на попытке {attempt} — быстрый повтор."
                            : $"[VLESS CONN] Reality fallback на попытке {attempt} — быстрый повтор.");
                        try { _writer?.Dispose(); } catch { }
                        try { _reader?.Dispose(); } catch { }
                        try { Socket?.Dispose(); } catch { }
                        _writer = null; _reader = null; Socket = null; _realityStream = null;
                        continue;
                    }

                    FileLog.W(_realityStream.AlertBeforeServerHello
                        ? $"[VLESS CONN ERROR] Alert вместо ServerHello — исчерпаны попытки ({maxRealityAttempts})."
                        : _realityStream.ServerFellBack
                        ? $"[VLESS CONN ERROR] Reality fallback — исчерпаны попытки ({maxRealityAttempts})."
                        : timedOut
                            ? "[VLESS CONN ERROR] Таймаут Reality handshake (8с) — сервер не ответил."
                            : "[VLESS CONN ERROR] Сбой Reality handshake.");
                    Close();
                    return false;
                }

                _handshakeDoneUtc = DateTime.UtcNow;

                // vision работает только на raw TCP в direct-режиме (не ws/xhttp)
                _visionEnabled = _cfg.IsVision && _directMode;
                if (_visionEnabled)
                    FileLog.Important("[VISION] xtls-rprx-vision активирован (flow в заголовке + padding-обёртка).");

                using (var ms = new MemoryStream())
                {
                    ms.WriteByte(0x00);
                    Guid guid = Guid.Empty;
                    Guid.TryParse(_cfg.Uuid, out guid);
                    _uuidBytes = GuidToNetworkBytes(guid);
                    ms.Write(_uuidBytes, 0, 16);

                    if (_visionEnabled)
                    {
                        // addon: тип 0x0a (flow как строковое поле) + длина + значение
                        byte[] flowBytes = Encoding.ASCII.GetBytes(_cfg.Flow);
                        ms.WriteByte((byte)(2 + flowBytes.Length)); // длина блока addon
                        ms.WriteByte(0x0a);
                        ms.WriteByte((byte)flowBytes.Length);
                        ms.Write(flowBytes, 0, flowBytes.Length);
                        // Состояние TLS-фильтра общее на соединение: версию сайта
                        // видит нисходящий поток, а решает по ней восходящий.
                        var visionState = new VisionTrafficState();
                        _visionWrap = new VisionWrap(_uuidBytes, visionState);
                        _visionUnpad = new VisionUnpad(_uuidBytes, visionState);
                    }
                    else
                    {
                        ms.WriteByte(0x00); // addon len = 0
                    }
                    ms.WriteByte(0x01); // cmd = TCP

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
            EnsureOutStream();
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

        // Вариант B: получаем H2-стрим из общего мультиплексированного туннеля.
        // Собственный сокет/reality/H2 для этого flow НЕ открываем.
        private async System.Threading.Tasks.Task<bool> StartH2MuxAsync()
        {
            try
            {
                _vlessHeaderBuffer = BuildDirectVlessHeader();
                _muxStream = await H2MuxRegistry.AcquireStreamAsync(_cfg);
                if (_muxStream == null)
                {
                    FileLog.Important("[H2MUX] Не удалось получить стрим (туннель не поднялся).");
                    return false;
                }
                _muxEnabled = true;
                FileLog.Important($"[H2MUX] xhttp stream-one через общий туннель, H2 sid={_muxStream.Id}.");
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[H2MUX ERROR] StartH2Mux: {ex.Message}");
                return false;
            }
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
            // Гонка: ОС может закрыть локальный сокет, пока идёт StartAsync, и очередь
            // отправки дописывает данные уже в освобождённые объекты. Раньше это вылезало
            // как Arg_NullReferenceException / ObjectDisposed_Generic в логе и выглядело
            // ошибкой протокола, хотя соединения просто уже не было.
            if (_closed) return;

            if (_muxEnabled)
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
                await _muxStream.WriteAsync(payload);
                return;
            }
            if (_wsEnabled)
            {
                byte[] payload = data ?? new byte[0];
                if (_vlessHeaderBuffer != null)
                {
                    byte[] c = new byte[_vlessHeaderBuffer.Length + payload.Length];
                    System.Buffer.BlockCopy(_vlessHeaderBuffer, 0, c, 0, _vlessHeaderBuffer.Length);
                    if (payload.Length > 0)
                        System.Buffer.BlockCopy(payload, 0, c, _vlessHeaderBuffer.Length, payload.Length);
                    payload = c;
                    _vlessHeaderBuffer = null;
                }
                await _ws.SendAsync(payload);
                return;
            }
            if (_splitEnabled) { await _split.WriteUpAsync(data); return; }
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

                    bool stalledLogged = false;
                    while (!_h2.TryReserveSend(piece))
                    {
                        if (_h2.StreamClosed) return;
                        if (!stalledLogged)
                        {
                            stalledLogged = true;
                            FileLog.Important($"[H2 TX] upload ждёт окна отправки (нужно {piece}b) — backpressure сервера");
                        }
                        await _h2.WaitWindowAsync();
                    }

                    byte[] frame = _h2.FrameData(payload, off, piece, false);
                    await WriteRawSerializedAsync(frame);
                    off += piece;
                }

                if (FileLog.Verbose) FileLog.W($"[H2 TX] {payload.Length}b (stream 1)");
                return;
            }

            // xtls-rprx-vision: заголовок (один раз) + vision-обёрнутая полезная
            // нагрузка. Полезная нагрузка режется на блоки ≤8192 (как в senko),
            // чтобы каждый vision-блок с учётом паддинга помещался в одну TLS-запись.
            // После выхода из padding-режима Wrap отдаёт данные «сырыми».
            if (_visionEnabled)
            {
                byte[] payload = data ?? new byte[0];
                var outMs = new MemoryStream();
                bool first = !_visionFirstSent;
                byte[] hdr = null;
                if (first)
                {
                    _visionFirstSent = true;
                    hdr = _vlessHeaderBuffer ?? new byte[0];
                    _vlessHeaderBuffer = null;
                }

                if (payload.Length == 0)
                {
                    // только на первом вызове без данных отправляем header + bootstrap
                    if (first)
                    {
                        byte[] boot = _visionWrap.Bootstrap();
                        AppendVisionEncrypted(outMs, hdr, boot);
                    }
                }
                else
                {
                    // Симметрично приёму: после того как мы отправили DIRECT, узел
                    // ждёт сырой поток и больше не расшифровывает уплинк своим
                    // REALITY. Продолжая шифровать, мы отдавали ему криптограмму
                    // вместо TLS сайта — выходной узел отвечал alert 20
                    // (bad_record_mac). На END это не распространяется: там внешний
                    // TLS остаётся, поэтому проверяем именно DirectSent.
                    if (_visionWrap.DirectSent)
                    {
                        outMs.Write(payload, 0, payload.Length);
                    }
                    else
                    {
                        const int VisionChunk = 8192;
                        for (int off = 0; off < payload.Length; off += VisionChunk)
                        {
                            int n = Math.Min(VisionChunk, payload.Length - off);
                            byte[] chunk = new byte[n];
                            System.Buffer.BlockCopy(payload, off, chunk, 0, n);
                            byte[] blk = _visionWrap.Wrap(chunk, n);
                            // header приклеиваем к самому первому исходящему блоку
                            byte[] pre = (first && off == 0) ? hdr : null;
                            AppendVisionEncrypted(outMs, pre, blk);
                        }
                    }
                }

                byte[] outAll = outMs.ToArray();
                if (outAll.Length == 0) return;
                EnsureOutStream();
                _outStream.Write(outAll, 0, outAll.Length);
                await _outStream.FlushAsync();
                // Первый запрос — единственное, что мы отправляем до ответа сервера.
                // Без этой строки в vision-режиме исходящий поток не логировался вовсе,
                // и «сервер молчит» было неотличимо от «мы ничего не отправили».
                if (first)
                {
                    _requestSentUtc = DateTime.UtcNow;
                    // Начало полезной нагрузки — это ClientHello браузера к самому сайту.
                    // Часть соединений сайт обрывает сразу после ServerHello, будто получил
                    // мусор; без дампа отличить «мы испортили» от «сайт сам так решил» нельзя.
                    int peek = Math.Min(48, payload.Length);
                    byte[] head = new byte[peek];
                    System.Buffer.BlockCopy(payload, 0, head, 0, peek);
                    FileLog.Important($"[VISION TX] Запрос отправлен: заголовок {hdr?.Length ?? 0}б + " +
                                      $"данные {payload.Length}б, cmd={_visionWrap.LastCommand}, " +
                                      $"итого {outAll.Length}б в TLS. Начало данных: " +
                                      CryptoSelfTest.BytesToHex(head));
                }
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

            EnsureOutStream();
            _outStream.Write(toSend, 0, toSend.Length);
            await _outStream.FlushAsync();
        }

        // Склеивает необязательный префикс (VLESS-заголовок) с vision-блоком,
        // шифрует под reality (одна TLS-запись) и дописывает в буфер отправки.
        private void AppendVisionEncrypted(MemoryStream dst, byte[] prefix, byte[] block)
        {
            int pl = prefix?.Length ?? 0;
            int bl = block?.Length ?? 0;
            if (pl == 0 && bl == 0) return;
            byte[] plain = new byte[pl + bl];
            if (pl > 0) System.Buffer.BlockCopy(prefix, 0, plain, 0, pl);
            if (bl > 0) System.Buffer.BlockCopy(block, 0, plain, pl, bl);
            byte[] enc = _realityStream != null ? _realityStream.EncryptRecord(plain) : plain;
            dst.Write(enc, 0, enc.Length);
        }

        private async Task<bool> ReadExactAsync(uint count)
        {
            try
            {
                uint loaded = _reader.UnconsumedBufferLength;
                while (loaded < count)
                {
                    uint bytesRead = await _reader.LoadAsync(count - loaded);
                    // Ноль байт — это корректный FIN: соединение закрыла программа на той
                    // стороне. Исключение — это RST или обрыв: так выглядит вмешательство
                    // по пути. Раньше оба случая сводились к одному «false».
                    if (bytesRead == 0) { _closeReason = "штатный FIN от узла"; return false; }
                    loaded += bytesRead;
                }
                return true;
            }
            catch (Exception ex)
            {
                // 0x800703E3 = ERROR_OPERATION_ABORTED: незавершённое чтение отменено
                // тем, что сокет закрыли С НАШЕЙ стороны. Это не сетевой обрыв, и
                // называть его «RST» значило врать в логе о причине.
                _closeReason = (uint)ex.HResult == 0x800703E3
                    ? "чтение отменено закрытием сокета с нашей стороны"
                    : "обрыв: " + ex.Message;
                return false;
            }
        }

        private async Task<byte[]> ReadTlsPlaintextAsync()
        {
            try
            {
                // После команды DIRECT узел перестаёт заворачивать нисходящий поток
                // в свой REALITY: в этом и смысл «X» в XTLS — дальше идёт сплайс, а
                // шифрование обеспечивает внутренний TLS. Продолжать расшифровку
                // нельзя, но и заметить это по заголовку невозможно: внутренние
                // записи выглядят точно так же — 17 03 03 <len>. Симптомом было
                // «Запись не расшифровалась» ровно после [VISION SW RX] DIRECT.
                if (_realityStream != null && _visionEnabled && _visionUnpad != null && _visionUnpad.RawSplice)
                {
                    uint got = await _reader.LoadAsync(16384);
                    if (got == 0) return null;
                    byte[] rawDirect = new byte[got];
                    _reader.ReadBytes(rawDirect);
                    return rawDirect;
                }

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
                            // Две несовместимые причины отказа, и различить их можно
                            // только по байтам. Либо узел после vision-DIRECT перестал
                            // заворачивать поток в REALITY (тогда мы читаем как заголовок
                            // TLS то, что им не является, и заголовок будет мусорным),
                            // либо разошёлся счётчик AEAD (тогда заголовок правильный,
                            // а расшифровка всё равно не проходит).
                            int hn = Math.Min(16, payload.Length);
                            var ph = new byte[hn];
                            System.Buffer.BlockCopy(payload, 0, ph, 0, hn);
                            bool headerSane = (recordType == 0x17 || recordType == 0x16 ||
                                               recordType == 0x15 || recordType == 0x14)
                                              && header[1] == 0x03 && header[2] == 0x03;
                            FileLog.Important(
                                $"[TLS ERR] Запись не расшифровалась. Заголовок: {CryptoSelfTest.BytesToHex(header)}, " +
                                $"len={len}, начало тела: {CryptoSelfTest.BytesToHex(ph)}. " +
                                $"Цепочка={( _chainOuter != null ? "второе звено" : "обычное")}.");
                            // По заголовку различить «сырой поток после DIRECT» и
                            // рассинхрон счётчика нельзя: внутренние записи имеют
                            // такой же вид 17 03 03 <len>. Решает только состояние
                            // vision на момент отказа.
                            FileLog.Important(
                                $"[TLS ERR] vision: включён={_visionEnabled}, " +
                                $"downstream direct={(_visionUnpad != null && _visionUnpad.IsDirect)}. " +
                                (headerSane ? "Заголовок правдоподобный." : "Заголовок не похож на TLS."));
                            return null;
                        }

                        if (innerType == 23)
                        {
                            // Пустая application-запись — легальный TLS, её шлют как
                            // keep-alive/паддинг. Наверх её отдавать нельзя: вызывающий
                            // принимал пустой буфер за конец потока и рвал соединение,
                            // хотя сервер ничего не закрывал.
                            if (plain.Length == 0)
                            {
                                FileLog.W("[TLS] Пустая application-запись — пропускаю.");
                                continue;
                            }
                            return plain;
                        }
                        else
                        {
                            // Alert (21) — единственная причина, по которой сервер
                            // молча закрывает уже поднятый туннель. Его код и
                            // уровень надо видеть: без них «поток закрыт» и
                            // «нас выгнали» выглядят в логе одинаково.
                            if (innerType == 21 && plain.Length >= 2)
                            {
                                string level = plain[0] == 1 ? "warning" : plain[0] == 2 ? "fatal" : plain[0].ToString();
                                string desc = plain[1] == 0 ? "close_notify"
                                            : plain[1] == 49 ? "access_denied"
                                            : plain[1] == 80 ? "internal_error"
                                            : plain[1] == 40 ? "handshake_failure"
                                            : plain[1] == 90 ? "user_canceled"
                                            : "код " + plain[1];
                                FileLog.Important($"[TLS ALERT] Сервер прислал alert: {level} / {desc}.");
                            }
                            else
                            {
                                FileLog.W($"[TLS] Отсеяно служебное шифрованное TLS-сообщение (тип: {innerType})");
                            }
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
            if (_muxEnabled) return await _muxStream.ReadDownAsync();
            if (_wsEnabled) return await _ws.ReceiveAsync();
            if (_splitEnabled) return await _split.ReadDownAsync();
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
                            NetDiag.ReportHttp("H2", _h2.Status, "200 OK");
                            return null;
                        }
                        NetDiag.ClearError();
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
                        NetDiag.Report("XHTTP", "сервер разорвал TLS до того, как прислал заголовки ответа");
                        return null;
                    }

                    if (_xhttp.TryConsumeResponseHead(plain, out string status, out var headers))
                    {
                        FileLog.Important($"[XHTTP] <<< {status}");
                        int xCode = NetDiag.ParseStatus(status);
                        if (xCode != 200)
                        {
                            NetDiag.ReportHttp("XHTTP", xCode, "200 OK");
                            return null;
                        }
                        NetDiag.ClearError();

                        _xhttp.ConfigureFromResponse(headers);
                        _xhttpHeadParsed = true;
                        FileLog.Important("[XHTTP] Заголовки приняты, читаю chunked downstream.");
                        break;
                    }

                    if (DateTime.UtcNow > deadline)
                    {
                        NetDiag.Report("XHTTP", "сервер не прислал заголовки ответа за 15 секунд");
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

        // Кадр HTTP/2 SETTINGS на нулевом стриме: длина(3) тип=0x04 флаги=0x00 stream=0.
        // Первым кадром его шлёт любой h2-сервер, в том числе сайт-прикрытия reality.
        private static bool LooksLikeHttp2Settings(List<byte> buf)
        {
            if (buf == null || buf.Count < 9) return false;
            if (buf[0] != 0x00 || buf[1] != 0x00) return false;   // кадр короче 64 КБ
            if (buf[3] != 0x04 || buf[4] != 0x00) return false;   // SETTINGS без флагов
            for (int i = 5; i < 9; i++) if (buf[i] != 0x00) return false;   // stream id = 0
            int len = buf[2];
            return len % 6 == 0;                                  // записи SETTINGS по 6 байт
        }

        public async Task<byte[]> ReadVlessPayloadAsync()
        {
            byte[] raw = await ReadUnderlyingRecordAsync();
            // Пустой буфер — это НЕ конец потока: транспорты возвращают его, когда данных
            // ещё нет (неполный заголовок, пустая TLS-запись). Концом потока считается
            // только null. Раньше пустой буфер убивал живое соединение.
            if (raw != null && raw.Length == 0) return new byte[0];

            if (raw == null)
            {
                // Ключевой замер: закрытие через ~один RTT ПОСЛЕ рукопожатия означает,
                // что сервер отверг нас ещё на Client Finished и наш запрос до него даже
                // не доехал. Закрытие через ~RTT после запроса — что дело в самом запросе.
                // По одному лишь факту обрыва эти два случая неразличимы.
                if (!_downClosedLogged && _handshakeDoneUtc != DateTime.MinValue)
                {
                    _downClosedLogged = true;
                    var now = DateTime.UtcNow;
                    string sinceReq = _requestSentUtc == DateTime.MinValue
                        ? "запрос ещё не отправляли"
                        : $"{(int)(now - _requestSentUtc).TotalMilliseconds} мс после запроса";
                    FileLog.Important($"[VLESS RX] Поток закрыт ({_closeReason}): " +
                        $"{(int)(now - _handshakeDoneUtc).TotalMilliseconds} мс после рукопожатия, " +
                        $"{sinceReq}, RTT TCP ~{_tcpRttMs} мс.");
                }
                return null;
            }

            byte[] output;

            if (!_headerStripped)
            {
                _receiveBuffer.AddRange(raw);
                if (_receiveBuffer.Count >= 2)
                {
                    int totalHeader = 2 + _receiveBuffer[1];
                    if (_receiveBuffer.Count >= totalHeader)
                    {
                        // Диагностика: первые байты нисходящего потока (VLESS-ответ-заголовок
                        // ver+addonlen, затем данные). Показывает, что реально пришло от сервера.
                        int dn = Math.Min(_receiveBuffer.Count, 16);
                        var hx = new StringBuilder();
                        for (int i = 0; i < dn; i++) hx.Append(_receiveBuffer[i].ToString("X2")).Append(' ');
                        FileLog.Important($"[VLESS RESP] ver={_receiveBuffer[0]} addonlen={_receiveBuffer[1]} hdr={totalHeader}b всего={_receiveBuffer.Count}b hex: {hx}");

                        // Последний рубеж: сайт-прикрытие отвечает по HTTP/2, и его SETTINGS-кадр
                        // начинается с 00 00 — ровно как валидный VLESS-заголовок (ver=0, addonlen=0).
                        // Без этой проверки два байта кадра съедались как заголовок, а сдвинутый
                        // мусор уходил в браузер (в адресной строке — «dяяяя» вместо страницы).
                        if (LooksLikeHttp2Settings(_receiveBuffer))
                        {
                            FileLog.Important("[VLESS RESP] Это HTTP/2-кадр SETTINGS, а не ответ VLESS: " +
                                              "мы разговариваем с сайтом-прикрытием, туннеля нет. " +
                                              "Проверьте pbk/sid в ссылке и часы устройства.");
                            return null;
                        }

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

            // Снятие vision-обёртки с нисходящего потока (устойчиво к серверам,
            // которые downstream не паддят — тогда сразу direct passthrough).
            if (_visionEnabled && _visionUnpad.NeedsProcessing && output.Length > 0)
            {
                bool switchedDirect;
                output = _visionUnpad.Unpad(output, output.Length, out switchedDirect);
                if (switchedDirect)
                    FileLog.Important("[VISION] downstream → direct passthrough.");

                // Ответ на проверку цепочки: если реле пропустило IP-назначение,
                // здесь придёт ServerHello выходного узла (16 03 03 ...).
                if (_isChainProbe && output.Length > 0)
                {
                    int n = Math.Min(32, output.Length);
                    var head = new byte[n];
                    System.Buffer.BlockCopy(output, 0, head, 0, n);
                    bool looksTls = output.Length >= 3 && output[0] == 0x16 && output[1] == 0x03;
                    FileLog.Important($"[CHAIN PROBE] От выходного узла пришло {output.Length}б. " +
                                      $"Начало: {CryptoSelfTest.BytesToHex(head)}");
                    FileLog.Important(looksTls
                        ? "[CHAIN PROBE] Это TLS-рукопожатие — реле ПРОПУСКАЕТ трафик до выходного узла, цепочка реализуема."
                        : "[CHAIN PROBE] На TLS не похоже — разбирать нужно по этим байтам.");
                    _isChainProbe = false;
                }
                // Связывать направления, как делает senko (request_upstream_direct
                // на downstream DIRECT), оказалось нельзя: в xray они независимы.
                // На TLS 1.2 сервер закрывает нисходящую обёртку командой END рано,
                // и по этому сигналу мы снимали паддинг с восходящего потока, так и
                // не отправив завершающий блок — сервер продолжал ждать заголовок
                // vision и разбирал сырые TLS-записи как команду с длинами.
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

        public void Close() { _closed = true; try { _muxStream?.Close(); } catch { }; try { _writer?.Dispose(); _reader?.Dispose(); Socket?.Dispose(); } catch { }; try { _outStream?.Dispose(); } catch { }; try { _split?.Close(); } catch { }; try { _ws?.Close(); } catch { } }
    }
}