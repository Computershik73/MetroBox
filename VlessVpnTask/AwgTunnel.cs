using System;
using System.Text;

namespace VlessVpnTask
{
    // Протокол AmneziaWG = WireGuard (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s) + обфускация.
    // Порт awg_handshake.c / awg_tunnel.c из senko.
    //
    // Отличия от чистого WireGuard — только «снаружи»:
    //   S1..S4  — перед каждым пакетом дописывается случайный префикс заданной длины;
    //   H1..H4  — номер типа пакета берётся из заданного диапазона вместо жёстких 1..4;
    //   Jc/Jmin/Jmax — перед хендшейком отправляется Jc мусорных датаграмм.
    // Сама криптография не меняется, поэтому сервер обычного WireGuard тоже работает
    // (при S=0, H=1..4, Jc=0 — ровно стандартный протокол).
    internal sealed class AwgTunnel
    {
        public const int InitPacketLen = 148;
        public const int RespPacketLen = 92;
        private const int TransportFixed = 32;   // 16 байт заголовка + 16 байт тега
        private const int TagLen = 16;

        private static readonly byte[] NoiseName = Encoding.ASCII.GetBytes("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
        private static readonly byte[] WgIdentifier = Encoding.ASCII.GetBytes("WireGuard v1 zx2c4 Jason@zx2c4.com");
        private static readonly byte[] Mac1Label = Encoding.ASCII.GetBytes("mac1----");

        private readonly AwgConfig _cfg;
        private readonly Random _rnd = new Random();

        private byte[] _chainKey = new byte[32];
        private byte[] _hash = new byte[32];
        private byte[] _ephPrivate, _ephPublic;

        private byte[] _sendKey, _recvKey;
        private uint _senderIndex, _receiverIndex;
        private ulong _sendCounter;
        private ulong _recvCounter;
        private ulong _recvWindow;
        private bool _haveRecvCounter;

        public bool Established { get; private set; }
        public DateTime EstablishedAtUtc { get; private set; }

        public AwgTunnel(AwgConfig cfg) { _cfg = cfg; }

        // ===================== вспомогательное =====================

        private static void WriteLe32(byte[] b, int o, uint v)
        {
            b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24);
        }

        private static uint ReadLe32(byte[] b, int o)
        {
            return (uint)b[o] | ((uint)b[o + 1] << 8) | ((uint)b[o + 2] << 16) | ((uint)b[o + 3] << 24);
        }

        private static void WriteLe64(byte[] b, int o, ulong v)
        {
            for (int i = 0; i < 8; i++) b[o + i] = (byte)(v >> (8 * i));
        }

        private static ulong ReadLe64(byte[] b, int o)
        {
            ulong v = 0;
            for (int i = 0; i < 8; i++) v |= (ulong)b[o + i] << (8 * i);
            return v;
        }

        private static byte[] Slice(byte[] src, int off, int len)
        {
            var d = new byte[len];
            Array.Copy(src, off, d, 0, len);
            return d;
        }

        private uint RandomU32()
        {
            byte[] b = Tls13Crypto.RandomBytes(4);
            uint v = ReadLe32(b, 0);
            return v == 0 ? 1u : v;
        }

        private uint ChooseHeader(int idx)
        {
            uint min = _cfg.HeaderMin[idx], max = _cfg.HeaderMax[idx];
            if (min == max) return min;
            ulong span = (ulong)max - min + 1;
            return min + (uint)(RandomU32() % span);
        }

        // KDF WireGuard: HMAC-BLAKE2s цепочкой, 2 или 3 выхода.
        private static void Kdf2(byte[] chainKey, byte[] input, out byte[] o1, out byte[] o2)
        {
            byte[] temp = AwgCrypto.HmacBlake2s(chainKey, input ?? new byte[0]);
            o1 = AwgCrypto.HmacBlake2s(temp, new byte[] { 1 });
            byte[] part = new byte[33];
            Array.Copy(o1, part, 32); part[32] = 2;
            o2 = AwgCrypto.HmacBlake2s(temp, part);
        }

        private static void Kdf3(byte[] chainKey, byte[] input, out byte[] o1, out byte[] o2, out byte[] o3)
        {
            byte[] temp = AwgCrypto.HmacBlake2s(chainKey, input ?? new byte[0]);
            o1 = AwgCrypto.HmacBlake2s(temp, new byte[] { 1 });
            byte[] part = new byte[33];
            Array.Copy(o1, part, 32); part[32] = 2;
            o2 = AwgCrypto.HmacBlake2s(temp, part);
            Array.Copy(o2, part, 32); part[32] = 3;
            o3 = AwgCrypto.HmacBlake2s(temp, part);
        }

        private void MixHash(byte[] data)
        {
            _hash = AwgCrypto.Hash(_hash, data);
        }

        private byte[] MixKey(byte[] input)
        {
            byte[] newChain, key;
            Kdf2(_chainKey, input, out newChain, out key);
            _chainKey = newChain;
            return key;
        }

        private static byte[] HandshakeNonce(ulong counter)
        {
            byte[] n = new byte[12];
            WriteLe64(n, 4, counter);
            return n;
        }

        // Шифрует и подмешивает шифротекст в транскрипт (hash), как того требует Noise.
        private void SealAndHash(byte[] key, ulong counter, byte[] plain, byte[] dst, int dstOff)
        {
            byte[] aad = _hash;
            AwgCrypto.Seal(key, HandshakeNonce(counter), aad, plain, 0, plain.Length, dst, dstOff);
            MixHash(Slice(dst, dstOff, plain.Length + TagLen));
        }

        private bool OpenAndHash(byte[] key, ulong counter, byte[] src, int off, int ctAndTagLen, byte[] plainOut)
        {
            int plainLen = ctAndTagLen - TagLen;
            if (plainLen < 0) return false;
            byte[] aad = _hash;
            if (!AwgCrypto.Open(key, HandshakeNonce(counter), aad, src, off, plainLen, src, off + plainLen, plainOut, 0))
                return false;
            MixHash(Slice(src, off, ctAndTagLen));
            return true;
        }

        private static byte[] MakeTai64N()
        {
            // TAI64N: 8 байт секунд (со сдвигом TAI) + 4 байта наносекунд, big-endian.
            var now = DateTime.UtcNow;
            var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var delta = now - unixEpoch;
            ulong seconds = (ulong)(long)delta.TotalSeconds + 0x400000000000000aUL;
            uint nanos = (uint)((delta.Ticks % TimeSpan.TicksPerSecond) * 100);

            byte[] o = new byte[12];
            for (int i = 0; i < 8; i++) o[i] = (byte)(seconds >> (56 - 8 * i));
            o[8] = (byte)(nanos >> 24); o[9] = (byte)(nanos >> 16);
            o[10] = (byte)(nanos >> 8); o[11] = (byte)nanos;
            return o;
        }

        // ===================== хендшейк =====================

        // Мусорные датаграммы Jc штук размером Jmin..Jmax — отправляются ПЕРЕД инициацией.
        public byte[][] BuildJunkPackets()
        {
            if (_cfg.Jc == 0) return new byte[0][];
            var list = new byte[_cfg.Jc][];
            uint span = _cfg.Jmax - _cfg.Jmin + 1;
            for (int i = 0; i < _cfg.Jc; i++)
            {
                int len = (int)(_cfg.Jmin + (span > 1 ? RandomU32() % span : 0));
                if (len <= 0) len = 1;
                list[i] = Tls13Crypto.RandomBytes(len);
            }
            return list;
        }

        // Датаграммы по шаблонам I1..I5 (AmneziaWG 1.5+). Уходят ПЕРЕД мусорными Jc:
        // они имитируют начало чужого протокола, поэтому первый пакет сессии не выглядит
        // как WireGuard даже статистически.
        public byte[][] BuildSignaturePackets()
        {
            var list = new System.Collections.Generic.List<byte[]>();
            for (int i = 0; i < 5; i++)
            {
                string spec = _cfg.Signature[i];
                if (string.IsNullOrEmpty(spec)) continue;
                byte[] pkt = ExpandSignature(spec);
                if (pkt != null && pkt.Length > 0) list.Add(pkt);
            }
            return list.ToArray();
        }

        private const string RandomLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // Разворачивает один шаблон. Синтаксис описан в AwgConfig.Signature.
        // Возвращает null, если шаблон битый (проверка формы уже была при разборе конфига).
        private byte[] ExpandSignature(string spec)
        {
            var outBuf = new System.Collections.Generic.List<byte>(256);
            int i = 0;
            while (i < spec.Length)
            {
                if (spec[i] != '<') return null;
                int close = spec.IndexOf('>', i + 1);
                if (close < 0) return null;
                string body = spec.Substring(i + 1, close - i - 1).Trim();
                i = close + 1;

                if (body == "t")
                {
                    uint now = (uint)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
                    outBuf.Add((byte)(now >> 24)); outBuf.Add((byte)(now >> 16));
                    outBuf.Add((byte)(now >> 8)); outBuf.Add((byte)now);
                    continue;
                }

                if (body.StartsWith("b 0x", StringComparison.Ordinal))
                {
                    string hex = body.Substring(4);
                    if ((hex.Length & 1) != 0) return null;
                    for (int h = 0; h < hex.Length; h += 2)
                    {
                        int hi = HexVal(hex[h]), lo = HexVal(hex[h + 1]);
                        if (hi < 0 || lo < 0) return null;
                        outBuf.Add((byte)((hi << 4) | lo));
                    }
                    continue;
                }

                int kind;                                     // 1 = байты, 2 = цифры, 3 = буквы
                string num;
                if (body.StartsWith("rd ", StringComparison.Ordinal)) { kind = 2; num = body.Substring(3); }
                else if (body.StartsWith("rc ", StringComparison.Ordinal)) { kind = 3; num = body.Substring(3); }
                else if (body.StartsWith("r ", StringComparison.Ordinal)) { kind = 1; num = body.Substring(2); }
                else return null;

                int count;
                if (!int.TryParse(num.Trim(), out count) || count < 0 || count > 65507) return null;
                if (count == 0) continue;

                if (kind == 1) outBuf.AddRange(Tls13Crypto.RandomBytes(count));
                else
                {
                    byte[] rnd = Tls13Crypto.RandomBytes(count);
                    for (int k = 0; k < count; k++)
                        outBuf.Add(kind == 2
                            ? (byte)('0' + rnd[k] % 10)
                            : (byte)RandomLetters[rnd[k] % RandomLetters.Length]);
                }
            }
            return outBuf.ToArray();
        }

        private static int HexVal(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        public byte[] BuildInitiation()
        {
            int offset = (int)_cfg.Padding[0];
            byte[] outBuf = new byte[offset + InitPacketLen];
            if (offset > 0) Array.Copy(Tls13Crypto.RandomBytes(offset), outBuf, offset);

            _chainKey = AwgCrypto.Hash(NoiseName);
            _hash = (byte[])_chainKey.Clone();
            MixHash(WgIdentifier);
            MixHash(_cfg.PeerPublicKey);

            _ephPrivate = Curve25519.CreateRandomPrivateKey();
            _ephPublic = Curve25519.GetPublicKey(_ephPrivate);

            int p = offset;
            _senderIndex = RandomU32();
            WriteLe32(outBuf, p, ChooseHeader(0));
            WriteLe32(outBuf, p + 4, _senderIndex);
            Array.Copy(_ephPublic, 0, outBuf, p + 8, 32);

            MixKey(_ephPublic);
            MixHash(_ephPublic);

            byte[] shared = Curve25519.GetSharedSecret(_ephPrivate, _cfg.PeerPublicKey);
            byte[] key = MixKey(shared);

            byte[] staticPublic = Curve25519.GetPublicKey(_cfg.PrivateKey);
            SealAndHash(key, 0, staticPublic, outBuf, p + 40);          // 32 + 16 = 48 байт

            shared = Curve25519.GetSharedSecret(_cfg.PrivateKey, _cfg.PeerPublicKey);
            key = MixKey(shared);

            SealAndHash(key, 0, MakeTai64N(), outBuf, p + 88);          // 12 + 16 = 28 байт

            // mac1 = keyed-BLAKE2s(BLAKE2s("mac1----" || peer_pub), пакет[0..116])
            byte[] macInput = new byte[Mac1Label.Length + 32];
            Array.Copy(Mac1Label, macInput, Mac1Label.Length);
            Array.Copy(_cfg.PeerPublicKey, 0, macInput, Mac1Label.Length, 32);
            byte[] macKey = AwgCrypto.Hash(macInput);
            byte[] mac1 = AwgCrypto.Blake2s(Slice(outBuf, p, 116), macKey, 16);
            Array.Copy(mac1, 0, outBuf, p + 116, 16);
            // mac2 остаётся нулевым: cookie нам не присылали.

            return outBuf;
        }

        // Возвращает true, если это корректный ответ на нашу инициацию и туннель поднят.
        public bool ConsumeResponse(byte[] packet, int packetLen)
        {
            int offset = (int)_cfg.Padding[1];
            if (packetLen < offset + RespPacketLen) return false;
            int m = offset;

            uint header = ReadLe32(packet, m);
            if (header < _cfg.HeaderMin[1] || header > _cfg.HeaderMax[1]) return false;
            if (ReadLe32(packet, m + 8) != _senderIndex) return false;

            byte[] theirEph = Slice(packet, m + 12, 32);
            MixKey(theirEph);
            MixHash(theirEph);

            byte[] shared = Curve25519.GetSharedSecret(_ephPrivate, theirEph);
            MixKey(shared);
            shared = Curve25519.GetSharedSecret(_cfg.PrivateKey, theirEph);
            MixKey(shared);

            byte[] psk = _cfg.HasPresharedKey ? _cfg.PresharedKey : new byte[32];
            byte[] newChain, tau, key;
            Kdf3(_chainKey, psk, out newChain, out tau, out key);
            _chainKey = newChain;
            MixHash(tau);

            if (!OpenAndHash(key, 0, packet, m + 44, TagLen, new byte[0])) return false;

            byte[] s, r;
            Kdf2(_chainKey, null, out s, out r);
            _sendKey = s; _recvKey = r;

            _receiverIndex = ReadLe32(packet, m + 4);
            _sendCounter = 0;
            _recvCounter = 0;
            _recvWindow = 0;
            _haveRecvCounter = false;
            Established = true;
            EstablishedAtUtc = DateTime.UtcNow;
            return true;
        }

        // Строгая проверка «это ответ на инициацию»: и точная длина, и номер типа из H2.
        // Без неё обычный транспортный пакет во время перевыпуска ключей принимался
        // за ответ сервера — и перевыпуск падал, а данные терялись.
        public static bool IsHandshakeResponse(AwgConfig cfg, byte[] p, int len)
        {
            int off = (int)cfg.Padding[1];
            if (len != off + RespPacketLen) return false;
            uint h = ReadLe32(p, off);
            return h >= cfg.HeaderMin[1] && h <= cfg.HeaderMax[1];
        }

        // Тип пакета (с учётом H1..H4) — чтобы понять, что прилетело от сервера.
        public int ClassifyIncoming(byte[] packet, int len)
        {
            for (int i = 0; i < 4; i++)
            {
                int off = (int)_cfg.Padding[i];
                if (len < off + 4) continue;
                uint h = ReadLe32(packet, off);
                if (h >= _cfg.HeaderMin[i] && h <= _cfg.HeaderMax[i]) return i + 1;  // 1..4
            }
            return 0;
        }

        // ===================== транспорт =====================

        // Заворачивает IP-пакет в транспортное сообщение WireGuard.
        public byte[] Seal(byte[] packet, int packetLen)
        {
            if (!Established || _sendCounter == ulong.MaxValue) return null;
            int prefix = (int)_cfg.Padding[3];
            int paddedLen = (packetLen + 15) & ~15;          // WireGuard паддит до кратности 16
            byte[] outBuf = new byte[prefix + TransportFixed + paddedLen];
            if (prefix > 0) Array.Copy(Tls13Crypto.RandomBytes(prefix), outBuf, prefix);

            int w = prefix;
            ulong counter = _sendCounter++;
            WriteLe32(outBuf, w, ChooseHeader(3));
            WriteLe32(outBuf, w + 4, _receiverIndex);
            WriteLe64(outBuf, w + 8, counter);

            // Шифруем прямо в выходном буфере: хвост до кратности 16 уже нулевой.
            Array.Copy(packet, 0, outBuf, w + 16, packetLen);

            byte[] nonce = new byte[12];
            WriteLe64(nonce, 4, counter);
            AwgCrypto.Seal(_sendKey, nonce, null, outBuf, w + 16, paddedLen, outBuf, w + 16);
            return outBuf;
        }

        // Разворачивает транспортное сообщение. Возвращает IP-пакет или null.
        public byte[] Open(byte[] packet, int packetLen)
        {
            if (!Established) return null;
            int prefix = (int)_cfg.Padding[3];
            if (packetLen < prefix + TransportFixed) return null;
            int w = prefix;

            uint header = ReadLe32(packet, w);
            if (header < _cfg.HeaderMin[3] || header > _cfg.HeaderMax[3]) return null;
            if (ReadLe32(packet, w + 4) != _senderIndex) return null;

            ulong counter = ReadLe64(packet, w + 8);

            // Скользящее окно 64 пакета против повторов (как в WireGuard).
            if (_haveRecvCounter)
            {
                if (counter > _recvCounter)
                {
                    ulong shift = counter - _recvCounter;
                    _recvWindow = shift >= 64 ? 1UL : (_recvWindow << (int)shift) | 1UL;
                }
                else
                {
                    ulong distance = _recvCounter - counter;
                    if (distance >= 64 || (_recvWindow & (1UL << (int)distance)) != 0) return null;
                    _recvWindow |= 1UL << (int)distance;
                }
            }
            else _recvWindow = 1;

            int ctLen = packetLen - prefix - TransportFixed;
            byte[] plain = new byte[ctLen];
            byte[] nonce = new byte[12];
            WriteLe64(nonce, 4, counter);
            if (!AwgCrypto.Open(_recvKey, nonce, null, packet, w + 16, ctLen, packet, w + 16 + ctLen, plain, 0))
                return null;

            if (!_haveRecvCounter || counter > _recvCounter) _recvCounter = counter;
            _haveRecvCounter = true;

            // Пустой пакет = keepalive, наружу его отдавать не надо.
            int real = InnerPacketLength(plain, ctLen);
            if (real <= 0) return new byte[0];
            if (real == ctLen) return plain;
            return Slice(plain, 0, real);
        }

        // Настоящая длина IP-пакета внутри (остальное — паддинг до кратности 16).
        private static int InnerPacketLength(byte[] p, int len)
        {
            if (len == 0) return 0;
            int ver = p[0] >> 4;
            if (ver == 4 && len >= 4)
            {
                int declared = (p[2] << 8) | p[3];
                return declared >= 20 && declared <= len ? declared : len;
            }
            if (ver == 6 && len >= 6)
            {
                int declared = 40 + ((p[4] << 8) | p[5]);
                return declared <= len ? declared : len;
            }
            return len;
        }
    }
}
