using System;

namespace VlessVpnTask
{
    // Криптопримитивы AmneziaWG/WireGuard. Всё написано вручную: в UWP (Windows.Security.
    // Cryptography) нет ни BLAKE2s, ни ChaCha20/Poly1305 — только SHA/AES/HMAC. X25519 берём
    // из уже готового Curve25519 (donna-реализация в VlessConnection.cs), он проверен
    // на векторах RFC 7748.
    //
    // Проверено на официальных векторах: RFC 7693 (BLAKE2s), RFC 8439 (ChaCha20, Poly1305,
    // AEAD) — см. scratchpad/awgtest.cs.
    internal static class AwgCrypto
    {
        // ===================== BLAKE2s =====================

        private static readonly uint[] Blake2sIv =
        {
            0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
            0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
        };

        private static readonly byte[,] Sigma =
        {
            { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 },
            { 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3 },
            { 11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4 },
            { 7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8 },
            { 9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13 },
            { 2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9 },
            { 12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11 },
            { 13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10 },
            { 6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5 },
            { 10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0 }
        };

        private static uint Rotr(uint x, int n) { return (x >> n) | (x << (32 - n)); }

        private static uint Le32(byte[] b, int o)
        {
            return (uint)b[o] | ((uint)b[o + 1] << 8) | ((uint)b[o + 2] << 16) | ((uint)b[o + 3] << 24);
        }

        private static void Blake2sCompress(uint[] h, byte[] block, int off, ulong counter, bool last)
        {
            uint[] v = new uint[16];
            uint[] m = new uint[16];
            for (int i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = Blake2sIv[i]; }
            v[12] ^= (uint)counter;
            v[13] ^= (uint)(counter >> 32);
            if (last) v[14] = ~v[14];
            for (int i = 0; i < 16; i++) m[i] = Le32(block, off + 4 * i);

            for (int r = 0; r < 10; r++)
            {
                G(v, m, 0, 4, 8, 12, Sigma[r, 0], Sigma[r, 1]);
                G(v, m, 1, 5, 9, 13, Sigma[r, 2], Sigma[r, 3]);
                G(v, m, 2, 6, 10, 14, Sigma[r, 4], Sigma[r, 5]);
                G(v, m, 3, 7, 11, 15, Sigma[r, 6], Sigma[r, 7]);
                G(v, m, 0, 5, 10, 15, Sigma[r, 8], Sigma[r, 9]);
                G(v, m, 1, 6, 11, 12, Sigma[r, 10], Sigma[r, 11]);
                G(v, m, 2, 7, 8, 13, Sigma[r, 12], Sigma[r, 13]);
                G(v, m, 3, 4, 9, 14, Sigma[r, 14], Sigma[r, 15]);
            }
            for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
        }

        private static void G(uint[] v, uint[] m, int a, int b, int c, int d, int x, int y)
        {
            v[a] = v[a] + v[b] + m[x];
            v[d] = Rotr(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = Rotr(v[b] ^ v[c], 12);
            v[a] = v[a] + v[b] + m[y];
            v[d] = Rotr(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];
            v[b] = Rotr(v[b] ^ v[c], 7);
        }

        // BLAKE2s с произвольным ключом (может быть пустым) и длиной вывода 1..32.
        public static byte[] Blake2s(byte[] input, byte[] key, int outLen)
        {
            if (outLen < 1 || outLen > 32) throw new ArgumentException("blake2s outLen");
            int keyLen = key == null ? 0 : key.Length;
            if (keyLen > 32) throw new ArgumentException("blake2s keyLen");
            if (input == null) input = new byte[0];

            uint[] h = new uint[8];
            Array.Copy(Blake2sIv, h, 8);
            h[0] ^= 0x01010000u ^ ((uint)keyLen << 8) ^ (uint)outLen;

            byte[] buf = new byte[64];
            ulong counter = 0;
            int pos = 0;

            // Ключ (если есть) занимает ровно один первый блок, дополненный нулями.
            if (keyLen > 0)
            {
                Array.Clear(buf, 0, 64);
                Array.Copy(key, 0, buf, 0, keyLen);
                if (input.Length == 0)
                {
                    counter = 64;
                    Blake2sCompress(h, buf, 0, counter, true);
                    return Tail(h, outLen);
                }
                counter = 64;
                Blake2sCompress(h, buf, 0, counter, false);
            }

            // Все полные блоки, кроме последнего: последний обязан идти с флагом final.
            while (input.Length - pos > 64)
            {
                counter += 64;
                Blake2sCompress(h, input, pos, counter, false);
                pos += 64;
            }

            int rest = input.Length - pos;
            Array.Clear(buf, 0, 64);
            Array.Copy(input, pos, buf, 0, rest);
            counter += (ulong)rest;
            Blake2sCompress(h, buf, 0, counter, true);
            return Tail(h, outLen);
        }

        private static byte[] Tail(uint[] h, int outLen)
        {
            byte[] full = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                full[4 * i] = (byte)h[i];
                full[4 * i + 1] = (byte)(h[i] >> 8);
                full[4 * i + 2] = (byte)(h[i] >> 16);
                full[4 * i + 3] = (byte)(h[i] >> 24);
            }
            if (outLen == 32) return full;
            byte[] o = new byte[outLen];
            Array.Copy(full, o, outLen);
            return o;
        }

        public static byte[] Hash(byte[] input) { return Blake2s(input, null, 32); }

        public static byte[] Hash(byte[] a, byte[] b)
        {
            byte[] j = new byte[(a?.Length ?? 0) + (b?.Length ?? 0)];
            if (a != null) Array.Copy(a, 0, j, 0, a.Length);
            if (b != null) Array.Copy(b, 0, j, a?.Length ?? 0, b.Length);
            return Blake2s(j, null, 32);
        }

        // HMAC поверх BLAKE2s (WireGuard использует именно HMAC, а не keyed-режим BLAKE2s).
        public static byte[] HmacBlake2s(byte[] key, byte[] data)
        {
            const int block = 64;
            byte[] k = key ?? new byte[0];
            if (k.Length > block) k = Blake2s(k, null, 32);

            byte[] ipad = new byte[block];
            byte[] opad = new byte[block];
            for (int i = 0; i < block; i++)
            {
                byte kb = i < k.Length ? k[i] : (byte)0;
                ipad[i] = (byte)(kb ^ 0x36);
                opad[i] = (byte)(kb ^ 0x5c);
            }

            byte[] inner = new byte[block + (data?.Length ?? 0)];
            Array.Copy(ipad, inner, block);
            if (data != null) Array.Copy(data, 0, inner, block, data.Length);
            byte[] innerHash = Blake2s(inner, null, 32);

            byte[] outer = new byte[block + 32];
            Array.Copy(opad, outer, block);
            Array.Copy(innerHash, 0, outer, block, 32);
            return Blake2s(outer, null, 32);
        }

        // ===================== ChaCha20 (RFC 8439) =====================

        // x — рабочий массив вызывающего: на пакет в 1400 байт это 22 блока,
        // и выделять его внутри цикла означало бы тысячи мелких аллокаций в секунду.
        private static void ChaChaBlock(uint[] state, byte[] outBlock, uint[] x)
        {
            Array.Copy(state, x, 16);
            for (int i = 0; i < 10; i++)
            {
                Qr(x, 0, 4, 8, 12); Qr(x, 1, 5, 9, 13); Qr(x, 2, 6, 10, 14); Qr(x, 3, 7, 11, 15);
                Qr(x, 0, 5, 10, 15); Qr(x, 1, 6, 11, 12); Qr(x, 2, 7, 8, 13); Qr(x, 3, 4, 9, 14);
            }
            for (int i = 0; i < 16; i++)
            {
                uint v = x[i] + state[i];
                outBlock[4 * i] = (byte)v;
                outBlock[4 * i + 1] = (byte)(v >> 8);
                outBlock[4 * i + 2] = (byte)(v >> 16);
                outBlock[4 * i + 3] = (byte)(v >> 24);
            }
        }

        private static void Qr(uint[] x, int a, int b, int c, int d)
        {
            x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a], 16);
            x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c], 12);
            x[a] += x[b]; x[d] = Rotl(x[d] ^ x[a], 8);
            x[c] += x[d]; x[b] = Rotl(x[b] ^ x[c], 7);
        }

        private static uint Rotl(uint x, int n) { return (x << n) | (x >> (32 - n)); }

        // XOR-гамма ChaCha20 поверх data[off..off+len) с записью в out[outOff..].
        // Рабочие буферы на поток: путь данных горячий (каждый пакет туннеля),
        // а [ThreadStatic] снимает и аллокации, и любые вопросы о потокобезопасности.
        [ThreadStatic] private static uint[] _chachaState;
        [ThreadStatic] private static uint[] _chachaWork;
        [ThreadStatic] private static byte[] _chachaBlock;

        private static void ChaCha20Xor(byte[] key, byte[] nonce12, uint counter,
                                        byte[] data, int off, int len, byte[] dst, int dstOff)
        {
            uint[] s = _chachaState ?? (_chachaState = new uint[16]);
            uint[] x = _chachaWork ?? (_chachaWork = new uint[16]);
            byte[] block = _chachaBlock ?? (_chachaBlock = new byte[64]);

            FillChaChaState(s, key, nonce12, counter);
            int done = 0;
            while (done < len)
            {
                ChaChaBlock(s, block, x);
                int n = Math.Min(64, len - done);
                for (int i = 0; i < n; i++) dst[dstOff + done + i] = (byte)(data[off + done + i] ^ block[i]);
                done += n;
                s[12]++;   // счётчик блоков
            }
        }

        private static void FillChaChaState(uint[] s, byte[] key, byte[] nonce12, uint counter)
        {
            s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
            for (int i = 0; i < 8; i++) s[4 + i] = Le32(key, 4 * i);
            s[12] = counter;
            s[13] = Le32(nonce12, 0);
            s[14] = Le32(nonce12, 4);
            s[15] = Le32(nonce12, 8);
        }

        // ===================== Poly1305 (RFC 8439) =====================

        private sealed class Poly1305
        {
            private readonly uint[] _r = new uint[5];
            private readonly uint[] _s = new uint[4];
            private readonly uint[] _h = new uint[5];
            private readonly byte[] _buf = new byte[16];
            private int _bufLen;

            public Poly1305(byte[] key)
            {
                uint t0 = Le32(key, 0), t1 = Le32(key, 4), t2 = Le32(key, 8), t3 = Le32(key, 12);
                // clamp
                _r[0] = t0 & 0x3ffffff;
                _r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
                _r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
                _r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
                _r[4] = (t3 >> 8) & 0x00fffff;
                _s[0] = Le32(key, 16); _s[1] = Le32(key, 20);
                _s[2] = Le32(key, 24); _s[3] = Le32(key, 28);
            }

            private void Block(byte[] m, int off, bool final)
            {
                uint hibit = final ? 0u : (1u << 24);
                uint t0 = Le32(m, off), t1 = Le32(m, off + 4), t2 = Le32(m, off + 8), t3 = Le32(m, off + 12);

                _h[0] += t0 & 0x3ffffff;
                _h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
                _h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
                _h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
                _h[4] += (t3 >> 8) | hibit;

                ulong d0 = (ulong)_h[0] * _r[0] + (ulong)_h[1] * (5 * _r[4]) + (ulong)_h[2] * (5 * _r[3]) + (ulong)_h[3] * (5 * _r[2]) + (ulong)_h[4] * (5 * _r[1]);
                ulong d1 = (ulong)_h[0] * _r[1] + (ulong)_h[1] * _r[0] + (ulong)_h[2] * (5 * _r[4]) + (ulong)_h[3] * (5 * _r[3]) + (ulong)_h[4] * (5 * _r[2]);
                ulong d2 = (ulong)_h[0] * _r[2] + (ulong)_h[1] * _r[1] + (ulong)_h[2] * _r[0] + (ulong)_h[3] * (5 * _r[4]) + (ulong)_h[4] * (5 * _r[3]);
                ulong d3 = (ulong)_h[0] * _r[3] + (ulong)_h[1] * _r[2] + (ulong)_h[2] * _r[1] + (ulong)_h[3] * _r[0] + (ulong)_h[4] * (5 * _r[4]);
                ulong d4 = (ulong)_h[0] * _r[4] + (ulong)_h[1] * _r[3] + (ulong)_h[2] * _r[2] + (ulong)_h[3] * _r[1] + (ulong)_h[4] * _r[0];

                ulong c = d0 >> 26; _h[0] = (uint)d0 & 0x3ffffff;
                d1 += c; c = d1 >> 26; _h[1] = (uint)d1 & 0x3ffffff;
                d2 += c; c = d2 >> 26; _h[2] = (uint)d2 & 0x3ffffff;
                d3 += c; c = d3 >> 26; _h[3] = (uint)d3 & 0x3ffffff;
                d4 += c; c = d4 >> 26; _h[4] = (uint)d4 & 0x3ffffff;
                _h[0] += (uint)c * 5; c = _h[0] >> 26; _h[0] &= 0x3ffffff;
                _h[1] += (uint)c;
            }

            public void Update(byte[] data, int off, int len)
            {
                if (data == null || len <= 0) return;
                int i = 0;
                if (_bufLen > 0)
                {
                    int need = Math.Min(16 - _bufLen, len);
                    Array.Copy(data, off, _buf, _bufLen, need);
                    _bufLen += need; i += need;
                    if (_bufLen == 16) { Block(_buf, 0, false); _bufLen = 0; }
                }
                while (len - i >= 16) { Block(data, off + i, false); i += 16; }
                if (len - i > 0)
                {
                    Array.Copy(data, off + i, _buf, 0, len - i);
                    _bufLen = len - i;
                }
            }

            public byte[] Finish()
            {
                if (_bufLen > 0)
                {
                    _buf[_bufLen] = 1;
                    for (int i = _bufLen + 1; i < 16; i++) _buf[i] = 0;
                    Block(_buf, 0, true);
                }

                uint c = _h[1] >> 26; _h[1] &= 0x3ffffff;
                _h[2] += c; c = _h[2] >> 26; _h[2] &= 0x3ffffff;
                _h[3] += c; c = _h[3] >> 26; _h[3] &= 0x3ffffff;
                _h[4] += c; c = _h[4] >> 26; _h[4] &= 0x3ffffff;
                _h[0] += c * 5; c = _h[0] >> 26; _h[0] &= 0x3ffffff;
                _h[1] += c;

                uint[] g = new uint[5];
                g[0] = _h[0] + 5; c = g[0] >> 26; g[0] &= 0x3ffffff;
                g[1] = _h[1] + c; c = g[1] >> 26; g[1] &= 0x3ffffff;
                g[2] = _h[2] + c; c = g[2] >> 26; g[2] &= 0x3ffffff;
                g[3] = _h[3] + c; c = g[3] >> 26; g[3] &= 0x3ffffff;
                g[4] = _h[4] + c - (1u << 26);

                uint mask = (g[4] >> 31) - 1;   // 0xffffffff если g >= 2^130-5
                for (int i = 0; i < 5; i++) g[i] &= mask;
                mask = ~mask;
                for (int i = 0; i < 5; i++) _h[i] = (_h[i] & mask) | g[i];

                uint f0 = (_h[0] | (_h[1] << 26)) & 0xffffffff;
                uint f1 = ((_h[1] >> 6) | (_h[2] << 20)) & 0xffffffff;
                uint f2 = ((_h[2] >> 12) | (_h[3] << 14)) & 0xffffffff;
                uint f3 = ((_h[3] >> 18) | (_h[4] << 8)) & 0xffffffff;

                ulong t = (ulong)f0 + _s[0]; f0 = (uint)t;
                t = (ulong)f1 + _s[1] + (t >> 32); f1 = (uint)t;
                t = (ulong)f2 + _s[2] + (t >> 32); f2 = (uint)t;
                t = (ulong)f3 + _s[3] + (t >> 32); f3 = (uint)t;

                byte[] tag = new byte[16];
                WriteLe32(tag, 0, f0); WriteLe32(tag, 4, f1);
                WriteLe32(tag, 8, f2); WriteLe32(tag, 12, f3);
                return tag;
            }
        }

        private static void WriteLe32(byte[] b, int o, uint v)
        {
            b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24);
        }

        // ===================== ChaCha20-Poly1305 AEAD =====================

        private static readonly byte[] Pad16 = new byte[16];

        [ThreadStatic] private static byte[] _polyKeyScratch;
        [ThreadStatic] private static byte[] _polyPkScratch;
        [ThreadStatic] private static byte[] _polyLenScratch;

        private static byte[] AeadTag(byte[] key, byte[] nonce12, byte[] aad,
                                      byte[] ct, int ctOff, int ctLen)
        {
            byte[] polyKey = _polyKeyScratch ?? (_polyKeyScratch = new byte[64]);
            byte[] pk = _polyPkScratch ?? (_polyPkScratch = new byte[32]);
            byte[] lens = _polyLenScratch ?? (_polyLenScratch = new byte[16]);
            Array.Clear(polyKey, 0, 64);
            ChaCha20Xor(key, nonce12, 0, polyKey, 0, 64, polyKey, 0); // блок 0 = ключ Poly1305
            Array.Copy(polyKey, pk, 32);

            var p = new Poly1305(pk);
            int aadLen = aad?.Length ?? 0;
            if (aadLen > 0)
            {
                p.Update(aad, 0, aadLen);
                int rem = aadLen % 16;
                if (rem != 0) p.Update(Pad16, 0, 16 - rem);
            }
            p.Update(ct, ctOff, ctLen);
            int crem = ctLen % 16;
            if (crem != 0) p.Update(Pad16, 0, 16 - crem);

            WriteLe64(lens, 0, (ulong)aadLen);
            WriteLe64(lens, 8, (ulong)ctLen);
            p.Update(lens, 0, 16);
            return p.Finish();
        }

        private static void WriteLe64(byte[] b, int o, ulong v)
        {
            for (int i = 0; i < 8; i++) b[o + i] = (byte)(v >> (8 * i));
        }

        // Шифрует plain[plainOff..+plainLen) в dst[dstOff..], следом кладёт 16-байтовый тег.
        // Допускается dst == plain при dstOff == plainOff (шифрование на месте).
        public static void Seal(byte[] key, byte[] nonce12, byte[] aad,
                                byte[] plain, int plainOff, int plainLen,
                                byte[] dst, int dstOff)
        {
            ChaCha20Xor(key, nonce12, 1, plain, plainOff, plainLen, dst, dstOff);
            byte[] tag = AeadTag(key, nonce12, aad, dst, dstOff, plainLen);
            Array.Copy(tag, 0, dst, dstOff + plainLen, 16);
        }

        public static byte[] Seal(byte[] key, byte[] nonce12, byte[] aad, byte[] plain)
        {
            byte[] outBuf = new byte[plain.Length + 16];
            Seal(key, nonce12, aad, plain, 0, plain.Length, outBuf, 0);
            return outBuf;
        }

        // Проверяет тег и расшифровывает. Возвращает false при несовпадении тега.
        public static bool Open(byte[] key, byte[] nonce12, byte[] aad,
                                byte[] ct, int ctOff, int ctLen,
                                byte[] tag, int tagOff,
                                byte[] dst, int dstOff)
        {
            byte[] expect = AeadTag(key, nonce12, aad, ct, ctOff, ctLen);
            int diff = 0;
            for (int i = 0; i < 16; i++) diff |= expect[i] ^ tag[tagOff + i];
            if (diff != 0) return false;
            ChaCha20Xor(key, nonce12, 1, ct, ctOff, ctLen, dst, dstOff);
            return true;
        }

        public static byte[] Open(byte[] key, byte[] nonce12, byte[] aad, byte[] ctAndTag)
        {
            if (ctAndTag == null || ctAndTag.Length < 16) return null;
            int ctLen = ctAndTag.Length - 16;
            byte[] plain = new byte[ctLen];
            return Open(key, nonce12, aad, ctAndTag, 0, ctLen, ctAndTag, ctLen, plain, 0) ? plain : null;
        }
    }
}
