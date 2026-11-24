using System;
using System.Diagnostics;
using System.Text;
using Windows.Data.Json;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace VlessApp
{
    // Порт INCY-DEV/incy-link-encoder — распаковка зашифрованных deep-link подписок INCY.
    // Схема: incy://crypt1/<payload>
    // Wire format payload: base64url(iv[12] + ciphertext + tag[16])
    // Алгоритм шифрования: AES-256-GCM с каноническим симметричным ключом K1.
    // Расшифрованный открытый текст: компактный JSON {"url":"...","v":1,"n":"Provider Name"}.
    internal static class IncyCrypto
    {
        private const string SchemePrefix = "incy://crypt1/";
        private const int IvLen = 12;
        private const int TagLen = 16;

        // Симметричный 256-битный ключ K1 для схемы crypt1.
        // SHA-256 Fingerprint: b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c
        private static readonly byte[] kIncyKey = new byte[32]
        {
            0xf6, 0xd4, 0x0e, 0xa0, 0xc8, 0xa8, 0x89, 0x9d,
            0x7c, 0x68, 0x2d, 0x09, 0xba, 0x0d, 0x41, 0x65,
            0xdf, 0xe2, 0xb3, 0xdd, 0x45, 0xe6, 0xbb, 0x3e,
            0x25, 0xcb, 0x23, 0x3c, 0xf0, 0x0c, 0x24, 0x62
        };

        public static bool IsIncyLink(string s)
        {
            return !string.IsNullOrWhiteSpace(s) &&
                   s.TrimStart().StartsWith("incy://", StringComparison.OrdinalIgnoreCase);
        }

        public static string Unwrap(string link, out string providerName)
        {
            providerName = null;
            if (string.IsNullOrWhiteSpace(link)) return null;

            string trimmed = link.Trim();
            if (!trimmed.StartsWith(SchemePrefix, StringComparison.OrdinalIgnoreCase))
            {
                // Не crypt1 или нестандартная форма
                if (trimmed.StartsWith("incy://", StringComparison.OrdinalIgnoreCase))
                {
                    Debug.WriteLine($"[INCY] Схема ссылки не crypt1 (поддерживается только crypt1): {trimmed}");
                }
                return null;
            }

            string payload = trimmed.Substring(SchemePrefix.Length).TrimEnd('/');
            if (string.IsNullOrEmpty(payload)) return null;

            try
            {
                byte[] wire = DecodeUrlSafeBase64(payload);
                if (wire == null || wire.Length < IvLen + TagLen + 1)
                {
                    Debug.WriteLine("[INCY] Длина полезной нагрузки меньше минимальной (IV + Tag + 1 байт данных).");
                    return null;
                }

                // Разбиение wire: iv (12) + ct (длина - 28) + tag (16)
                byte[] iv = new byte[IvLen];
                Buffer.BlockCopy(wire, 0, iv, 0, IvLen);

                int ctLen = wire.Length - IvLen - TagLen;
                byte[] ct = new byte[ctLen];
                Buffer.BlockCopy(wire, IvLen, ct, 0, ctLen);

                byte[] tag = new byte[TagLen];
                Buffer.BlockCopy(wire, IvLen + ctLen, tag, 0, TagLen);

                var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);
                var keyBlob = CryptographicBuffer.CreateFromByteArray(kIncyKey);
                var key = provider.CreateSymmetricKey(keyBlob);

                var nonceBuf = CryptographicBuffer.CreateFromByteArray(iv);
                var cipherBuf = CryptographicBuffer.CreateFromByteArray(ct);
                var tagBuf = CryptographicBuffer.CreateFromByteArray(tag);

                var plainBuf = CryptographicEngine.DecryptAndAuthenticate(key, cipherBuf, nonceBuf, tagBuf, null);
                byte[] plainBytes;
                CryptographicBuffer.CopyToByteArray(plainBuf, out plainBytes);

                if (plainBytes == null || plainBytes.Length == 0) return null;

                string json = Encoding.UTF8.GetString(plainBytes, 0, plainBytes.Length);
                Debug.WriteLine($"[INCY] Успешно расшифрован crypt1 JSON: {json}");

                JsonObject root;
                if (JsonObject.TryParse(json, out root))
                {
                    if (root.ContainsKey("n"))
                    {
                        var nVal = root.GetNamedValue("n");
                        if (nVal.ValueType == JsonValueType.String)
                            providerName = nVal.GetString();
                    }

                    if (root.ContainsKey("url"))
                    {
                        var urlVal = root.GetNamedValue("url");
                        if (urlVal.ValueType == JsonValueType.String)
                        {
                            string url = urlVal.GetString();
                            return string.IsNullOrWhiteSpace(url) ? null : url.Trim();
                        }
                    }
                }

                return null;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[INCY ERROR] Ошибка расшифровки incy://: {ex.Message}");
                AppLog.W($"  [INCY] Ошибка расшифровки ссылки crypt1: {ex.Message}");
                return null;
            }
        }

        private static byte[] DecodeUrlSafeBase64(string input)
        {
            if (string.IsNullOrEmpty(input)) return null;
            var sb = new StringBuilder(input.Length);
            foreach (char c in input)
            {
                if (c == '-') sb.Append('+');
                else if (c == '_') sb.Append('/');
                else if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
                else sb.Append(c);
            }
            int rem = sb.Length % 4;
            if (rem > 0) sb.Append('=', 4 - rem);

            try { return Convert.FromBase64String(sb.ToString()); }
            catch { return null; }
        }
    }
}
