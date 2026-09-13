using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using Windows.Data.Json;

namespace VlessApp
{
    // Ссылки vpn://… из приложения AmneziaVPN.
    //
    // Формат: "vpn://" + base64url( qCompress(JSON) ), где qCompress — это
    // 4 байта длины (big-endian) + обычный zlib-поток. Внутри JSON лежит список
    // «контейнеров» (протоколов), а нужный нам конфиг AmneziaWG хранится
    // в контейнере "awg" полем last_config → config (это готовый текст .conf).
    internal static class AmneziaLink
    {
        public sealed class Result
        {
            public string ConfText;     // готовый текст .conf
            public string Name;         // имя профиля из поля description
            public string HostName;     // адрес сервера (для имени по умолчанию)
        }

        public static bool IsAmneziaLink(string s)
        {
            return !string.IsNullOrWhiteSpace(s) &&
                   s.TrimStart().StartsWith("vpn://", StringComparison.OrdinalIgnoreCase);
        }

        // Распаковать тело ссылки в JSON. Принимает как полную ссылку vpn://…,
        // так и голое тело — в таком виде конфиг приходит от API-шлюза Amnezia
        // полем "config", и формат там ровно тот же.
        public static JsonObject DecodePayload(string payloadOrLink)
        {
            if (string.IsNullOrWhiteSpace(payloadOrLink)) return null;
            string payload = payloadOrLink.Trim();
            if (payload.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase))
                payload = payload.Substring("vpn://".Length).Trim();

            byte[] raw = DecodeBase64Url(payload);
            if (raw == null || raw.Length < 6) return null;

            string json = Inflate(raw);
            if (json == null) return null;

            JsonObject root;
            return JsonObject.TryParse(json, out root) ? root : null;
        }

        // Подписка Amnezia Premium (config_version 2): конфига внутри нет, есть
        // только ключ доступа к API. Возвращает null, если ссылка не такая.
        public static AmneziaApi.Subscription TryGetApiSubscription(string link)
        {
            JsonObject root = DecodePayload(link);
            return root == null ? null : TryGetApiSubscription(root);
        }

        public static AmneziaApi.Subscription TryGetApiSubscription(JsonObject root)
        {
            if (root == null) return null;
            if (FindAwgContainer(root) != null) return null;   // обычный конфиг, API не нужен
            if (!root.ContainsKey("api_config") && !root.ContainsKey("auth_data")) return null;

            JsonObject api = null, auth = null;
            try { if (root.ContainsKey("api_config")) api = root.GetNamedObject("api_config"); } catch { }
            try { if (root.ContainsKey("auth_data")) auth = root.GetNamedObject("auth_data"); } catch { }

            string apiKey = GetStr(auth, "api_key");
            if (string.IsNullOrEmpty(apiKey)) return null;

            return new AmneziaApi.Subscription
            {
                ApiKey = apiKey,
                ServiceType = GetStr(api, "service_type"),
                ServiceProtocol = GetStr(api, "service_protocol"),
                UserCountryCode = GetStr(api, "user_country_code"),
                Name = GetStr(root, "description") ?? GetStr(root, "name")
            };
        }

        // Возвращает null, если это не наш формат либо в ссылке нет AmneziaWG.
        // reason заполняется понятным текстом, чтобы показать его пользователю.
        public static Result Parse(string link, out string reason)
        {
            reason = null;
            try
            {
                JsonObject root = DecodePayload(link);
                if (root == null)
                { reason = "не удалось распаковать содержимое ссылки"; return null; }

                return ParseRoot(root, out reason);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[AMNEZIA LINK] Ошибка разбора: {ex.Message}");
                reason = "ошибка разбора ссылки: " + ex.Message;
                return null;
            }
        }

        // Разбор уже распакованного JSON — общий путь для ссылки vpn:// и для
        // ответа API-шлюза, которые устроены одинаково.
        public static Result ParseRoot(JsonObject root, out string reason)
        {
            reason = null;
            try
            {
                JsonObject awg = FindAwgContainer(root);
                if (awg == null)
                {
                    // config_version 2 — подписка Amnezia Premium: вместо containers
                    // с готовым .conf здесь только ключ к их API, по которому конфиг
                    // скачивает сам клиент AmneziaVPN. Импортировать тут нечего, и
                    // без этой ветки пользователь видел бы «нет протокола AmneziaWG»,
                    // как будто ссылка просто не того типа.
                    if (root.ContainsKey("api_config") || root.ContainsKey("auth_data"))
                    {
                        string svc = null;
                        JsonObject api = null;
                        try { if (root.ContainsKey("api_config")) api = root.GetNamedObject("api_config"); }
                        catch { }
                        if (api != null) svc = GetStr(api, "service_type");

                        reason = "это ссылка-подписка Amnezia Premium" +
                                 (string.IsNullOrEmpty(svc) ? "" : " (" + svc + ")") +
                                 ", в ней нет самого конфига — только ключ доступа к API Amnezia. " +
                                 "Такую ссылку понимает только клиент AmneziaVPN: он скачивает конфиг по этому ключу. " +
                                 "Нужен обычный vpn://-конфиг (экспорт готового подключения) либо .conf-файл AmneziaWG.";
                        return null;
                    }

                    reason = "в ссылке нет протокола AmneziaWG (возможно, это OpenVPN, Shadowsocks или XRay)";
                    return null;
                }

                string conf = ExtractConf(awg);
                if (string.IsNullOrWhiteSpace(conf))
                { reason = "в контейнере AmneziaWG нет текста конфигурации"; return null; }

                // Amnezia подставляет DNS уже на клиенте, в шаблоне остаются плейсхолдеры.
                string dns1 = GetStr(root, "dns1"), dns2 = GetStr(root, "dns2");
                conf = conf.Replace("$PRIMARY_DNS", string.IsNullOrEmpty(dns1) ? "1.1.1.1" : dns1)
                           .Replace("$SECONDARY_DNS", string.IsNullOrEmpty(dns2) ? "1.0.0.1" : dns2);

                // MTU в .conf обычно отсутствует — он лежит отдельным полем контейнера.
                if (conf.IndexOf("MTU", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    string mtu = GetStr(awg, "mtu");
                    if (string.IsNullOrEmpty(mtu)) mtu = GetConfField(awg, "mtu");
                    int m;
                    if (int.TryParse(mtu, out m) && m >= 576 && m <= 1500)
                        conf = InsertIntoInterface(conf, "MTU = " + m);
                }

                string host = GetStr(root, "hostName");
                if (string.IsNullOrEmpty(host)) host = GetStr(awg, "hostName");

                return new Result
                {
                    ConfText = conf,
                    Name = GetStr(root, "description"),
                    HostName = host
                };
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[AMNEZIA LINK] Ошибка разбора: {ex.Message}");
                reason = "ошибка разбора конфигурации: " + ex.Message;
                return null;
            }
        }

        // =====================================================================

        private static byte[] DecodeBase64Url(string s)
        {
            try
            {
                string b = s.Replace('-', '+').Replace('_', '/').Trim();
                int pad = b.Length % 4;
                if (pad > 0) b += new string('=', 4 - pad);
                return Convert.FromBase64String(b);
            }
            catch (FormatException)
            {
                return null;
            }
        }

        // qCompress: 4 байта длины BE, дальше zlib (2 байта заголовка + deflate + adler32).
        // В UWP есть только DeflateStream, поэтому заголовок zlib снимаем вручную.
        private static string Inflate(byte[] raw)
        {
            // Первые 4 байта по формату qCompress — длина распакованных данных,
            // но Amnezia её не заполняет: и в ссылке, и в ответе шлюза там лежит
            // одно и то же 0x000000FF при совершенно разных размерах. Поэтому
            // просто пропускаем их вместе с двухбайтовым заголовком zlib.
            try
            {
                using (var src = new MemoryStream(raw, 6, raw.Length - 6))
                using (var inflater = new DeflateStream(src, CompressionMode.Decompress))
                using (var dst = new MemoryStream())
                {
                    inflater.CopyTo(dst);
                    return Encoding.UTF8.GetString(dst.ToArray());
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[AMNEZIA LINK] zlib не раскрылся ({ex.Message}), пробую как обычный текст.");
                // Старые/укороченные ссылки иногда содержат несжатый JSON.
                string plain = Encoding.UTF8.GetString(raw);
                int brace = plain.IndexOf('{');
                return brace >= 0 ? plain.Substring(brace) : null;
            }
        }

        private static JsonObject FindAwgContainer(JsonObject root)
        {
            if (!root.ContainsKey("containers")) return null;
            JsonArray arr;
            try { arr = root.GetNamedArray("containers"); }
            catch { return null; }

            string preferred = GetStr(root, "defaultContainer");

            JsonObject firstMatch = null;
            foreach (var item in arr)
            {
                JsonObject c;
                try { c = item.GetObject(); }
                catch { continue; }

                JsonObject inner = null;
                if (c.ContainsKey("awg")) { try { inner = c.GetNamedObject("awg"); } catch { } }
                if (inner == null && c.ContainsKey("wireguard")) { try { inner = c.GetNamedObject("wireguard"); } catch { } }
                if (inner == null) continue;

                if (firstMatch == null) firstMatch = inner;
                if (!string.IsNullOrEmpty(preferred) &&
                    string.Equals(GetStr(c, "container"), preferred, StringComparison.OrdinalIgnoreCase))
                    return inner;
            }
            return firstMatch;
        }

        // Текст .conf лежит внутри last_config — это строка с вложенным JSON.
        private static string ExtractConf(JsonObject awg)
        {
            string direct = GetConfField(awg, "config");
            if (!string.IsNullOrWhiteSpace(direct)) return direct;

            string lastConfig = GetStr(awg, "last_config");
            if (string.IsNullOrWhiteSpace(lastConfig)) return null;

            JsonObject inner;
            if (!JsonObject.TryParse(lastConfig, out inner)) return null;
            return GetStr(inner, "config");
        }

        private static string GetConfField(JsonObject awg, string field)
        {
            string lastConfig = GetStr(awg, "last_config");
            if (string.IsNullOrWhiteSpace(lastConfig)) return null;
            JsonObject inner;
            if (!JsonObject.TryParse(lastConfig, out inner)) return null;
            return GetStr(inner, field);
        }

        private static string GetStr(JsonObject o, string key)
        {
            if (o == null || !o.ContainsKey(key)) return null;
            try
            {
                var v = o.GetNamedValue(key);
                switch (v.ValueType)
                {
                    case JsonValueType.String: return v.GetString();
                    case JsonValueType.Number: return ((long)v.GetNumber()).ToString();
                    default: return null;
                }
            }
            catch { return null; }
        }

        private static string InsertIntoInterface(string conf, string line)
        {
            int idx = conf.IndexOf("[Interface]", StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return conf;
            int eol = conf.IndexOf('\n', idx);
            if (eol < 0) return conf + "\n" + line + "\n";
            return conf.Substring(0, eol + 1) + line + "\n" + conf.Substring(eol + 1);
        }
    }
}
