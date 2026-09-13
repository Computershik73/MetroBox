using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using Windows.Data.Json;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace VlessApp
{
    // Клиент API-шлюза AmneziaVPN (подписки Amnezia Premium, config_version 2).
    //
    // Ссылка vpn://… такой подписки не содержит конфига — в ней только ключ
    // доступа. Настоящий конфиг выдаёт шлюз по запросу; здесь воспроизведён его
    // протокол (см. GatewayController в открытом клиенте amnezia-vpn/amnezia-client).
    //
    // Схема запроса:
    //   POST http://gw.amnezia.org:80/v1/config
    //   Content-Type: application/json, X-Client-Request-ID: <uuid>
    //   { "key_payload": base64(RSA-PKCS1v1.5(pub, {aes_key,aes_iv,aes_salt})),
    //     "api_payload": base64(AES-256-CBC(<json запроса>, key, iv)) }
    // Ответ — сырой шифротекст AES-256-CBC на том же ключе (не base64).
    // HTTP здесь обычный: шифрование сделано на уровне полезной нагрузки.
    internal static class AmneziaApi
    {
        private const string GatewayEndpoint = "http://gw.amnezia.org:80/";

        // Боевой ключ шлюза. В открытый репозиторий он не попадает (подставляется
        // из переменной окружения PROD_AGW_PUBLIC_KEY при сборке), поэтому взят из
        // libAmneziaVPN официального релиза. Проверен опытом: на запрос, зашифрованный
        // этим ключом, gw.amnezia.org отвечает осмысленно; на второй ключ из той же
        // библиотеки (он от dev-стенда gw.dev.amzsvc.com) — HTTP 500 с пустым телом.
        // Хранится построчно, потому что ключ используется двумя способами:
        // как DER для RSA (тогда нужны только строки тела) и как ТЕКСТ PEM
        // целиком — из его SHA512 выводится ключ расшифровки списка прокси
        // (decryptProxyUrlsPayload в gatewayController.cpp). Переводы строк
        // там LF и завершающего нет — проверено на реальном endpoints.json.
        private static readonly string[] KeyBodyLines =
        {
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj5mxl/4DL3Sk89ntxs5G",
            "X3JawGQWIoq6rvNkOzNGuNgedNS2+pi6hZl3Izl1Io9om4KiUlMT6mgLO1hTr9q+",
            "s7CYhlvroFA7ErucF+9L+7FCt0Igi0kIK/R2/vxd/2HaUrorn/aSvvutkYwbfxqW",
            "SwtzE+RuBeDWGvEt937OW0oqYONPYv9E4T56Dz/EZ6v2t8ejAnKLbGD/GocMmipK",
            "7etFSiSMAB2RmaztqTq4NleBepfO80XpYlW9pCSXuHcE8wxHczkzxsbyMAMsG/K3",
            "vUQY6qPtohqqzSSBwa/8u2ptNHBeor7l7DdYXeR/Nqcc4z92VUkZ5lOVR4evkS5V",
            "/wQqp5tnOJEj3NjUhEhXFoNEapbZd1bh6iQoUk7jC1TdvKJ/nPKGZAsHRpr0rNKz",
            "fx/N/Oo6lr2yh/+ps6VxTkbPmB6E85WOO3UvjImZUY0XQdBjWle/4iJLdEC77Nr0",
            "jXhdgeypucy6jkB6iBHMeVMlrNMEV7UxoBR/cCNx55zu/8sml5ByiDvCDT7sRomN",
            "NgVt5S/FaVjYuzFUifJ12ToChXFgESKFmuso7WluEaWvMIGREdrMrKQKHfYLOzWF",
            "2B5ZJDqw4o03fU4J/6rw61M1b+rjVpXMjPnzc2A+RgcjTvXv955gfZkwe4lt5wk/",
            "3j8zMVo3+zLrMTAaEeIUM0UCAwEAAQ=="
        };

        private static string ProdPublicKeyPem { get { return string.Concat(KeyBodyLines); } }

        private static string ProdPublicKeyPemText
        {
            get
            {
                return "-----BEGIN PUBLIC KEY-----\n" +
                       string.Join("\n", KeyBodyLines) +
                       "\n-----END PUBLIC KEY-----";
            }
        }

        // Хранилища со списком обходных прокси. Список зашифрован, ключ
        // выводится из PEM выше — отдельного секрета не требуется.
        private static readonly string[] ProxyStorageBases =
        {
            "https://s3.eu-north-1.amazonaws.com/amnezia/",
            "https://storage.googleapis.com/lambda-list/",
            "https://amnzstrg01.blob.core.windows.net/lambda-list/",
            "https://storage.mwsapis.ru/lambda-list/",
            "https://objectstorage.eu-zurich-1.oraclecloud.com/n/zrhfyaq6qxvh/b/lambda-list/o/"
        };

        // Версию и платформу шлюз видит в открытом виде внутри шифрованной нагрузки.
        // Представляемся так же, как настольный клиент: сервер вправе отказать
        // незнакомой версии, а поля os_version/app_version он проверяет.
        private const string AppVersion = "5.0.0.5";
        private const string OsVersion = "windows";

        // =====================================================================
        // Лог. Пишем каждый шаг: без него любая ошибка шлюза выглядела как
        // «что-то пошло не так», а причина оставалась невидимой.
        // =====================================================================
        private static readonly StringBuilder LogBuffer = new StringBuilder();
        private const int LogLimit = 16000;

        public static void Log(string message)
        {
            string line = DateTime.Now.ToString("HH:mm:ss.fff") + "  " + message;
            Debug.WriteLine("[AMNEZIA API] " + message);
            lock (LogBuffer)
            {
                LogBuffer.AppendLine(line);
                if (LogBuffer.Length > LogLimit)
                    LogBuffer.Remove(0, LogBuffer.Length - LogLimit);
            }
            AppendToFile(line);
        }

        // Отдельный файл, а не общий vpnlog.txt: тот обнуляется при каждом старте
        // VPN, и строки выдачи конфига стирались бы ровно перед тем, как их читать.
        // До этой правки лог выдачи существовал только в отладочном выводе Visual
        // Studio, то есть у обычного пользователя его не было вовсе — и попросить
        // его прислать причину отказа шлюза было невозможно.
        private static readonly object FileLock = new object();
        private const long AmneziaLogMaxBytes = 512L * 1024;

        public static string LogFileName { get { return "amnezialog.txt"; } }

        private static void AppendToFile(string line)
        {
            try
            {
                lock (FileLock)
                {
                    string path = System.IO.Path.Combine(
                        Windows.Storage.ApplicationData.Current.LocalFolder.Path, LogFileName);
                    try
                    {
                        var fi = new System.IO.FileInfo(path);
                        if (fi.Exists && fi.Length > AmneziaLogMaxBytes) System.IO.File.Delete(path);
                    }
                    catch { }
                    System.IO.File.AppendAllText(path, line + Environment.NewLine,
                                                 System.Text.Encoding.UTF8);
                }
            }
            catch { /* лог не должен ломать выдачу конфига */ }
        }

        public static string GetLog()
        {
            lock (LogBuffer) { return LogBuffer.ToString(); }
        }

        public static void ClearLog()
        {
            lock (LogBuffer) { LogBuffer.Clear(); }
        }

        private static string Mask(string s)
        {
            if (string.IsNullOrEmpty(s)) return "<пусто>";
            if (s.Length <= 8) return "<" + s.Length + " симв.>";
            return s.Substring(0, 4) + "…" + s.Substring(s.Length - 2) + " (" + s.Length + " симв.)";
        }

        private static string Hex(byte[] b, int max)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < b.Length && i < max; i++) sb.Append(b[i].ToString("x2")).Append(' ');
            return sb.ToString().Trim();
        }

        private static string AsText(byte[] b, int max)
        {
            try
            {
                string s = Encoding.UTF8.GetString(b);
                if (s.Length > max) s = s.Substring(0, max) + "…";
                return s;
            }
            catch { return "<не текст>"; }
        }

        // Шлюз ответил, но не тем, что мы ждали. Несёт статус и тело как есть.
        public sealed class GatewayException : Exception
        {
            public int HttpStatus { get; private set; }
            public string RawBody { get; private set; }
            public GatewayException(string message, int status, string rawBody) : base(message)
            {
                HttpStatus = status;
                RawBody = rawBody;
            }
        }

        public sealed class Subscription
        {
            public string ApiKey;
            public string ServiceType;       // "amnezia-premium"
            public string ServiceProtocol;   // "awg"
            public string UserCountryCode;   // "ru"
            public string Name;
            // Куда подключаться. Пусто — выбирает шлюз. Подписка выдаёт ОДИН
            // активный конфиг на устройство, поэтому смена страны — это новый
            // запрос, после которого прежний конфиг отзывается.
            public string ServerCountryCode;
        }

        public sealed class Country
        {
            public string Code;
            public string Name;
            public List<string> Protocols = new List<string>();

            public override string ToString()
            {
                string p = Protocols.Count > 0 ? " · " + string.Join("/", Protocols).ToUpperInvariant() : "";
                return (string.IsNullOrEmpty(Name) ? Code : Name) + p;
            }
        }

        // =====================================================================

        public static async Task<List<VlessProfile>> FetchAsync(Subscription sub, string groupName)
        {
            var result = new List<VlessProfile>();
            if (sub == null || string.IsNullOrEmpty(sub.ApiKey))
                throw new Exception("в ссылке нет ключа доступа Amnezia.");

            string protocol = string.IsNullOrEmpty(sub.ServiceProtocol) ? "awg" : sub.ServiceProtocol;
            bool isAwg = string.Equals(protocol, "awg", StringComparison.OrdinalIgnoreCase);

            // Для awg клиент генерирует пару ключей и отдаёт публичный; для vless
            // в том же поле public_key уходит просто новый UUID — он и становится
            // идентификатором клиента. Так же делает официальный клиент
            // (generateProtocolData в subscriptionController.cpp).
            string privB64 = "", pubB64;
            if (isAwg)
            {
                byte[] priv = X25519.CreateRandomPrivateKey();
                byte[] pub = X25519.GetPublicKey(priv);
                privB64 = Convert.ToBase64String(priv);
                pubB64 = Convert.ToBase64String(pub);
            }
            else
            {
                pubB64 = Guid.NewGuid().ToString();
            }

            var apiPayload = new JsonObject();
            apiPayload["os_version"] = JsonValue.CreateStringValue(OsVersion);
            apiPayload["app_version"] = JsonValue.CreateStringValue(AppVersion);
            apiPayload["app_language"] = JsonValue.CreateStringValue("ru");
            apiPayload["installation_uuid"] = JsonValue.CreateStringValue(GetInstallationUuid());
            if (!string.IsNullOrEmpty(sub.UserCountryCode))
                apiPayload["user_country_code"] = JsonValue.CreateStringValue(sub.UserCountryCode);
            if (!string.IsNullOrEmpty(sub.ServiceType))
                apiPayload["service_type"] = JsonValue.CreateStringValue(sub.ServiceType);
            if (!string.IsNullOrEmpty(sub.ServerCountryCode))
                apiPayload["server_country_code"] = JsonValue.CreateStringValue(sub.ServerCountryCode);
            apiPayload["service_protocol"] = JsonValue.CreateStringValue(protocol);

            var authData = new JsonObject();
            authData["api_key"] = JsonValue.CreateStringValue(sub.ApiKey);
            apiPayload["auth_data"] = authData;
            apiPayload["public_key"] = JsonValue.CreateStringValue(pubB64);

            Log("=== Запрос конфига ===");
            Log($"  сервис {sub.ServiceType}, протокол {protocol}, " +
                $"страна пользователя {sub.UserCountryCode ?? "—"}, " +
                $"страна сервера {(string.IsNullOrEmpty(sub.ServerCountryCode) ? "<на усмотрение шлюза>" : sub.ServerCountryCode)}");
            Log($"  api_key {Mask(sub.ApiKey)}, installation_uuid {Mask(GetInstallationUuid())}");
            Log($"  public_key {(isAwg ? "ключ WireGuard" : "UUID клиента")} {Mask(pubB64)}");

            string responseJson = await PostAsync("v1/config", apiPayload);

            JsonObject resp;
            if (!JsonObject.TryParse(responseJson, out resp))
                throw new Exception("шлюз Amnezia вернул неожиданный ответ.");

            Log("  поля ответа: " + string.Join(", ", resp.Keys));

            // Ошибки приходят тем же шифрованным каналом, с полем message.
            if (resp.ContainsKey("message") && !resp.ContainsKey("config"))
                throw new Exception("шлюз Amnezia отказал: " + GetStr(resp, "message"));

            string configField = GetStr(resp, "config");
            if (string.IsNullOrWhiteSpace(configField))
                throw new Exception("в ответе шлюза нет конфигурации.");

            // Поле config — это тело ссылки vpn:// (base64url от qCompress(JSON)).
            JsonObject serverConfig = AmneziaLink.DecodePayload(configField);
            if (serverConfig == null)
                throw new Exception("не удалось распаковать конфигурацию из ответа шлюза.");

            Log("  конфиг распакован, поля: " + string.Join(", ", serverConfig.Keys));
            foreach (var c in EnumerateContainers(serverConfig))
                Log("  контейнер: " + string.Join(", ", c.Keys));

            string reason;
            var parsed = AmneziaLink.ParseRoot(serverConfig, out reason);

            VlessProfile profile;
            if (parsed != null)
            {
                string conf = parsed.ConfText.Replace("$WIREGUARD_CLIENT_PRIVATE_KEY", privB64);
                if (conf.IndexOf("$WIREGUARD_CLIENT_PRIVATE_KEY", StringComparison.Ordinal) >= 0)
                    throw new Exception("в конфигурации остался неподставленный приватный ключ.");

                profile = VlessProfile.FromWgConfig(conf, groupName);
                if (profile == null)
                    throw new Exception("конфигурация от шлюза не содержит корректного [Peer] Endpoint.");
            }
            else
            {
                // Контейнера AmneziaWG нет — значит шлюз выдал другой протокол
                // (скорее всего vless). Пробуем разобрать, а если не выходит,
                // отдаём наружу обезличенную структуру ответа: по ней можно
                // дописать разбор, не гадая по заголовочным файлам.
                profile = TryParseNonWg(serverConfig, groupName);
                if (profile == null)
                    throw new UnsupportedConfigException(
                        $"шлюз выдал конфиг протокола «{protocol}», разобрать его мы пока не умеем ({reason}).",
                        Sanitize(serverConfig));
            }

            // Всё интересное про подписку лежит в api_config внутри выданного
            // конфига: список стран с их протоколами, текущая страна, счётчик
            // устройств и срок действия. Раньше мы это молча выбрасывали, из-за
            // чего подписка выглядела как один-единственный сервер.
            ApplyApiConfig(profile, serverConfig, sub);

            // parsed заполнен только в ветке AmneziaWG: у vless-конфига
            // контейнера awg нет, и обращение к parsed.Name роняло импорт.
            string parsedName = parsed != null ? parsed.Name : null;
            string configName = GetStr(serverConfig, "description") ?? GetStr(serverConfig, "name");

            profile.Name = FirstNonEmpty(profile.AmneziaCountryName, parsedName, configName, sub.Name, "Amnezia Premium");
            // Ключ группы — сама ссылка vpn://, показывать её нельзя.
            profile.GroupTitle = FirstNonEmpty(sub.Name, parsedName, configName, "Amnezia Premium");
            result.Add(profile);
            return result;
        }

        // Конфиг пришёл, но разобрать его нечем. Несёт обезличенную структуру
        // ответа, чтобы её можно было показать и скопировать.
        public sealed class UnsupportedConfigException : Exception
        {
            public string Dump { get; private set; }
            public UnsupportedConfigException(string message, string dump) : base(message) { Dump = dump; }
        }

        // Попытка вытащить профиль из контейнера, отличного от AmneziaWG.
        // Внутри last_config у Amnezia лежит готовая клиентская конфигурация —
        // либо ссылка vless://, либо JSON xray с outbounds. И то и другое наш
        // разбор ссылок уже умеет, поэтому просто передаём ему текст.
        private static VlessProfile TryParseNonWg(JsonObject serverConfig, string groupName)
        {
            // Адрес сервера лежит на верхнем уровне конфига, а порт — в самом
            // контейнере; в outbound их может не быть.
            string host = GetStr(serverConfig, "hostName") ?? "";
            string name = GetStr(serverConfig, "description") ?? GetStr(serverConfig, "name") ?? "";

            foreach (var container in EnumerateContainers(serverConfig))
            {
                foreach (var key in new[] { "xray", "vless", "ssxray", "shadowsocks" })
                {
                    JsonObject inner = null;
                    try { if (container.ContainsKey(key)) inner = container.GetNamedObject(key); }
                    catch { }
                    if (inner == null) continue;

                    int port = 0;
                    string portStr = GetStr(inner, "port");
                    if (!string.IsNullOrEmpty(portStr)) int.TryParse(portStr, out port);
                    if (port == 0) port = GetInt(inner, "port");

                    string lastConfig = GetStr(inner, "last_config");
                    if (string.IsNullOrWhiteSpace(lastConfig))
                    {
                        Log($"  контейнер «{key}» без last_config.");
                        continue;
                    }

                    // Структуру печатаем всегда, а не только при неудаче: профиль
                    // может собраться и с пустым SNI, а увидеть это по одному
                    // «разобран» невозможно — соединение просто молчит.
                    JsonObject lastObj;
                    if (JsonObject.TryParse(lastConfig, out lastObj))
                        Log("  last_config: " + Sanitize(lastObj));
                    else
                        Log($"  last_config не JSON ({lastConfig.Length}б), начало: " +
                            lastConfig.Substring(0, Math.Min(120, lastConfig.Length)));

                    // Сначала как клиентский конфиг xray (Amnezia кладёт именно
                    // его), затем — как ссылку или обёртку с ссылкой внутри.
                    var p = VlessProfile.FromXrayClientConfig(lastConfig, groupName, name, host, port)
                            ?? ParseClientConfigText(lastConfig, groupName);

                    if (p != null)
                    {
                        Log($"  контейнер «{key}» разобран: {p.Type}/{p.Security} {p.Address}:{p.Port}" +
                            (string.IsNullOrEmpty(p.Flow) ? "" : " flow=" + p.Flow));
                        // Без этих полей REALITY не поднимется, а по одному лишь
                        // «разобран» пустой SNI был незаметен.
                        if (string.Equals(p.Security, "reality", StringComparison.OrdinalIgnoreCase))
                        {
                            Log($"    reality: sni='{p.Sni}', shortId='{p.ShortId}', " +
                                $"pbk={(p.PublicKey ?? "").Length} симв.");
                            if (p.HasAmneziaChain)
                                Log($"    цепочка: реле {p.Address}:{p.Port} → выход {p.AmneziaExitHost}:{p.AmneziaExitPort}" +
                                    $" (flow={p.AmneziaExitFlow}, pbk={(p.AmneziaExitPublicKey ?? "").Length} симв.)");
                            else
                                Log("    цепочки нет: второй outbound не найден или без адреса.");
                        }
                        return p;
                    }
                    Log($"  контейнер «{key}» найден, но last_config не разобрался ({lastConfig.Length}б).");
                }
            }
            return null;
        }

        private static VlessProfile ParseClientConfigText(string text, string groupName)
        {
            text = text.Trim();

            // Готовая ссылка внутри текста или JSON-поля.
            int idx = text.IndexOf("vless://", StringComparison.OrdinalIgnoreCase);
            if (idx >= 0)
            {
                int end = text.IndexOfAny(new[] { '"', '\r', '\n', ' ' }, idx);
                string url = end > idx ? text.Substring(idx, end - idx) : text.Substring(idx);
                var p = VlessProfile.Parse(url);
                if (p != null) { p.SubscriptionGroup = groupName; return p; }
            }

            // JSON: либо сам xray-конфиг с outbounds, либо обёртка, внутри
            // которой ссылка лежит отдельным полем.
            JsonObject obj;
            if (JsonObject.TryParse(text, out obj))
            {
                foreach (var field in new[] { "config", "vpn_key", "url", "link" })
                {
                    string nested = GetStr(obj, field);
                    if (string.IsNullOrWhiteSpace(nested)) continue;
                    var p = ParseClientConfigText(nested, groupName);
                    if (p != null) return p;
                }
            }
            return null;
        }

        private static IEnumerable<JsonObject> EnumerateContainers(JsonObject serverConfig)
        {
            JsonArray arr = null;
            try { if (serverConfig.ContainsKey("containers")) arr = serverConfig.GetNamedArray("containers"); }
            catch { }
            if (arr == null) yield break;

            foreach (var item in arr)
            {
                JsonObject o = null;
                try { o = item.GetObject(); } catch { }
                if (o != null) yield return o;
            }
        }

        // Обезличенный слепок ответа: сохраняем структуру и значения-перечисления,
        // но вычищаем всё, что является ключом или адресом. Такой текст можно
        // показать и переслать, не раскрывая доступ к подписке.
        public static string Sanitize(JsonObject root)
        {
            var sb = new StringBuilder();
            WriteValue(sb, root, 0);
            return sb.ToString();
        }

        private static readonly string[] SecretKeys =
        {
            "private_key","privatekey","password","api_key","apikey","uuid","id","client_id",
            "public_key","publickey","psk","preshared","secret","token","vpn_key","hostname","host",
            "address","server","endpoint","ip","sni","short_id","shortid"
        };

        private static bool IsSecret(string key)
        {
            string k = (key ?? "").ToLowerInvariant().Replace("-", "").Replace("_", "");
            foreach (var s in SecretKeys)
                if (k == s.Replace("_", "")) return true;
            return false;
        }

        private static void WriteValue(StringBuilder sb, IJsonValue v, int depth, string keyName = null)
        {
            string pad = new string(' ', depth * 2);
            switch (v.ValueType)
            {
                case JsonValueType.Object:
                    sb.AppendLine("{");
                    var o = v.GetObject();
                    foreach (var k in o.Keys)
                    {
                        sb.Append(pad).Append("  \"").Append(k).Append("\": ");
                        WriteValue(sb, o[k], depth + 1, k);
                        sb.AppendLine();
                    }
                    sb.Append(pad).Append("}");
                    break;

                case JsonValueType.Array:
                    var a = v.GetArray();
                    sb.AppendLine("[");
                    for (int i = 0; i < a.Count && i < 8; i++)
                    {
                        sb.Append(pad).Append("  ");
                        WriteValue(sb, a[i], depth + 1);
                        sb.AppendLine(i + 1 < a.Count ? "," : "");
                    }
                    if (a.Count > 8) sb.Append(pad).AppendLine($"  … ещё {a.Count - 8}");
                    sb.Append(pad).Append("]");
                    break;

                case JsonValueType.String:
                    string s = v.GetString();
                    if (IsSecret(keyName) || LooksSecret(s))
                    {
                        sb.Append("\"<скрыто:").Append(s.Length).Append(">\"");
                        break;
                    }

                    // Внутри строки может лежать вложенный JSON — так устроен
                    // last_config. Свернуть его в «длинная строка» значило бы
                    // спрятать ровно то, ради чего дамп и делается.
                    if (s.Length > 40 && (s.TrimStart().StartsWith("{") || s.TrimStart().StartsWith("[")))
                    {
                        JsonObject nestedObj;
                        JsonArray nestedArr;
                        if (JsonObject.TryParse(s, out nestedObj))
                        {
                            sb.Append("<вложенный JSON> ");
                            WriteValue(sb, nestedObj, depth);
                            break;
                        }
                        if (JsonArray.TryParse(s, out nestedArr))
                        {
                            sb.Append("<вложенный JSON> ");
                            WriteValue(sb, nestedArr, depth);
                            break;
                        }
                    }

                    if (s.Length > 200) sb.Append("\"<длинная строка:").Append(s.Length).Append(">\"");
                    else sb.Append("\"").Append(s).Append("\"");
                    break;

                default:
                    sb.Append(v.Stringify());
                    break;
            }
        }

        private static bool LooksSecret(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            if (s.Length == 36 && s[8] == '-' && s[13] == '-') return true;              // uuid
            if ((s.Length == 43 || s.Length == 44) && s.IndexOf(' ') < 0) return true;   // ключ base64
            return false;
        }

        // Строки для всех сочетаний «страна × протокол», кроме уже выданного.
        // Конфига под ними ещё нет: он запрашивается по нажатию, потому что
        // шлюз выдаёт их по одному.
        public static List<VlessProfile> BuildCountryRows(VlessProfile issued, string groupName)
        {
            var rows = new List<VlessProfile>();
            if (issued == null) return rows;

            foreach (var c in DeserializeCountries(issued.AmneziaCountries))
            {
                var protocols = c.Protocols.Count > 0 ? c.Protocols : new List<string> { "awg" };
                foreach (var proto in protocols)
                {
                    bool isIssued = string.Equals(c.Code, issued.AmneziaCountryCode, StringComparison.OrdinalIgnoreCase) &&
                                    string.Equals(proto, issued.AmneziaProtocol, StringComparison.OrdinalIgnoreCase);
                    if (isIssued) continue;

                    rows.Add(new VlessProfile
                    {
                        Name = string.IsNullOrEmpty(c.Name) ? c.Code.ToUpperInvariant() : c.Name,
                        SubscriptionGroup = groupName,
                        GroupTitle = issued.GroupTitle,
                        GroupTitleCustom = issued.GroupTitleCustom,
                        Address = "",
                        Port = 0,
                        Uuid = "",
                        Type = proto,
                        Security = "none",
                        AmneziaNotIssued = true,
                        AmneziaCountries = issued.AmneziaCountries,
                        AmneziaCountryCode = c.Code,
                        AmneziaCountryName = c.Name,
                        AmneziaProtocol = proto,
                        AmneziaInfo = issued.AmneziaInfo,
                        // Флаг берётся из кода страны напрямую, а не из имени.
                        CountryCode = c.Code.ToUpperInvariant(),
                        LastUpdated = issued.LastUpdated
                    });
                }
            }
            return rows;
        }

        private static void ApplyApiConfig(VlessProfile profile, JsonObject serverConfig, Subscription sub)
        {
            JsonObject api = null;
            try { if (serverConfig.ContainsKey("api_config")) api = serverConfig.GetNamedObject("api_config"); }
            catch { }
            if (api == null)
            {
                Log("  в конфиге нет api_config — список стран недоступен.");
                profile.AmneziaCountryCode = sub.ServerCountryCode ?? "";
                return;
            }

            profile.AmneziaCountryCode = FirstNonEmpty(GetStr(api, "server_country_code"), sub.ServerCountryCode);
            profile.AmneziaCountryName = GetStr(api, "server_country_name") ?? "";
            // Флаг рисуется по коду страны, а не по разбору имени.
            if (!string.IsNullOrEmpty(profile.AmneziaCountryCode))
                profile.CountryCode = profile.AmneziaCountryCode.ToUpperInvariant();
            profile.AmneziaProtocol = FirstNonEmpty(GetStr(api, "service_protocol"), sub.ServiceProtocol, "awg");

            var countries = ParseCountries(api);
            profile.AmneziaCountries = SerializeCountries(countries);

            int active = GetInt(api, "active_device_count");
            int max = GetInt(api, "max_device_count");
            string until = "";
            try
            {
                if (api.ContainsKey("subscription"))
                    until = GetStr(api.GetNamedObject("subscription"), "end_date") ?? "";
            }
            catch { }

            var bits = new List<string>();
            if (max > 0) bits.Add($"Устройств: {active} из {max}");
            if (!string.IsNullOrEmpty(until)) bits.Add("Подписка до " + until.Substring(0, Math.Min(10, until.Length)));
            profile.AmneziaInfo = string.Join(" · ", bits);

            Log($"  выдана страна {profile.AmneziaCountryCode}/{profile.AmneziaCountryName}, " +
                $"протокол {profile.AmneziaProtocol}. {profile.AmneziaInfo}");
            Log($"  доступно стран: {countries.Count}");
            // Протоколы по странам печатаем поимённо: диалог выбора протокола
            // показывается только когда их больше одного, и без этого списка
            // непонятно, пуст ли available_protocols или там правда один awg.
            foreach (var c in countries)
                Log($"    {c.Code} {c.Name} — протоколы: " +
                    (c.Protocols.Count == 0 ? "<список пуст>" : string.Join(", ", c.Protocols)));
        }

        public static List<Country> ParseCountries(JsonObject api)
        {
            var list = new List<Country>();
            if (api == null || !api.ContainsKey("available_countries")) return list;

            JsonArray arr;
            try { arr = api.GetNamedArray("available_countries"); }
            catch { return list; }

            foreach (var item in arr)
            {
                JsonObject o;
                try { o = item.GetObject(); } catch { continue; }

                var c = new Country
                {
                    Code = GetStr(o, "server_country_code") ?? "",
                    Name = GetStr(o, "server_country_name") ?? ""
                };
                if (string.IsNullOrEmpty(c.Code) && string.IsNullOrEmpty(c.Name)) continue;

                try
                {
                    if (o.ContainsKey("available_protocols"))
                        foreach (var p in o.GetNamedArray("available_protocols"))
                            if (p.ValueType == JsonValueType.String) c.Protocols.Add(p.GetString());
                }
                catch { }
                list.Add(c);
            }
            return list;
        }

        // Список стран хранится в профиле строкой: «код|имя|awg,vless» через ';'.
        // Отдельная модель ради этого не нужна, а DataContract-сериализация
        // списка объектов потребовала бы менять формат profiles.json.
        public static string SerializeCountries(List<Country> countries)
        {
            var parts = new List<string>();
            foreach (var c in countries)
                parts.Add($"{c.Code}|{c.Name}|{string.Join(",", c.Protocols)}");
            return string.Join(";", parts);
        }

        public static List<Country> DeserializeCountries(string s)
        {
            var list = new List<Country>();
            if (string.IsNullOrWhiteSpace(s)) return list;
            foreach (var chunk in s.Split(';'))
            {
                if (chunk.Length == 0) continue;
                var f = chunk.Split('|');
                var c = new Country { Code = f.Length > 0 ? f[0] : "", Name = f.Length > 1 ? f[1] : "" };
                if (f.Length > 2 && f[2].Length > 0) c.Protocols.AddRange(f[2].Split(','));
                list.Add(c);
            }
            return list;
        }

        private static int GetInt(JsonObject o, string key)
        {
            if (o == null || !o.ContainsKey(key)) return 0;
            try
            {
                var v = o.GetNamedValue(key);
                return v.ValueType == JsonValueType.Number ? (int)v.GetNumber() : 0;
            }
            catch { return 0; }
        }

        // =====================================================================
        // Транспорт
        // =====================================================================

        private static async Task<string> PostAsync(string path, JsonObject apiPayload)
        {
            byte[] key = CryptoBytes(32);
            byte[] iv = CryptoBytes(32);
            byte[] salt = CryptoBytes(8);

            var keyPayload = new JsonObject();
            keyPayload["aes_key"] = JsonValue.CreateStringValue(Convert.ToBase64String(key));
            keyPayload["aes_iv"] = JsonValue.CreateStringValue(Convert.ToBase64String(iv));
            keyPayload["aes_salt"] = JsonValue.CreateStringValue(Convert.ToBase64String(salt));

            byte[] encKey = RsaEncryptPkcs1(Encoding.UTF8.GetBytes(keyPayload.Stringify()));
            byte[] encApi = AesCbc(Encoding.UTF8.GetBytes(apiPayload.Stringify()), key, iv, true);

            var body = new JsonObject();
            body["key_payload"] = JsonValue.CreateStringValue(Convert.ToBase64String(encKey));
            body["api_payload"] = JsonValue.CreateStringValue(Convert.ToBase64String(encApi));

            string requestBody = body.Stringify();
            Log($"  запрос: key_payload {encKey.Length}б, api_payload {encApi.Length}б, тело {requestBody.Length}б");

            int lastStatus = 0;
            string lastRaw = "";

            // Сначала основной адрес, затем — прокси из списка. Ровно тот же
            // порядок, что у оригинального клиента.
            var targets = new List<string> { GatewayEndpoint };
            byte[] plain = await TrySendAsync(targets, path, requestBody, key, iv, r => { lastStatus = r.Status; lastRaw = r.Raw; });

            if (plain == null)
            {
                Log("  основной адрес не дал разбираемого ответа — идём в обход через прокси.");
                var proxies = await GetProxyUrlsAsync(
                    GetStr(apiPayload, "service_type"), GetStr(apiPayload, "user_country_code"));

                if (proxies.Count == 0)
                    Log("  список прокси пуст — обходить нечем.");
                else
                    plain = await TrySendAsync(proxies, path, requestBody, key, iv, r => { lastStatus = r.Status; lastRaw = r.Raw; });
            }

            if (plain == null)
                throw new GatewayException(BuildPlainErrorMessage(lastStatus, lastRaw), lastStatus, lastRaw);

            string decoded = Encoding.UTF8.GetString(plain);
            Log($"  расшифровано {plain.Length}б: {(decoded.Length > 400 ? decoded.Substring(0, 400) + "…" : decoded)}");
            return decoded;
        }

        private struct SendResult
        {
            public int Status;
            public string Raw;
        }

        private static async Task<byte[]> TrySendAsync(List<string> baseUrls, string path, string requestBody,
                                                       byte[] key, byte[] iv, Action<SendResult> onFailure)
        {
            foreach (var baseUrl in baseUrls)
            {
                string url = baseUrl + path;
                string requestId = Guid.NewGuid().ToString();
                Log($"POST {url}  (request-id {requestId})");

                byte[] responseBytes;
                int status;
                try
                {
                    using (var client = new HttpClient())
                    {
                        client.Timeout = TimeSpan.FromSeconds(20);
                        var request = new HttpRequestMessage(HttpMethod.Post, url);
                        request.Content = new StringContent(requestBody, Encoding.UTF8, "application/json");
                        request.Headers.TryAddWithoutValidation("X-Client-Request-ID", requestId);

                        var response = await client.SendAsync(request);
                        status = (int)response.StatusCode;
                        responseBytes = await response.Content.ReadAsByteArrayAsync();
                        string ctype = response.Content.Headers.ContentType != null
                            ? response.Content.Headers.ContentType.ToString() : "—";
                        Log($"  ответ: HTTP {status}, {responseBytes.Length}б, Content-Type {ctype}");
                        Log($"  первые байты: {Hex(responseBytes, 24)}");
                    }
                }
                catch (Exception ex)
                {
                    Log($"  сеть: {ex.GetType().Name}: {ex.Message}");
                    onFailure(new SendResult { Status = 0, Raw = ex.Message });
                    continue;
                }

                if (responseBytes.Length == 0)
                {
                    Log("  тело пустое.");
                    onFailure(new SendResult { Status = status, Raw = "" });
                    continue;
                }

                byte[] plain = null;
                if (responseBytes.Length % 16 == 0)
                {
                    try { plain = AesCbc(responseBytes, key, iv, false); }
                    catch (Exception ex) { Log($"  расшифровка не удалась: {ex.Message}"); }
                }
                else
                {
                    Log($"  длина {responseBytes.Length} не кратна 16 — это не шифротекст AES-CBC.");
                }

                if (plain != null && !LooksIntercepted(plain, true)) return plain;

                string raw = AsText(responseBytes, 800);
                if (plain == null && raw.IndexOf("html", StringComparison.OrdinalIgnoreCase) >= 0)
                    Log("  в теле HTML — запрос перехвачен по дороге, до шлюза он не дошёл.");
                Log($"  тело как текст: {raw}");
                onFailure(new SendResult { Status = status, Raw = raw });
            }
            return null;
        }

        // =====================================================================
        // Обход блокировки
        // =====================================================================
        // Основной адрес шлюза — обычный HTTP на порту 80 с известным именем,
        // поэтому операторы его перехватывают и подсовывают свою страницу
        // (у МегаФона это m.megafonpro.ru/rkn с HTTP 200 и text/html).
        // Официальный клиент на такой ответ уходит на прокси из списка,
        // который лежит в облачных хранилищах в зашифрованном виде.

        private static List<string> _proxyCache;

        private static async Task<List<string>> GetProxyUrlsAsync(string serviceType, string userCountryCode)
        {
            if (_proxyCache != null && _proxyCache.Count > 0) return _proxyCache;

            var names = new List<string>();
            if (!string.IsNullOrEmpty(serviceType))
                names.Add(Base64Url("endpoints-" + serviceType + "-" + (userCountryCode ?? "")) + ".json");
            names.Add("endpoints.json");

            foreach (var baseUrl in ProxyStorageBases)
            {
                foreach (var name in names)
                {
                    string url = baseUrl + name;
                    try
                    {
                        string body;
                        using (var client = new HttpClient())
                        {
                            client.Timeout = TimeSpan.FromSeconds(15);
                            var resp = await client.GetAsync(url);
                            if (!resp.IsSuccessStatusCode)
                            {
                                Log($"  список прокси: {url} → HTTP {(int)resp.StatusCode}");
                                continue;
                            }
                            body = await resp.Content.ReadAsStringAsync();
                        }

                        var list = DecryptProxyList(body);
                        if (list != null && list.Count > 0)
                        {
                            Log($"  список прокси получен из {url}: {list.Count} шт.");
                            foreach (var u in list) Log("    " + u);
                            _proxyCache = list;
                            return list;
                        }
                        Log($"  список прокси из {url} не расшифровался.");
                    }
                    catch (Exception ex)
                    {
                        Log($"  список прокси: {url} — {ex.GetType().Name}: {ex.Message}");
                    }
                }
            }
            return new List<string>();
        }

        // Ключ и IV — из SHA512 текста PEM: первые 32 байта и следующие 16.
        private static List<string> DecryptProxyList(string base64Body)
        {
            try
            {
                byte[] cipher = Convert.FromBase64String((base64Body ?? "").Trim());

                var sha = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha512);
                IBuffer digest = sha.HashData(CryptographicBuffer.ConvertStringToBinary(
                    ProdPublicKeyPemText, BinaryStringEncoding.Utf8));
                byte[] h;
                CryptographicBuffer.CopyToByteArray(digest, out h);

                byte[] key = new byte[32];
                byte[] iv = new byte[16];
                System.Buffer.BlockCopy(h, 0, key, 0, 32);
                System.Buffer.BlockCopy(h, 32, iv, 0, 16);

                byte[] plain = AesCbcRaw(cipher, key, iv, false);
                string json = Encoding.UTF8.GetString(plain);

                JsonArray arr;
                if (!JsonArray.TryParse(json, out arr)) return null;

                var list = new List<string>();
                foreach (var v in arr)
                    if (v.ValueType == JsonValueType.String) list.Add(v.GetString());
                return list;
            }
            catch (Exception ex)
            {
                Log("  расшифровка списка прокси не удалась: " + ex.Message);
                return null;
            }
        }

        private static string Base64Url(string s)
        {
            string b = Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
            return b.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        // Признаки того, что ответ пришёл не от шлюза: так же решает
        // shouldBypassProxy в оригинальном клиенте.
        private static bool LooksIntercepted(byte[] body, bool decrypted)
        {
            if (!decrypted) return true;
            string s = AsText(body, 400).ToLowerInvariant();
            return s.Contains("html");
        }

        // Из открытого тела вытаскиваем понятную причину: шлюз обычно кладёт её
        // в поле message, но может ответить и HTML от промежуточного прокси.
        private static string BuildPlainErrorMessage(int status, string raw)
        {
            string body = (raw ?? "").Trim();

            JsonObject o;
            if (JsonObject.TryParse(body, out o))
            {
                string msg = GetStr(o, "message") ?? GetStr(o, "error") ?? GetStr(o, "detail");
                if (!string.IsNullOrWhiteSpace(msg))
                    return $"шлюз Amnezia отказал (HTTP {status}): {msg}";
            }

            if (body.StartsWith("<", StringComparison.Ordinal) ||
                body.IndexOf("html", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                string who = body.IndexOf("rkn", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             body.IndexOf("megafon", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             body.IndexOf("beeline", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             body.IndexOf("mts", StringComparison.OrdinalIgnoreCase) >= 0
                    ? "оператором связи" : "по дороге";
                return $"запрос к шлюзу Amnezia перехвачен {who}: вместо ответа пришла HTML-страница (HTTP {status}). " +
                       "Обход через запасные адреса тоже не сработал. Попробуйте с Wi-Fi или подключите сначала любой рабочий сервер, " +
                       "чтобы запрос ушёл через туннель.";
            }

            if (body.Length == 0)
                return $"шлюз Amnezia вернул HTTP {status} без тела.";

            return $"шлюз Amnezia вернул HTTP {status}, ответ не шифрован: " +
                   (body.Length > 200 ? body.Substring(0, 200) + "…" : body);
        }

        private static byte[] CryptoBytes(uint n)
        {
            var buf = CryptographicBuffer.GenerateRandom(n);
            byte[] o;
            CryptographicBuffer.CopyToByteArray(buf, out o);
            return o;
        }

        private static byte[] RsaEncryptPkcs1(byte[] data)
        {
            var provider = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);
            IBuffer der = CryptographicBuffer.DecodeFromBase64String(ProdPublicKeyPem);
            var pubKey = provider.ImportPublicKey(der, CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);
            IBuffer outBuf = CryptographicEngine.Encrypt(pubKey, CryptographicBuffer.CreateFromByteArray(data), null);
            byte[] o;
            CryptographicBuffer.CopyToByteArray(outBuf, out o);
            return o;
        }

        // IV приходит 32-байтовым, но AES-CBC использует только первые 16 —
        // ровно так же ведёт себя OpenSSL в оригинальном клиенте.
        private static byte[] AesCbc(byte[] data, byte[] key, byte[] iv32, bool encrypt)
        {
            byte[] iv16 = new byte[16];
            System.Buffer.BlockCopy(iv32, 0, iv16, 0, 16);
            return AesCbcRaw(data, key, iv16, encrypt);
        }

        private static byte[] AesCbcRaw(byte[] data, byte[] key, byte[] iv16, bool encrypt)
        {
            var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            var symKey = provider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(key));
            IBuffer ivBuf = CryptographicBuffer.CreateFromByteArray(iv16);
            IBuffer inBuf = CryptographicBuffer.CreateFromByteArray(data);
            IBuffer outBuf = encrypt
                ? CryptographicEngine.Encrypt(symKey, inBuf, ivBuf)
                : CryptographicEngine.Decrypt(symKey, inBuf, ivBuf);
            byte[] o;
            CryptographicBuffer.CopyToByteArray(outBuf, out o);
            return o;
        }

        // Шлюз считает устройства по installation_uuid, поэтому он должен быть
        // постоянным: новый uuid на каждый импорт съедал бы слоты подписки.
        private static string GetInstallationUuid()
        {
            var settings = Windows.Storage.ApplicationData.Current.LocalSettings;
            const string k = "v_AmneziaInstallationUuid";
            string v = settings.Values.ContainsKey(k) ? settings.Values[k] as string : null;
            if (string.IsNullOrEmpty(v))
            {
                v = Guid.NewGuid().ToString();
                settings.Values[k] = v;
            }
            return v;
        }

        private static string GetStr(JsonObject o, string key)
        {
            if (o == null || !o.ContainsKey(key)) return null;
            try
            {
                var v = o.GetNamedValue(key);
                return v.ValueType == JsonValueType.String ? v.GetString() : null;
            }
            catch { return null; }
        }

        private static string FirstNonEmpty(params string[] values)
        {
            foreach (var v in values)
                if (!string.IsNullOrWhiteSpace(v)) return v;
            return "";
        }

        // =====================================================================
        // X25519 — только для генерации пары ключей WireGuard при импорте.
        // Лестница Монтгомери на BigInteger: вызывается один раз за импорт,
        // поэтому скорость не важна, а короткий код проще проверить.
        // =====================================================================
        internal static class X25519
        {
            private static readonly BigInteger P =
                (BigInteger.One << 255) - 19;
            private const int A24 = 121665;

            public static byte[] CreateRandomPrivateKey()
            {
                byte[] k = CryptoBytes(32);
                k[0] &= 248; k[31] &= 127; k[31] |= 64;
                return k;
            }

            public static byte[] GetPublicKey(byte[] privateKey)
            {
                byte[] basePoint = new byte[32];
                basePoint[0] = 9;
                return ScalarMult(privateKey, basePoint);
            }

            public static byte[] ScalarMult(byte[] scalar, byte[] uCoord)
            {
                byte[] k = (byte[])scalar.Clone();
                k[0] &= 248; k[31] &= 127; k[31] |= 64;

                byte[] u = (byte[])uCoord.Clone();
                u[31] &= 0x7F;                       // RFC 7748: старший бит u игнорируется
                BigInteger x1 = FromLe(u);

                BigInteger x2 = BigInteger.One, z2 = BigInteger.Zero;
                BigInteger x3 = x1, z3 = BigInteger.One;
                int swap = 0;

                for (int t = 254; t >= 0; t--)
                {
                    int kt = (k[t >> 3] >> (t & 7)) & 1;
                    swap ^= kt;
                    CSwap(swap, ref x2, ref x3);
                    CSwap(swap, ref z2, ref z3);
                    swap = kt;

                    BigInteger a = Mod(x2 + z2);
                    BigInteger aa = Mod(a * a);
                    BigInteger b = Mod(x2 - z2);
                    BigInteger bb = Mod(b * b);
                    BigInteger e = Mod(aa - bb);
                    BigInteger c = Mod(x3 + z3);
                    BigInteger d = Mod(x3 - z3);
                    BigInteger da = Mod(d * a);
                    BigInteger cb = Mod(c * b);

                    x3 = Mod((da + cb) * (da + cb));
                    z3 = Mod(x1 * Mod((da - cb) * (da - cb)));
                    x2 = Mod(aa * bb);
                    z2 = Mod(e * (aa + A24 * e));
                }

                CSwap(swap, ref x2, ref x3);
                CSwap(swap, ref z2, ref z3);

                BigInteger res = Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
                return ToLe(res);
            }

            private static void CSwap(int swap, ref BigInteger a, ref BigInteger b)
            {
                if (swap == 0) return;
                BigInteger t = a; a = b; b = t;
            }

            private static BigInteger Mod(BigInteger v)
            {
                BigInteger r = v % P;
                if (r.Sign < 0) r += P;
                return r;
            }

            private static BigInteger FromLe(byte[] le)
            {
                byte[] t = new byte[le.Length + 1];   // хвостовой ноль — число без знака
                System.Buffer.BlockCopy(le, 0, t, 0, le.Length);
                return new BigInteger(t);
            }

            private static byte[] ToLe(BigInteger v)
            {
                byte[] raw = v.ToByteArray();
                byte[] o = new byte[32];
                System.Buffer.BlockCopy(raw, 0, o, 0, Math.Min(32, raw.Length));
                return o;
            }
        }
    }
}
