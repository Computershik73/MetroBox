using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.Serialization;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Media;
using Windows.UI;
using Windows.Data.Json; // Добавлен стандартный UWP JSON-парсер

namespace VlessApp
{
    [DataContract]
    public class VlessProfile : INotifyPropertyChanged
    {
        [DataMember] public string Name { get; set; } = "Vless-Reality";
        [DataMember] public string Address { get; set; }
        [DataMember] public int Port { get; set; } = 443;
        [DataMember] public string Uuid { get; set; }
        [DataMember] public string Type { get; set; } = "tcp";
        [DataMember] public string Security { get; set; } = "reality";
        [DataMember] public string Flow { get; set; }
        [DataMember] public string Sni { get; set; }
        [DataMember] public string PublicKey { get; set; }
        [DataMember] public string ShortId { get; set; }
        [DataMember] public string Path { get; set; }
        [DataMember] public string Host { get; set; }
        [DataMember] public string Alpn { get; set; }
        [DataMember] public string SubscriptionGroup { get; set; } = "Ручной импорт";

        // Поля хранения метаданных подписки
        [DataMember] public DateTime LastUpdated { get; set; } = DateTime.Now;
        [DataMember] public string Description { get; set; } = "";
        [DataMember] public string InfoUrl { get; set; } = "";
        [DataMember] public string TelegramUrl { get; set; } = "";

        [DataMember] public string Mode { get; set; } = "";

        private string _pingText = "";
        public string PingText
        {
            get => _pingText;
            set
            {
                if (_pingText != value)
                {
                    _pingText = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(DisplayText));
                }
            }
        }
        private string _cleanPingText = "";
        [IgnoreDataMember]
        public string CleanPingText
        {
            get => _cleanPingText;
            set
            {
                if (_cleanPingText != value)
                {
                    _cleanPingText = value;
                    OnPropertyChanged();
                }
            }
        }

        public string DisplayText => $"{Type} / {Security} | {Address}:{Port}";

        // Выделение активного сервера
        private bool _isSelected = false;
        [IgnoreDataMember]
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected != value)
                {
                    _isSelected = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(ItemBackgroundBrush));
                    OnPropertyChanged(nameof(SelectedIndicatorVisibility));
                }
            }
        }

        [IgnoreDataMember]
        public Brush ItemBackgroundBrush => IsSelected
            ? new SolidColorBrush(Color.FromArgb(255, 30, 41, 73))
            : new SolidColorBrush(Color.FromArgb(255, 18, 24, 45));

        [IgnoreDataMember]
        public Visibility SelectedIndicatorVisibility => IsSelected ? Visibility.Visible : Visibility.Collapsed;

        // Поля свайпа и инлайн шаринга
        private bool _isShareOpen = false;
        [IgnoreDataMember]
        public bool IsShareOpen
        {
            get => _isShareOpen;
            set
            {
                if (_isShareOpen != value)
                {
                    _isShareOpen = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(SharePanelVisibility));
                    OnPropertyChanged(nameof(DefaultActionsVisibility));
                }
            }
        }

        [IgnoreDataMember]
        public Visibility SharePanelVisibility => IsShareOpen ? Visibility.Visible : Visibility.Collapsed;

        [IgnoreDataMember]
        public Visibility DefaultActionsVisibility => IsShareOpen ? Visibility.Collapsed : Visibility.Visible;


        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        // =========================================================================
        // 1. БЕЗОПАСНЫЙ ПАРСИНГ ОДНОЙ ССЫЛКИ VLESS
        // =========================================================================
        public static VlessProfile Parse(string url)
        {
            if (string.IsNullOrWhiteSpace(url) || !url.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
                return null;

            try
            {
                var uri = new Uri(url);
                var profile = new VlessProfile
                {
                    Uuid = uri.UserInfo.Replace("-", ""),
                    Address = uri.Host,
                    Port = uri.Port > 0 ? uri.Port : 443,
                    Name = string.IsNullOrEmpty(uri.Fragment) ? "Vless-Reality" : Uri.UnescapeDataString(uri.Fragment.TrimStart('#'))
                };

                string query = uri.Query.TrimStart('?');
                var pairs = query.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries);

                foreach (var pair in pairs)
                {
                    var kv = pair.Split(new[] { '=' }, 2);
                    if (kv.Length == 2)
                    {
                        string key = kv[0].ToLowerInvariant();
                        string val = Uri.UnescapeDataString(kv[1]);

                        switch (key)
                        {
                            case "type": profile.Type = val; break;
                            case "security": profile.Security = val; break;
                            case "sni": profile.Sni = val; break;
                            case "sid":
                            case "shortid": profile.ShortId = val; break;
                            case "flow": profile.Flow = val; break;
                            case "path": profile.Path = val; break;
                            case "host": profile.Host = val; break;
                            case "alpn": profile.Alpn = val; break;
                            case "mode": profile.Mode = val; break;
                            case "pbk":
                            case "publickey":
                                val = val.Replace("-", "+").Replace("_", "/");
                                while (val.Length % 4 != 0) val += "=";
                                profile.PublicKey = val;
                                break;
                        }
                    }
                }

                return string.IsNullOrEmpty(profile.Uuid) || string.IsNullOrEmpty(profile.Address) ? null : profile;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PARSE ERROR] Ошибка разбора ссылки: {url}");
                Debug.WriteLine($"[PARSE ERROR] Детали: {ex.Message}");
                return null;
            }
        }

        // Вспомогательный декодер системных Base64-заголовков HTTP
        private static string DecodeHeaderValueSafe(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";

            value = value.Trim();
            if (value.StartsWith("base64:", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string base64Part = value.Substring(7).Trim();
                    base64Part = base64Part.Replace("-", "+").Replace("_", "/");
                    int padding = base64Part.Length % 4;
                    if (padding > 0) base64Part += new string('=', 4 - padding);

                    byte[] bytes = Convert.FromBase64String(base64Part);
                    return Encoding.UTF8.GetString(bytes);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[HEADER DECODE ERROR] {ex.Message}");
                    return value;
                }
            }
            return value;
        }

        // =========================================================================
        // 2. СКАЧИВАНИЕ ПОДПИСОК (Считывание реальных метаданных из HTTP-заголовков)
        // =========================================================================
        public static async Task<List<VlessProfile>> ProcessInputAsync(string input)
        {
            input = input.Trim();

            if (input.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                input.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var handler = new HttpClientHandler
                    {
                        AllowAutoRedirect = true,
                        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.None
                    };

                    using (var client = new HttpClient(handler))
                    {
                        var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
                        if (!localSettings.Values.ContainsKey("v_DeviceHwid"))
                        {
                            string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
                            var rnd = new Random();
                            var sb = new System.Text.StringBuilder();
                            for (int i = 0; i < 16; i++)
                            {
                                sb.Append(chars[rnd.Next(chars.Length)]);
                            }
                            localSettings.Values["v_DeviceHwid"] = sb.ToString();
                        }
                        string hwid = localSettings.Values["v_DeviceHwid"] as string;

                        client.DefaultRequestHeaders.UserAgent.Clear();
                        client.DefaultRequestHeaders.UserAgent.TryParseAdd("Happ/3.13.0");

                        if (client.DefaultRequestHeaders.Contains("X-Hwid")) client.DefaultRequestHeaders.Remove("X-Hwid");
                        client.DefaultRequestHeaders.Add("X-Hwid", hwid);

                        if (client.DefaultRequestHeaders.Contains("X-Device-Os")) client.DefaultRequestHeaders.Remove("X-Device-Os");
                        client.DefaultRequestHeaders.Add("X-Device-Os", "Android");

                        if (client.DefaultRequestHeaders.Contains("X-Ver-Os")) client.DefaultRequestHeaders.Remove("X-Ver-Os");
                        client.DefaultRequestHeaders.Add("X-Ver-Os", "14");

                        if (client.DefaultRequestHeaders.Contains("X-Device-Model")) client.DefaultRequestHeaders.Remove("X-Device-Model");
                        client.DefaultRequestHeaders.Add("X-Device-Model", "Samsung Galaxy S24");

                        if (client.DefaultRequestHeaders.Contains("X-App-Version")) client.DefaultRequestHeaders.Remove("X-App-Version");
                        client.DefaultRequestHeaders.Add("X-App-Version", "3.13.0");

                        Debug.WriteLine($"[NETWORK] Отправляем запрос к: {input}");
                        var response = await client.GetAsync(input);
                        response.EnsureSuccessStatusCode();

                        var rawContent = await response.Content.ReadAsStringAsync();

                        string announce = "";
                        string infoUrl = "";
                        string telegramUrl = "";

                        if (response.Headers.Contains("announce"))
                        {
                            foreach (var val in response.Headers.GetValues("announce"))
                            {
                                announce = DecodeHeaderValueSafe(val);
                                break;
                            }
                        }
                        if (response.Headers.Contains("announce-url"))
                        {
                            foreach (var val in response.Headers.GetValues("announce-url"))
                            {
                                infoUrl = DecodeHeaderValueSafe(val);
                                break;
                            }
                        }
                        if (response.Headers.Contains("announce-telegram"))
                        {
                            foreach (var val in response.Headers.GetValues("announce-telegram"))
                            {
                                telegramUrl = DecodeHeaderValueSafe(val);
                                break;
                            }
                        }

                        var profiles = ParseSubscriptionData(rawContent, input);

                        foreach (var p in profiles)
                        {
                            p.Description = announce;
                            p.InfoUrl = infoUrl;
                            p.TelegramUrl = telegramUrl;
                            p.LastUpdated = DateTime.Now;
                        }

                        return profiles;
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[NETWORK ERROR] Ошибка сети: {ex.Message}");
                    throw;
                }
            }
            else
            {
                var profiles = ParseSubscriptionData(input, "Импорт из буфера");
                foreach (var p in profiles)
                {
                    p.LastUpdated = DateTime.Now;
                }
                return profiles;
            }
        }

        // =========================================================================
        // 3. ДЕКОДИРОВАНИЕ ДАННЫХ И АВТОМАТИЧЕСКИЙ ВЫБОР JSON-ПАРСЕРА
        // =========================================================================
        private static List<VlessProfile> ParseSubscriptionData(string rawData, string groupName)
        {
            string decodedText = rawData.Trim();

            // Если это не ссылки vless:// и не JSON, пробуем Base64 декодирование
            if (!decodedText.Contains("vless://") && !decodedText.StartsWith("[") && !decodedText.StartsWith("{"))
            {
                string cleanData = decodedText.Replace("\n", "").Replace("\r", "").Replace(" ", "");
                decodedText = DecodeBase64Safe(cleanData).Trim();
            }

            // Проверяем: если подписка вернулась в виде JSON-структуры
            if (decodedText.StartsWith("[") || decodedText.StartsWith("{"))
            {
                Debug.WriteLine("[PARSER] Обнаружен JSON-формат подписки. Запускаем JSON-парсер.");
                var jsonList = ParseJsonSubscription(decodedText);
                foreach (var p in jsonList)
                {
                    p.SubscriptionGroup = groupName;
                }
                Debug.WriteLine($"[PARSER] ИТОГО импортировано из JSON: {jsonList.Count}");
                return jsonList;
            }

            // Стандартный построчный парсинг
            var list = new List<VlessProfile>();
            var lines = decodedText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            Debug.WriteLine($"[PARSER] Найдено строк для анализа: {lines.Length}");

            foreach (var line in lines)
            {
                var p = Parse(line.Trim());
                if (p != null)
                {
                    p.SubscriptionGroup = groupName;
                    list.Add(p);
                    Debug.WriteLine($"[PARSER] Успешно добавлен профиль: {p.Name} ({p.Address})");
                }
            }

            Debug.WriteLine($"[PARSER] ИТОГО импортировано профилей: {list.Count}");
            return list;
        }

        private static string DecodeBase64Safe(string text)
        {
            try
            {
                string base64 = text.Replace("-", "+").Replace("_", "/");
                int padding = base64.Length % 4;
                if (padding > 0) base64 += new string('=', 4 - padding);

                var bytes = Convert.FromBase64String(base64);
                string decoded = Encoding.UTF8.GetString(bytes);

                Debug.WriteLine("========== РАСШИФРОВАННЫЙ BASE64 ==========");
                Debug.WriteLine(decoded);
                Debug.WriteLine("===========================================");

                return decoded;
            }
            catch (FormatException ex)
            {
                Debug.WriteLine($"[BASE64 INFO] Текст не является Base64 ({ex.Message}). Распознаём как обычный текст.");
                return text;
            }
        }

        // =========================================================================
        // 4. ВСТРОЕННЫЙ JSON-ПАРСЕР ДЛЯ SING-BOX / XRAY КОНФИГУРАЦИЙ
        // =========================================================================
        private static List<VlessProfile> ParseJsonSubscription(string jsonText)
        {
            var list = new List<VlessProfile>();
            try
            {
                if (JsonArray.TryParse(jsonText, out JsonArray rootArray))
                {
                    foreach (var val in rootArray)
                    {
                        if (val.ValueType == JsonValueType.Object)
                        {
                            var obj = val.GetObject();
                            string remarks = GetJsonString(obj, "remarks", "Vless-Node");

                            if (obj.ContainsKey("outbounds"))
                            {
                                var outbounds = GetJsonArray(obj, "outbounds");
                                if (outbounds != null)
                                {
                                    foreach (var outVal in outbounds)
                                    {
                                        if (outVal.ValueType == JsonValueType.Object)
                                        {
                                            var outObj = outVal.GetObject();
                                            string proto = GetJsonString(outObj, "protocol");

                                            // Наш клиент работает только с VLESS-протоколом
                                            if (string.Equals(proto, "vless", StringComparison.OrdinalIgnoreCase))
                                            {
                                                var profile = ParseVlessOutbound(outObj, remarks);
                                                if (profile != null)
                                                {
                                                    list.Add(profile);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[JSON PARSE ERROR] {ex.Message}");
            }
            return list;
        }

        private static VlessProfile ParseVlessOutbound(JsonObject outObj, string remarks)
        {
            try
            {
                var profile = new VlessProfile { Name = remarks };

                var settings = GetJsonObject(outObj, "settings");
                if (settings != null)
                {
                    var vnext = GetJsonArray(settings, "vnext");
                    if (vnext != null && vnext.Count > 0 && vnext[0].ValueType == JsonValueType.Object)
                    {
                        var serverObj = vnext[0].GetObject();
                        profile.Address = GetJsonString(serverObj, "address");
                        profile.Port = (int)GetJsonNumber(serverObj, "port", 443);

                        var users = GetJsonArray(serverObj, "users");
                        if (users != null && users.Count > 0 && users[0].ValueType == JsonValueType.Object)
                        {
                            var user = users[0].GetObject();
                            profile.Uuid = GetJsonString(user, "id").Replace("-", "");
                            profile.Flow = GetJsonString(user, "flow");
                        }
                    }
                }

                var ss = GetJsonObject(outObj, "streamSettings");
                if (ss != null)
                {
                    profile.Type = GetJsonString(ss, "network", "tcp");
                    profile.Security = GetJsonString(ss, "security", "none");

                    var grpc = GetJsonObject(ss, "grpcSettings");
                    if (grpc != null)
                    {
                        profile.Path = GetJsonString(grpc, "serviceName");
                        profile.Host = GetJsonString(grpc, "authority");
                    }

                    var ws = GetJsonObject(ss, "wsSettings");
                    if (ws != null)
                    {
                        profile.Path = GetJsonString(ws, "path");
                        var headers = GetJsonObject(ws, "headers");
                        if (headers != null)
                        {
                            profile.Host = GetJsonString(headers, "Host");
                        }
                    }

                    var xhttp = GetJsonObject(ss, "xhttpSettings");
                    if (xhttp == null) xhttp = GetJsonObject(ss, "splithttpSettings");
                    if (xhttp != null)
                    {
                        profile.Path = GetJsonString(xhttp, "path");
                        profile.Host = GetJsonString(xhttp, "host");
                        profile.Mode = GetJsonString(xhttp, "mode");
                    }

                    var reality = GetJsonObject(ss, "realitySettings");
                    if (reality != null)
                    {
                        profile.Sni = GetJsonString(reality, "serverName");
                        profile.PublicKey = GetJsonString(reality, "publicKey");
                        profile.ShortId = GetJsonString(reality, "shortId");
                    }

                    var tls = GetJsonObject(ss, "tlsSettings");
                    if (tls != null)
                    {
                        profile.Sni = GetJsonString(tls, "serverName");
                    }
                }

                if (string.IsNullOrEmpty(profile.Uuid) || string.IsNullOrEmpty(profile.Address))
                    return null;

                return profile;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PARSE OUTBOUND ERROR] {ex.Message}");
                return null;
            }
        }

        // =========================================================================
        // 5. ЗАЩИЩЕННЫЕ HELPER-МЕТОДЫ ДЛЯ ЧТЕНИЯ СТАНДАРТНОГО WINRT JSON-ДЕРЕВА
        // =========================================================================
        private static string GetJsonString(JsonObject obj, string key, string def = "")
        {
            if (obj == null || !obj.ContainsKey(key)) return def;
            var val = obj.GetNamedValue(key);
            if (val != null && val.ValueType == JsonValueType.String) return val.GetString();
            return def;
        }

        private static double GetJsonNumber(JsonObject obj, string key, double def = 0)
        {
            if (obj == null || !obj.ContainsKey(key)) return def;
            var val = obj.GetNamedValue(key);
            if (val != null && val.ValueType == JsonValueType.Number) return val.GetNumber();
            return def;
        }

        private static JsonObject GetJsonObject(JsonObject obj, string key)
        {
            if (obj == null || !obj.ContainsKey(key)) return null;
            var val = obj.GetNamedValue(key);
            if (val != null && val.ValueType == JsonValueType.Object) return val.GetObject();
            return null;
        }

        private static JsonArray GetJsonArray(JsonObject obj, string key)
        {
            if (obj == null || !obj.ContainsKey(key)) return null;
            var val = obj.GetNamedValue(key);
            if (val != null && val.ValueType == JsonValueType.Array) return val.GetArray();
            return null;
        }
    }
}