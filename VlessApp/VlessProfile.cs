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

        // Обновлено: текст пинга больше не дописывается в детали конфигурации
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
                    // Очищаем префикс
                    string base64Part = value.Substring(7).Trim();

                    // Безопасное восстановление padding-символов '=' для стабильного декодирования в .NET
                    base64Part = base64Part.Replace("-", "+").Replace("_", "/");
                    int padding = base64Part.Length % 4;
                    if (padding > 0) base64Part += new string('=', 4 - padding);

                    byte[] bytes = Convert.FromBase64String(base64Part);
                    return Encoding.UTF8.GetString(bytes); // Возвращаем раскодированный русский UTF-8 текст
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"[HEADER DECODE ERROR] {ex.Message}");
                    return value; // В случае сбоя безопасно возвращаем сырую строку
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
                        client.DefaultRequestHeaders.UserAgent.ParseAdd("v2rayNG/1.8.5");

                        Debug.WriteLine($"[NETWORK] Отправляем запрос к: {input}");
                        var response = await client.GetAsync(input);
                        response.EnsureSuccessStatusCode();

                        var rawContent = await response.Content.ReadAsStringAsync();

                        // Парсим реальные метаданные из HTTP-заголовков ответа сервера с поддержкой Base64
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

                        // Наполняем реальными метаданными, если они предоставлены провайдером
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
        // 3. ДЕКОДИРОВАНИЕ ДАННЫХ
        // =========================================================================
        private static List<VlessProfile> ParseSubscriptionData(string rawData, string groupName)
        {
            string decodedText = rawData;

            if (!rawData.Contains("vless://"))
            {
                string cleanData = rawData.Replace("\n", "").Replace("\r", "").Replace(" ", "");
                decodedText = DecodeBase64Safe(cleanData);
            }

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
    }
}