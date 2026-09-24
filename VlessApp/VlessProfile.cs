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

        // Отображаемое имя подписки. SubscriptionGroup — это ключ (ссылка), по
        // нему идёт обновление и дедупликация, показывать его нельзя. Сюда
        // попадает имя из заголовка profile-title, из ссылки Amnezia или то,
        // что пользователь задал вручную. Общее для всех профилей группы.
        [DataMember] public string GroupTitle { get; set; } = "";

        // Имя задал пользователь, а не сервер. Обновление подписки пересоздаёт
        // профили, и без этого признака имя из заголовка profile-title каждый
        // раз затирало бы то, что человек ввёл руками.
        [DataMember] public bool GroupTitleCustom { get; set; }

        // Подписка Amnezia Premium. Шлюз выдаёт один активный конфиг, а список
        // стран приходит вместе с ним — держим его тут, чтобы переключаться
        // без повторного разбора ссылки.
        [DataMember] public string AmneziaCountries { get; set; } = "";   // «код|имя|awg,vless;…»
        [DataMember] public string AmneziaCountryCode { get; set; } = "";
        [DataMember] public string AmneziaCountryName { get; set; } = "";
        [DataMember] public string AmneziaProtocol { get; set; } = "";
        [DataMember] public string AmneziaInfo { get; set; } = "";        // устройства и срок подписки

        // Второе звено цепочки Amnezia. Реле (основной адрес профиля) умеет
        // только доводить до этого узла, поэтому его параметры нужно сохранить:
        // конфиг выдаётся один раз, второй раз шлюз отдаст уже другие ключи.
        [DataMember] public string AmneziaExitHost { get; set; } = "";
        [DataMember] public int AmneziaExitPort { get; set; }
        [DataMember] public string AmneziaExitUuid { get; set; } = "";
        [DataMember] public string AmneziaExitPublicKey { get; set; } = "";
        [DataMember] public string AmneziaExitSni { get; set; } = "";
        [DataMember] public string AmneziaExitShortId { get; set; } = "";
        [DataMember] public string AmneziaExitFlow { get; set; } = "";

        [IgnoreDataMember]
        public bool HasAmneziaChain => !string.IsNullOrEmpty(AmneziaExitHost) && AmneziaExitPort > 0;

        // Строка страны есть в списке, но конфиг под неё ещё не запрашивали.
        // Шлюз выдаёт конфиги по одному, поэтому держать 42 готовых нельзя —
        // строка создаётся сразу, а конфиг подтягивается по нажатию.
        [DataMember] public bool AmneziaNotIssued { get; set; }

        [IgnoreDataMember]
        public bool IsAmneziaRow => !string.IsNullOrEmpty(AmneziaCountryCode);

        // Поля хранения метаданных подписки
        [DataMember] public DateTime LastUpdated { get; set; } = DateTime.Now;
        [DataMember] public string Description { get; set; } = "";
        [DataMember] public string InfoUrl { get; set; } = "";
        [DataMember] public string TelegramUrl { get; set; } = "";

        [DataMember] public string Mode { get; set; } = "";

        // Полный текст .conf для профилей AmneziaWG/WireGuard (Type = "amneziawg").
        [DataMember] public string AwgConfig { get; set; } = "";

        // Shadowsocks / Outline (Type = "shadowsocks").
        [DataMember] public string Method { get; set; } = "";
        [DataMember] public string Password { get; set; } = "";
        // Маскировка начала потока у Outline (?prefix=… / поле "prefix"). Хранится в HEX:
        // среди этих байтов бывает 0x00, а строку с ним не переживают ни сериализация
        // профилей, ни LocalSettings.
        [DataMember] public string SsPrefix { get; set; } = "";

        // Код страны ISO 3166-1 alpha-2. Пусто — значит определяем из имени
        // на лету (см. EffectiveCountryCode). Поле сохраняется, чтобы позже
        // сюда мог писать GeoIP, не переопределяя разбор имени каждый запуск.
        [DataMember] public string CountryCode { get; set; } = "";

        private string _detectedCc;
        [IgnoreDataMember]
        public string EffectiveCountryCode
        {
            get
            {
                if (!string.IsNullOrEmpty(CountryCode)) return CountryCode;
                if (_detectedCc == null) _detectedCc = CountryFlags.DetectFromName(Name) ?? "";
                return _detectedCc;
            }
        }

        // Имя без флаг-эмодзи: Windows рисует такую пару буквенным квадратиком
        // «NL», и рядом с настоящим флагом это выглядело бы как мусор.
        [IgnoreDataMember]
        public string DisplayName => CountryFlags.StripFlagEmoji(Name);

        [IgnoreDataMember]
        public Windows.UI.Xaml.Media.Imaging.WriteableBitmap FlagImage =>
            CountryFlags.GetBitmap(EffectiveCountryCode);

        [IgnoreDataMember]
        public Visibility FlagVisibility =>
            FlagImage != null ? Visibility.Visible : Visibility.Collapsed;

        // Страна известна, но флаг не нарисован — показываем буквенный значок.
        [IgnoreDataMember]
        public Visibility CodeBadgeVisibility =>
            (FlagImage == null && !string.IsNullOrEmpty(EffectiveCountryCode))
                ? Visibility.Visible : Visibility.Collapsed;

        [IgnoreDataMember]
        public string CountryBadgeText => EffectiveCountryCode;

        // Страна не определилась вовсе — остаётся прежний глобус.
        [IgnoreDataMember]
        public Visibility GlobeVisibility =>
            string.IsNullOrEmpty(EffectiveCountryCode) ? Visibility.Visible : Visibility.Collapsed;

        [IgnoreDataMember]
        public bool IsAmneziaWg =>
            string.Equals(Type, "amneziawg", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Type, "wireguard", StringComparison.OrdinalIgnoreCase);

        [IgnoreDataMember]
        public bool IsShadowsocks =>
            string.Equals(Type, "shadowsocks", StringComparison.OrdinalIgnoreCase);

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
                    OnPropertyChanged(nameof(PingBrush));
                }
            }
        }

        // Кисти — общие на всё приложение. Раньше каждое вычисление привязки
        // создавало новый SolidColorBrush, то есть при прокрутке на каждую
        // переработанную строку рождалась пара новых кистей, а каждая кисть —
        // ещё и ресурс композитора. На устройствах с 1 ГБ это прямой путь
        // к мусору на экране.
        private static readonly Brush PingFastBrush = new SolidColorBrush(Color.FromArgb(255, 16, 185, 129));
        private static readonly Brush PingMediumBrush = new SolidColorBrush(Color.FromArgb(255, 245, 158, 11));
        private static readonly Brush PingSlowBrush = new SolidColorBrush(Color.FromArgb(255, 239, 68, 68));
        private static readonly Brush PingIdleBrush = new SolidColorBrush(Color.FromArgb(255, 156, 163, 175));
        private static readonly Brush RowSelectedBrush = new SolidColorBrush(Color.FromArgb(255, 30, 41, 73));
        private static readonly Brush RowNormalBrush = new SolidColorBrush(Color.FromArgb(255, 18, 24, 45));

        // Цвет по величине задержки. Раньше любой результат красился зелёным,
        // включая 5689 мс и «Таймаут», — то есть цвет не значил ничего.
        [IgnoreDataMember]
        public Brush PingBrush
        {
            get
            {
                string s = _cleanPingText ?? "";
                int space = s.IndexOf(' ');
                int ms;
                if (space > 0 && int.TryParse(s.Substring(0, space), out ms))
                {
                    if (ms < 300) return PingFastBrush;
                    if (ms < 1000) return PingMediumBrush;
                    return PingSlowBrush;
                }
                if (s.StartsWith("Таймаут") || s.StartsWith("Ошибка")) return PingSlowBrush;
                return PingIdleBrush;
            }
        }

        // Цепочка протокола в верхнем регистре — «VLESS / TCP / REALITY».
        // Адрес сюда больше не выводим: он длинный и переносил строку, а увидеть
        // его можно в шаринге. Полный вид остался в DetailsText.
        public string DisplayText => AmneziaNotIssued
            ? $"{Up(AmneziaProtocol)} · нажмите, чтобы получить конфиг"
            : IsAmneziaWg
                ? "AMNEZIAWG"
                : IsShadowsocks
                    ? $"SHADOWSOCKS / {Up(Method)}"
                    : $"VLESS / {Up(Type)} / {Up(Security)}";

        [IgnoreDataMember]
        public string DetailsText => $"{Address}:{Port}";

        private static string Up(string s) => string.IsNullOrEmpty(s) ? "—" : s.ToUpperInvariant();

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
            ? RowSelectedBrush
            : RowNormalBrush;

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
        // 0. ЧТО ИМЕННО МЫ УМЕЕМ (и что пропускаем молча)
        // =========================================================================

        // Схемы, которые регулярно встречаются в подписках и которые понимают
        // sing-box-клиенты (Exclave, v2rayNG), но у нас не реализованы. До появления
        // этой таблицы такая строка не попадала ни в один if и просто исчезала:
        // пользователь видел, что часть серверов из подписки «не импортировалась»,
        // без единого слова о причине.
        private static readonly Dictionary<string, string> UnsupportedSchemes =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "vmess",     "протокол VMess не реализован" },
            { "trojan",    "протокол Trojan не реализован" },
            { "hysteria",  "протокол Hysteria не реализован (нужен QUIC/UDP)" },
            { "hysteria2", "протокол Hysteria2 не реализован (нужен QUIC/UDP)" },
            { "hy2",       "протокол Hysteria2 не реализован (нужен QUIC/UDP)" },
            { "tuic",      "протокол TUIC не реализован (нужен QUIC/UDP)" },
            { "anytls",    "протокол AnyTLS не реализован" },
            { "shadowtls", "протокол ShadowTLS не реализован" },
            { "snell",     "протокол Snell не реализован" },
            { "juicity",   "протокол Juicity не реализован (нужен QUIC/UDP)" },
            { "naive",     "протокол NaiveProxy не реализован" },
            { "mieru",     "протокол Mieru не реализован" },
            { "brook",     "протокол Brook не реализован" },
            { "ssh",       "SSH-туннель не реализован" },
            { "socks",     "исходящий SOCKS не реализован" },
            { "socks5",    "исходящий SOCKS не реализован" },
            { "wireguard", "ссылки wireguard:// не разбираются — импортируйте .conf или vpn://" },
        };

        // Транспорты VLESS, до которых у нас есть код. Всё остальное молча уезжало
        // в ветку raw TCP и не поднималось — снаружи это «сервер не отвечает».
        private static readonly HashSet<string> SupportedVlessTypes =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "tcp", "raw", "ws", "websocket", "xhttp", "splithttp" };

        public static string WhyUnsupportedScheme(string scheme)
        {
            if (string.IsNullOrEmpty(scheme)) return null;
            string why;
            return UnsupportedSchemes.TryGetValue(scheme, out why) ? why : null;
        }

        // Транспорт, который мы не умеем: возвращает причину либо null, если всё в порядке.
        public static string WhyUnsupportedTransport(VlessProfile p)
        {
            if (p == null || p.IsShadowsocks || p.IsAmneziaWg) return null;
            string t = (p.Type ?? "tcp").Trim();
            if (SupportedVlessTypes.Contains(t)) return null;
            if (string.Equals(t, "grpc", StringComparison.OrdinalIgnoreCase))
                return "транспорт gRPC не реализован";
            if (string.Equals(t, "httpupgrade", StringComparison.OrdinalIgnoreCase))
                return "транспорт HTTPUpgrade не реализован (близок к ws, но это другой хендшейк)";
            if (string.Equals(t, "h2", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(t, "http", StringComparison.OrdinalIgnoreCase))
                return "транспорт HTTP/2 как самостоятельный тип не реализован";
            if (string.Equals(t, "kcp", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(t, "mkcp", StringComparison.OrdinalIgnoreCase))
                return "транспорт mKCP не реализован (нужен UDP)";
            if (string.Equals(t, "quic", StringComparison.OrdinalIgnoreCase))
                return "транспорт QUIC не реализован (нужен UDP)";
            return "транспорт «" + t + "» неизвестен приложению";
        }

        // Слой шифрования, который движок не поднимет. Обычный TLS сделан только под
        // WebSocket (свой стек TLS 1.3 в WsTransport); для tcp и xhttp есть лишь REALITY,
        // поэтому vless+tls за CDN — рабочий в других клиентах — здесь уйдёт открытым
        // текстом, и сервер его отвергнет. Это не отказ, а пометка в журнале.
        public static string WhySecurityWontWork(VlessProfile p)
        {
            if (p == null || p.IsShadowsocks || p.IsAmneziaWg) return null;
            string sec = (p.Security ?? "").Trim().ToLowerInvariant();
            string type = (p.Type ?? "tcp").Trim().ToLowerInvariant();
            bool ws = type == "ws" || type == "websocket";
            bool xhttp = type == "xhttp" || type == "splithttp";
            if (sec == "reality") return null;
            if (sec == "tls")
                return (ws || xhttp) ? null
                    : "обычный TLS реализован для WebSocket и XHTTP, а здесь транспорт «" + type + "» — нужен REALITY";
            if (sec == "xtls")
                return "XTLS (старый, до xtls-rprx-vision) не реализован";
            if (sec.Length == 0 || sec == "none")
                return ws ? null : "у профиля нет слоя шифрования (security=" + (sec.Length == 0 ? "<пусто>" : sec) + "): трафик уйдёт открытым текстом";
            return "неизвестный security=«" + sec + "»";
        }

        // Однострочная сводка профиля для лога. Без UUID/пароля: файл уходит наружу.
        public static string Describe(VlessProfile p)
        {
            if (p == null) return "<null>";
            var sb = new StringBuilder();
            if (p.IsAmneziaWg) { sb.Append("amneziawg"); }
            else if (p.IsShadowsocks) { sb.Append("shadowsocks method=").Append(p.Method ?? "?"); }
            else
            {
                sb.Append("vless type=").Append(p.Type ?? "tcp")
                  .Append(" security=").Append(string.IsNullOrEmpty(p.Security) ? "?" : p.Security);
                if (!string.IsNullOrEmpty(p.Flow)) sb.Append(" flow=").Append(p.Flow);
                if (!string.IsNullOrEmpty(p.Sni)) sb.Append(" sni=").Append(p.Sni);
                if (!string.IsNullOrEmpty(p.Host)) sb.Append(" host=").Append(p.Host);
                if (!string.IsNullOrEmpty(p.Path)) sb.Append(" path=").Append(p.Path);
                if (!string.IsNullOrEmpty(p.Alpn)) sb.Append(" alpn=").Append(p.Alpn);
                if (!string.IsNullOrEmpty(p.Mode)) sb.Append(" mode=").Append(p.Mode);
                if (!string.IsNullOrEmpty(p.PublicKey)) sb.Append(" pbk=").Append(AppLog.Mask(p.PublicKey));
            }
            sb.Append(" | ").Append(p.Address ?? "?").Append(':').Append(p.Port);
            return sb.ToString();
        }

        // Итог последнего разбора подписки — MainPage показывает его пользователю,
        // чтобы «импортировано 12» не скрывало «и ещё 7 пропущено».
        public sealed class ImportReport
        {
            public readonly List<string> Skipped = new List<string>();

            // Профили, которые импортировались, но заведомо не поднимутся:
            // незнакомый транспорт или нереализованный шифр.
            public readonly List<string> Warnings = new List<string>();

            // «vmess ×3, trojan ×1» — компактно для строки статуса.
            public string SkippedSummary()
            {
                var byKind = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                foreach (var s in Skipped)
                {
                    int n;
                    byKind.TryGetValue(s, out n);
                    byKind[s] = n + 1;
                }
                var parts = new List<string>();
                foreach (var kv in byKind)
                    parts.Add(kv.Value > 1 ? kv.Key + " ×" + kv.Value : kv.Key);
                return string.Join(", ", parts);
            }
        }

        public static ImportReport LastImport { get; private set; } = new ImportReport();

        // Строка подписки, которая не стала профилем. kind — схема ссылки, она же
        // попадает в сводку для пользователя.
        private static void Skip(string kind, string why)
        {
            LastImport.Skipped.Add(kind);
            AppLog.W($"  ПРОПУЩЕНО [{kind}]: {why}");
        }

        // Профиль добавлен — пишем, чем именно он оказался. Если транспорт нам
        // незнаком, профиль в списке будет, но не подключится: помечаем сразу,
        // иначе это всплывёт только как «сервер не отвечает».
        private static void Report(VlessProfile p)
        {
            AppLog.W("  + " + Describe(p));

            string bad = WhyUnsupportedTransport(p);
            if (bad != null)
            {
                LastImport.Warnings.Add((p.Name ?? "?") + ": " + bad);
                AppLog.W("    ВНИМАНИЕ: " + bad + " — профиль импортирован, но не подключится");
            }

            string badSecurity = WhySecurityWontWork(p);
            if (badSecurity != null)
            {
                LastImport.Warnings.Add((p.Name ?? "?") + ": " + badSecurity);
                AppLog.W("    ВНИМАНИЕ: " + badSecurity);
            }

            if (p.IsShadowsocks && !IsSupportedSsMethod(p.Method))
            {
                LastImport.Warnings.Add((p.Name ?? "?") + ": шифр " + (p.Method ?? "?") + " не реализован");
                AppLog.W("    ВНИМАНИЕ: шифр Shadowsocks «" + (p.Method ?? "?") +
                         "» не реализован — профиль импортирован, но не подключится");
            }
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

                // Параметры, которые разбор не читает. Часть из них безобидна (fp, spx),
                // часть меняет протокол (extra, xmux, downloadSettings) — и тогда сервер
                // ждёт не того, что шлёт приложение. В логе они нужны целиком: жалоба
                // «в Exclave работает, здесь нет» чаще всего упирается именно в них.
                var ignoredKeys = new List<string>();

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
                            default:
                                ignoredKeys.Add(key);
                                break;
                        }
                    }
                }

                if (ignoredKeys.Count > 0)
                    AppLog.W("    параметры ссылки, которые приложение не читает: " + string.Join(", ", ignoredKeys));

                return string.IsNullOrEmpty(profile.Uuid) || string.IsNullOrEmpty(profile.Address) ? null : profile;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PARSE ERROR] Ошибка разбора ссылки: {url}");
                Debug.WriteLine($"[PARSE ERROR] Детали: {ex.Message}");
                AppLog.W("  vless://-ссылка не разобралась: " + ex.Message);
                return null;
            }
        }

        // =========================================================================
        // 1a. SHADOWSOCKS / OUTLINE: ss:// и ssconf://
        // =========================================================================
        public static bool IsShadowsocksLink(string s)
        {
            return !string.IsNullOrWhiteSpace(s) &&
                   s.TrimStart().StartsWith("ss://", StringComparison.OrdinalIgnoreCase);
        }

        // Шифры, которые умеет фоновая задача (см. SsCipherSpec в SsConnection.cs).
        public static bool IsSupportedSsMethod(string method)
        {
            switch ((method ?? "").Trim().ToLowerInvariant())
            {
                case "chacha20-ietf-poly1305":
                case "chacha20-poly1305":
                case "aes-256-gcm":
                case "aes-192-gcm":
                case "aes-128-gcm":
                    return true;
                default:
                    return false;
            }
        }

        public static bool IsSsConfLink(string s)
        {
            return !string.IsNullOrWhiteSpace(s) &&
                   s.TrimStart().StartsWith("ssconf://", StringComparison.OrdinalIgnoreCase);
        }

        // Возвращает текст, если строка — корректный base64 (обычный или url-safe,
        // с паддингом или без) и раскрывается в печатный ASCII. Иначе null.
        // Так отличается SIP002 (base64 в userinfo) от формы «method:password» открытым текстом.
        private static string TryDecodeBase64Text(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            try
            {
                string b64 = value.Trim().Replace("-", "+").Replace("_", "/");
                int pad = b64.Length % 4;
                if (pad == 1) return null;
                if (pad > 0) b64 += new string('=', 4 - pad);

                byte[] bytes = Convert.FromBase64String(b64);
                if (bytes.Length == 0) return null;
                foreach (byte b in bytes)
                {
                    if (b < 0x20 || b > 0x7E) return null;
                }
                return Encoding.UTF8.GetString(bytes);
            }
            catch { return null; }
        }

        // Префикс Outline приходит строкой, каждый символ которой — один байт
        // (percent-декодированный из ссылки или \uXXXX из JSON). Переводим в hex.
        public static string PrefixToHex(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";
            var sb = new StringBuilder(raw.Length * 2);
            foreach (char ch in raw)
            {
                if (ch > 0xFF)
                {
                    Debug.WriteLine("[SS] prefix содержит не-байтовый символ — игнорируем.");
                    return "";
                }
                sb.Append(((int)ch).ToString("x2"));
            }
            return sb.ToString();
        }

        // Обратно в строку-«байты» — нужно, чтобы собрать ss://-ссылку для шаринга.
        public static string PrefixFromHex(string hex)
        {
            if (string.IsNullOrEmpty(hex) || (hex.Length % 2) != 0) return "";
            try
            {
                var sb = new StringBuilder(hex.Length / 2);
                for (int i = 0; i < hex.Length; i += 2)
                    sb.Append((char)Convert.ToInt32(hex.Substring(i, 2), 16));
                return sb.ToString();
            }
            catch { return ""; }
        }

        private static string UnescapeSafe(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            try { return Uri.UnescapeDataString(s); }
            catch { return s; }
        }

        // Разбирает host:port, в том числе IPv6 в скобках: [2001:db8::1]:443
        private static bool SplitHostPort(string hostPort, out string host, out int port)
        {
            host = null; port = 0;
            if (string.IsNullOrWhiteSpace(hostPort)) return false;
            hostPort = hostPort.Trim();

            int colon;
            if (hostPort.StartsWith("["))
            {
                int close = hostPort.IndexOf(']');
                if (close < 0) return false;
                host = hostPort.Substring(1, close - 1);
                colon = hostPort.IndexOf(':', close);
            }
            else
            {
                colon = hostPort.LastIndexOf(':');
                if (colon <= 0) return false;
                host = hostPort.Substring(0, colon);
            }

            if (colon < 0 || colon + 1 >= hostPort.Length) return false;
            if (!int.TryParse(hostPort.Substring(colon + 1).Trim(), out port)) return false;
            return !string.IsNullOrEmpty(host) && port > 0 && port < 65536;
        }

        // ss://  — поддержаны обе формы:
        //   SIP002 : ss://base64url(method:password)@host:port/?params#tag
        //   legacy : ss://base64(method:password@host:port)#tag
        public static VlessProfile ParseShadowsocks(string url)
        {
            if (!IsShadowsocksLink(url)) return null;

            try
            {
                string body = url.Trim().Substring(5);

                string tag = "";
                int hash = body.IndexOf('#');
                if (hash >= 0)
                {
                    tag = UnescapeSafe(body.Substring(hash + 1));
                    body = body.Substring(0, hash);
                }

                string query = "";
                int q = body.IndexOf('?');
                if (q >= 0)
                {
                    query = body.Substring(q + 1);
                    body = body.Substring(0, q);
                }
                body = body.TrimEnd('/');
                if (body.Length == 0) return null;

                string userInfo, hostPort;
                int at = body.LastIndexOf('@');
                if (at < 0)
                {
                    // legacy: в base64 упаковано всё целиком
                    string decoded = TryDecodeBase64Text(body);
                    if (decoded == null) return null;
                    at = decoded.LastIndexOf('@');
                    if (at <= 0) return null;
                    userInfo = decoded.Substring(0, at);
                    hostPort = decoded.Substring(at + 1);
                }
                else
                {
                    userInfo = body.Substring(0, at);
                    hostPort = body.Substring(at + 1);

                    // В SIP002 userinfo — base64. Открытый текст «method:password»
                    // base64 быть не может: двоеточие не входит в алфавит.
                    string decodedUser = TryDecodeBase64Text(userInfo);
                    userInfo = (decodedUser != null && decodedUser.IndexOf(':') > 0)
                        ? decodedUser
                        : UnescapeSafe(userInfo);
                }

                int sep = userInfo.IndexOf(':');
                if (sep <= 0) return null;
                string method = userInfo.Substring(0, sep).Trim();
                string password = userInfo.Substring(sep + 1);   // пароль может содержать ':'

                string host; int port;
                if (!SplitHostPort(hostPort, out host, out port)) return null;

                var profile = new VlessProfile
                {
                    Name = string.IsNullOrWhiteSpace(tag) ? $"Shadowsocks {host}" : tag,
                    Address = host,
                    Port = port,
                    Type = "shadowsocks",
                    Security = "none",
                    Method = method.ToLowerInvariant(),
                    Password = password,
                    Uuid = ""
                };

                foreach (var pair in query.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var kv = pair.Split(new[] { '=' }, 2);
                    if (kv.Length != 2) continue;
                    switch (kv[0].Trim().ToLowerInvariant())
                    {
                        case "prefix":
                            profile.SsPrefix = PrefixToHex(UnescapeSafe(kv[1]));
                            break;
                        case "plugin":
                            // SIP003-плагины (v2ray-plugin, obfs, …) здесь не реализованы:
                            // импортируем, но подключение таким профилем не поднимется.
                            Debug.WriteLine($"[SS] Плагин '{UnescapeSafe(kv[1])}' не поддерживается: {profile.Name}");
                            break;
                    }
                }

                return profile;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[SS PARSE ERROR] {url}: {ex.Message}");
                return null;
            }
        }

        // ssconf:// — «динамический ключ» Outline: это не конфиг, а АДРЕС конфига.
        // Схема меняется на https, тело ответа — либо JSON, либо ss://-ссылка(и),
        // либо base64 от них. Без этой раскрутки ссылка бесполезна.
        public static async Task<List<VlessProfile>> FetchSsConfAsync(string url, string groupName)
        {
            var result = new List<VlessProfile>();
            if (!IsSsConfLink(url)) return result;

            string body = url.Trim().Substring("ssconf://".Length);

            string tag = "";
            int hash = body.IndexOf('#');
            if (hash >= 0)
            {
                tag = UnescapeSafe(body.Substring(hash + 1));
                body = body.Substring(0, hash);
            }

            string httpUrl = "https://" + body;
            Debug.WriteLine($"[SSCONF] Запрашиваю конфиг Outline: {httpUrl}");

            string content;
            using (var handler = new HttpClientHandler { AllowAutoRedirect = true })
            using (var client = new HttpClient(handler))
            {
                // Без явного срока запрос висит сто секунд, и со стороны это ничем
                // не отличается от зависшего приложения.
                client.Timeout = TimeSpan.FromSeconds(25);

                client.DefaultRequestHeaders.UserAgent.Clear();
                client.DefaultRequestHeaders.UserAgent.TryParseAdd("Outline-Client/1.0");
                var response = await client.GetAsync(httpUrl);
                response.EnsureSuccessStatusCode();
                content = (await response.Content.ReadAsStringAsync() ?? "").Trim();
            }

            foreach (var p in ParseSsConfContent(content, tag))
            {
                p.SubscriptionGroup = groupName;
                p.LastUpdated = DateTime.Now;
                result.Add(p);
            }

            if (result.Count == 0)
                Debug.WriteLine("[SSCONF] Ответ сервера не содержит пригодной конфигурации Shadowsocks.");

            return result;
        }

        // Тело ответа ssconf: JSON Outline, готовые ss://-ссылки или base64 от них.
        private static List<VlessProfile> ParseSsConfContent(string content, string tag)
        {
            var list = new List<VlessProfile>();
            if (string.IsNullOrWhiteSpace(content)) return list;
            content = content.Trim();

            if (content.StartsWith("{"))
            {
                var p = ParseOutlineJson(content, tag);
                if (p != null) list.Add(p);
                return list;
            }

            if (content.IndexOf("ss://", StringComparison.OrdinalIgnoreCase) < 0)
            {
                // Не JSON и не ссылка — вероятно, base64-обёртка.
                string decoded = DecodeBase64Safe(content.Replace("\n", "").Replace("\r", "").Replace(" ", ""));
                if (!string.IsNullOrWhiteSpace(decoded) && decoded != content)
                    return ParseSsConfContent(decoded, tag);
                return list;
            }

            foreach (var line in content.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var p = ParseShadowsocks(line.Trim());
                if (p == null) continue;
                if (!string.IsNullOrWhiteSpace(tag)) p.Name = tag;
                list.Add(p);
            }
            return list;
        }

        // {"server":"…","server_port":443,"password":"…","method":"…","prefix":"…"}
        private static VlessProfile ParseOutlineJson(string json, string tag)
        {
            try
            {
                JsonObject obj;
                if (!JsonObject.TryParse(json, out obj)) return null;

                string server = GetJsonString(obj, "server");
                string method = GetJsonString(obj, "method");
                string password = GetJsonString(obj, "password");
                int port = (int)GetJsonNumber(obj, "server_port", 0);
                if (port <= 0) port = (int)GetJsonNumber(obj, "port", 0);

                if (string.IsNullOrEmpty(server) || port <= 0 ||
                    string.IsNullOrEmpty(method) || string.IsNullOrEmpty(password))
                    return null;

                return new VlessProfile
                {
                    Name = string.IsNullOrWhiteSpace(tag) ? $"Shadowsocks {server}" : tag,
                    Address = server,
                    Port = port,
                    Type = "shadowsocks",
                    Security = "none",
                    Method = method.ToLowerInvariant(),
                    Password = password,
                    SsPrefix = PrefixToHex(GetJsonString(obj, "prefix")),
                    Uuid = ""
                };
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[SSCONF JSON ERROR] {ex.Message}");
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

            // Новый импорт — новый отчёт: иначе в строке статуса накапливались бы
            // пропуски из прошлых подписок.
            LastImport = new ImportReport();
            AppLog.Section("ИМПОРТ: " + AppLog.SchemeOf(input) + ", длина ввода " + input.Length);

            // Динамический ключ Outline: сначала скачиваем по нему настоящий конфиг.
            // Группой служит сам адрес ключа — тогда повторный импорт и кнопка
            // «обновить» работают так же, как для обычной подписки.
            if (IsSsConfLink(input) && input.IndexOf('\n') < 0 && input.IndexOf('\r') < 0)
                return await FetchSsConfAsync(input, input);

            // Подписка Amnezia Premium: в самой ссылке конфига нет, он выдаётся
            // API-шлюзом по ключу доступа. Группой служит сама ссылка — тогда
            // кнопка «обновить» перезапросит у шлюза свежий конфиг.
            if (AmneziaLink.IsAmneziaLink(input) && input.IndexOf('\n') < 0 && input.IndexOf('\r') < 0)
            {
                var sub = AmneziaLink.TryGetApiSubscription(input);
                if (sub != null)
                {
                    Debug.WriteLine($"[AMNEZIA API] Подписка {sub.ServiceType}, протокол {sub.ServiceProtocol}, страна {sub.UserCountryCode}.");
                    var fetched = await AmneziaApi.FetchAsync(sub, input);
                    foreach (var p in fetched) p.LastUpdated = DateTime.Now;
                    return fetched;
                }
            }

            // Зашифрованные подписки Happ: happ://crypt … happ://crypt4 (RSA),
            // а также happ:// с обычным percent/base64-телом. Распаковываем и
            // обрабатываем результат как содержимое подписки.
            if (HappCrypto.IsHappLink(input))
            {
                string unwrapped = HappCrypto.Unwrap(input);
                if (string.IsNullOrWhiteSpace(unwrapped))
                    throw new Exception("Не удалось расшифровать happ://-подписку (возможно, crypt5 не поддерживается).");

                unwrapped = unwrapped.Trim();
                // Если внутри оказался единственный http(s) URL — это ссылка на
                // подписку: рекурсивно скачиваем её.
                bool singleLine = unwrapped.IndexOf('\n') < 0 && unwrapped.IndexOf('\r') < 0;
                if (singleLine &&
                    (unwrapped.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                     unwrapped.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                {
                    return await ProcessInputAsync(unwrapped);
                }

                var happProfiles = await ParseSubscriptionAsync(unwrapped, "Happ (шифрованная подписка)");
                foreach (var p in happProfiles) p.LastUpdated = DateTime.Now;
                return happProfiles;
            }

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
                        // Без явного срока запрос висит сто секунд, и со стороны это ничем
                        // не отличается от зависшего приложения.
                        client.Timeout = TimeSpan.FromSeconds(25);

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
                        string profileTitle = "";

                        // Имя подписки, которое отдаёт панель. Без него в шапке
                        // оставался голый URL.
                        foreach (var headerName in new[] { "profile-title", "profile-web-page-url-title", "subscription-title" })
                        {
                            if (!response.Headers.Contains(headerName)) continue;
                            foreach (var val in response.Headers.GetValues(headerName))
                            {
                                profileTitle = DecodeHeaderValueSafe(val);
                                break;
                            }
                            if (!string.IsNullOrWhiteSpace(profileTitle)) break;
                        }

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

                        var profiles = await ParseSubscriptionAsync(rawContent, input);

                        foreach (var p in profiles)
                        {
                            p.Description = announce;
                            p.InfoUrl = infoUrl;
                            p.TelegramUrl = telegramUrl;
                            p.GroupTitle = profileTitle;
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
                var profiles = await ParseSubscriptionAsync(input, "Импорт из буфера");
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
        // Обёртка над разбором: ssconf://-ссылки внутри подписки нельзя раскрутить
        // синхронно (за каждой стоит HTTP-запрос), поэтому парсер складывает их
        // отдельно, а докачиваем мы уже здесь.
        private static async Task<List<VlessProfile>> ParseSubscriptionAsync(string rawData, string groupName)
        {
            List<string> ssConfLinks;
            var list = ParseSubscriptionData(rawData, groupName, out ssConfLinks);

            foreach (var link in ssConfLinks)
            {
                try { list.AddRange(await FetchSsConfAsync(link, groupName)); }
                catch (Exception ex) { Debug.WriteLine($"[SSCONF] {link} не скачался: {ex.Message}"); }
            }
            return list;
        }

        private static List<VlessProfile> ParseSubscriptionData(string rawData, string groupName)
        {
            List<string> ignored;
            return ParseSubscriptionData(rawData, groupName, out ignored);
        }

        private static List<VlessProfile> ParseSubscriptionData(string rawData, string groupName,
                                                               out List<string> ssConfLinks)
        {
            ssConfLinks = new List<string>();
            string decodedText = rawData.Trim();

            // Ссылка vpn://… из AmneziaVPN — распаковываем и достаём из неё .conf.
            if (AmneziaLink.IsAmneziaLink(decodedText) && decodedText.IndexOf('\n') < 0)
            {
                string why;
                var res = AmneziaLink.Parse(decodedText, out why);
                if (res == null) throw new Exception("Ссылка AmneziaVPN не подошла: " + why);

                var link = ParseWgConfig(res.ConfText, groupName);
                if (link == null) throw new Exception("В ссылке AmneziaVPN не нашёлся корректный конфиг.");
                if (!string.IsNullOrWhiteSpace(res.Name)) link.Name = res.Name;
                return new List<VlessProfile> { link };
            }

            // Конфиг AmneziaWG/WireGuard — это ini-текст, начинающийся с [Interface].
            // Проверяем до всего остального: иначе '[' увёл бы его в JSON-парсер.
            if (LooksLikeWgConfig(decodedText))
            {
                var wg = ParseWgConfig(decodedText, groupName);
                return wg != null ? new List<VlessProfile> { wg } : new List<VlessProfile>();
            }

            // Если это не ссылки vless://ss://ssconf:// и не JSON, пробуем Base64 декодирование.
            // Без проверки на ss:// одиночная ссылка Shadowsocks уходила в base64-декодер
            // и превращалась в мусор — именно поэтому такие ссылки не импортировались.
            if (!decodedText.Contains("vless://") &&
                decodedText.IndexOf("ss://", StringComparison.OrdinalIgnoreCase) < 0 &&
                decodedText.IndexOf("ssconf://", StringComparison.OrdinalIgnoreCase) < 0 &&
                !decodedText.StartsWith("[") && !decodedText.StartsWith("{"))
            {
                string cleanData = decodedText.Replace("\n", "").Replace("\r", "").Replace(" ", "");
                decodedText = DecodeBase64Safe(cleanData).Trim();

                // Base64 мог скрывать тот же .conf
                if (LooksLikeWgConfig(decodedText))
                {
                    var wg = ParseWgConfig(decodedText, groupName);
                    return wg != null ? new List<VlessProfile> { wg } : new List<VlessProfile>();
                }
            }

            // Проверяем: если подписка вернулась в виде JSON-структуры
            if (decodedText.StartsWith("[") || decodedText.StartsWith("{"))
            {
                Debug.WriteLine("[PARSER] Обнаружен JSON-формат подписки. Запускаем JSON-парсер.");
                AppLog.W($"Разбор «{groupName}»: формат JSON (sing-box/xray)");
                var jsonList = ParseJsonSubscription(decodedText);
                foreach (var p in jsonList)
                {
                    p.SubscriptionGroup = groupName;
                }
                Debug.WriteLine($"[PARSER] ИТОГО импортировано из JSON: {jsonList.Count}");
                AppLog.W($"Итог «{groupName}»: добавлено {jsonList.Count}, пропущено {LastImport.Skipped.Count}"
                         + (LastImport.Skipped.Count > 0 ? " (" + LastImport.SkippedSummary() + ")" : ""));
                return jsonList;
            }

            // Стандартный построчный парсинг
            var list = new List<VlessProfile>();
            var lines = decodedText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            Debug.WriteLine($"[PARSER] Найдено строк для анализа: {lines.Length}");
            AppLog.W($"Разбор «{groupName}»: строк для анализа {lines.Length}");

            foreach (var line in lines)
            {
                string trimmed = line.Trim();

                // Пустые строки и комментарии панелей не считаем пропущенными
                // серверами: иначе хвостовой перевод строки поднимал бы диалог
                // «импортировано не всё» на ровном месте.
                if (trimmed.Length == 0 || trimmed[0] == '#' || trimmed.StartsWith("//")) continue;

                // Вложенная зашифрованная happ://-ссылка внутри списка
                if (HappCrypto.IsHappLink(trimmed))
                {
                    string inner = HappCrypto.Unwrap(trimmed);
                    if (!string.IsNullOrWhiteSpace(inner))
                    {
                        foreach (var innerLine in inner.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            var hp = Parse(innerLine.Trim());
                            if (hp != null) { hp.SubscriptionGroup = groupName; list.Add(hp); }
                        }
                    }
                    continue;
                }

                // Динамический ключ Outline — докачивается вызывающей стороной.
                if (IsSsConfLink(trimmed))
                {
                    ssConfLinks.Add(trimmed);
                    continue;
                }

                // Shadowsocks/Outline. Проверяем ДО vless://, но по StartsWith:
                // подстрока «ss://» есть и внутри самого «vless://».
                if (IsShadowsocksLink(trimmed))
                {
                    var sp = ParseShadowsocks(trimmed);
                    if (sp != null)
                    {
                        sp.SubscriptionGroup = groupName;
                        list.Add(sp);
                        Debug.WriteLine($"[PARSER] Добавлен Shadowsocks: {sp.Name} ({sp.Address}:{sp.Port}, {sp.Method})");
                        Report(sp);
                    }
                    else
                    {
                        Debug.WriteLine($"[PARSER] Ссылка ss:// не разобралась: {trimmed}");
                        Skip("ss", "ссылка не разобралась (неверный формат или base64)");
                    }
                    continue;
                }

                // Ссылка AmneziaVPN в общем списке подписки
                if (AmneziaLink.IsAmneziaLink(trimmed))
                {
                    string why;
                    var res = AmneziaLink.Parse(trimmed, out why);
                    if (res == null)
                    {
                        Debug.WriteLine($"[PARSER] vpn://-ссылка пропущена: {why}");
                        Skip("vpn", why);
                        continue;
                    }
                    var ap = ParseWgConfig(res.ConfText, groupName);
                    if (ap != null)
                    {
                        if (!string.IsNullOrWhiteSpace(res.Name)) ap.Name = res.Name;
                        list.Add(ap);
                        Report(ap);
                    }
                    else Skip("vpn", "внутри ссылки нет корректного конфига WireGuard");
                    continue;
                }

                var p = Parse(trimmed);
                if (p != null)
                {
                    p.SubscriptionGroup = groupName;
                    list.Add(p);
                    Debug.WriteLine($"[PARSER] Успешно добавлен профиль: {p.Name} ({p.Address})");
                    Report(p);
                    continue;
                }

                // Сюда доходит всё, что не подошло ни под один разборщик. Раньше
                // строка тут просто заканчивалась — ни в логе, ни в интерфейсе от
                // неё не оставалось следа, и «конфиг из Exclave» выглядел как
                // потерянный без причины.
                string scheme = AppLog.SchemeOf(trimmed);
                string unsupported = WhyUnsupportedScheme(scheme);
                if (unsupported != null) Skip(scheme, unsupported);
                else if (scheme.Equals("vless", StringComparison.OrdinalIgnoreCase))
                    Skip("vless", "ссылка не разобралась: нет UUID или адреса");
                else if (scheme.StartsWith("<"))
                    Skip("текст", "строка без схемы «xxx://» — не ссылка на сервер");
                else
                    Skip(scheme, "схема неизвестна приложению");
            }

            Debug.WriteLine($"[PARSER] ИТОГО импортировано профилей: {list.Count}");
            AppLog.W($"Итог «{groupName}»: добавлено {list.Count}, пропущено {LastImport.Skipped.Count}"
                     + (LastImport.Skipped.Count > 0 ? " (" + LastImport.SkippedSummary() + ")" : ""));
            return list;
        }

        // =========================================================================
        // 3a. КОНФИГИ AMNEZIAWG / WIREGUARD (.conf)
        // =========================================================================
        private static bool LooksLikeWgConfig(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            return text.IndexOf("[Interface]", StringComparison.OrdinalIgnoreCase) >= 0 &&
                   text.IndexOf("PrivateKey", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        // Профиль из клиентского конфига xray (то, что Amnezia кладёт в
        // last_config контейнера amnezia-xray). Это обычный конфиг xray с
        // массивом outbounds — разбор для него уже есть, не хватало только
        // входа в него с объекта, а не с массива подписки.
        // Адрес и порт могут отсутствовать в outbound: тогда берём их с уровня
        // конфига (hostName) и контейнера (port).
        public static VlessProfile FromXrayClientConfig(string json, string groupName, string remarks,
                                                        string fallbackHost, int fallbackPort)
        {
            try
            {
                JsonObject root;
                if (!JsonObject.TryParse(json, out root)) return null;

                var outbounds = GetJsonArray(root, "outbounds");
                if (outbounds == null) return null;

                // Amnezia отдаёт цепочку: outbound «proxy» имеет
                // sockopt.dialerProxy и дозванивается ЧЕРЕЗ outbound «proxy-relay».
                // Напрямую доступен только тот, у кого dialerProxy нет, — он и есть
                // точка входа. Раньше брался первый попавшийся, то есть выходной
                // узел, к которому мы шли в обход реле: TCP он принимал, а на
                // рукопожатие REALITY не отвечал.
                var direct = new List<JsonObject>();
                var chained = new List<JsonObject>();
                foreach (var val in outbounds)
                {
                    if (val.ValueType != JsonValueType.Object) continue;
                    var o = val.GetObject();
                    var sock = GetJsonObject(GetJsonObject(o, "streamSettings"), "sockopt");
                    if (!string.IsNullOrEmpty(GetJsonString(sock, "dialerProxy"))) chained.Add(o);
                    else direct.Add(o);
                }

                var ordered = new List<JsonObject>();
                ordered.AddRange(direct);
                ordered.AddRange(chained);

                foreach (var outObj in ordered)
                {
                    string proto = GetJsonString(outObj, "protocol");

                    VlessProfile p = null;
                    if (string.Equals(proto, "vless", StringComparison.OrdinalIgnoreCase))
                        p = ParseVlessOutbound(outObj, remarks);
                    else if (string.Equals(proto, "shadowsocks", StringComparison.OrdinalIgnoreCase))
                        p = ParseShadowsocksOutbound(outObj, remarks);

                    if (p == null) continue;

                    if (string.IsNullOrEmpty(p.Address) && !string.IsNullOrEmpty(fallbackHost))
                        p.Address = fallbackHost;
                    if (p.Port <= 0 && fallbackPort > 0)
                        p.Port = fallbackPort;
                    if (string.IsNullOrEmpty(p.Address) || p.Port <= 0) continue;

                    // Второе звено: outbound, который дозванивается через первый.
                    // Сохраняем целиком — без него цепочку не построить, а
                    // повторно тот же конфиг шлюз уже не выдаст.
                    foreach (var chainedObj in chained)
                    {
                        var exit = ParseVlessOutbound(chainedObj, remarks);
                        if (exit == null || string.IsNullOrEmpty(exit.Address)) continue;
                        p.AmneziaExitHost = exit.Address;
                        p.AmneziaExitPort = exit.Port > 0 ? exit.Port : 443;
                        p.AmneziaExitUuid = exit.Uuid;
                        p.AmneziaExitPublicKey = exit.PublicKey;
                        p.AmneziaExitSni = exit.Sni;
                        p.AmneziaExitShortId = exit.ShortId;
                        p.AmneziaExitFlow = exit.Flow;
                        break;
                    }

                    p.SubscriptionGroup = groupName;
                    return p;
                }
                return null;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[XRAY CONFIG] Не разобрался: {ex.Message}");
                return null;
            }
        }

        // Профиль из готового текста .conf — нужен клиенту API-шлюза Amnezia,
        // который получает конфиг по сети, а не из ссылки.
        public static VlessProfile FromWgConfig(string confText, string groupName)
        {
            return ParseWgConfig(confText, groupName);
        }

        // Из .conf берём только то, что нужно списку профилей (адрес, порт, имя).
        // Весь остальной разбор делает фоновая задача — там же лежит настоящий парсер.
        private static VlessProfile ParseWgConfig(string text, string groupName)
        {
            try
            {
                string endpoint = null, section = "";
                bool amnezia = false;

                foreach (var rawLine in text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
                {
                    string line = rawLine.Trim();
                    int hash = line.IndexOf('#');
                    if (hash >= 0) line = line.Substring(0, hash).Trim();
                    if (line.Length == 0) continue;

                    if (line[0] == '[')
                    {
                        section = line.Trim('[', ']').Trim().ToLowerInvariant();
                        continue;
                    }

                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string key = line.Substring(0, eq).Trim();
                    string val = line.Substring(eq + 1).Trim();

                    if (section == "peer" && string.Equals(key, "Endpoint", StringComparison.OrdinalIgnoreCase))
                        endpoint = val;

                    // Наличие полей обфускации отличает AmneziaWG от чистого WireGuard.
                    if (section == "interface" && key.Length >= 2 && key.Length <= 4)
                    {
                        string k = key.ToLowerInvariant();
                        if (k == "jc" || k == "jmin" || k == "jmax" ||
                            (key.Length == 2 && (k[0] == 's' || k[0] == 'h') && k[1] >= '1' && k[1] <= '4'))
                            amnezia = true;
                    }
                }

                if (string.IsNullOrEmpty(endpoint))
                {
                    Debug.WriteLine("[PARSER] .conf без Endpoint в [Peer] — пропускаем.");
                    return null;
                }

                int colon = endpoint.LastIndexOf(':');
                if (colon <= 0) return null;
                string host = endpoint.Substring(0, colon).Trim().Trim('[', ']');
                int port;
                if (!int.TryParse(endpoint.Substring(colon + 1).Trim(), out port) || port <= 0) return null;

                var p = new VlessProfile
                {
                    Name = amnezia ? $"AmneziaWG {host}" : $"WireGuard {host}",
                    Address = host,
                    Port = port,
                    Type = "amneziawg",
                    Security = "none",
                    AwgConfig = text,
                    SubscriptionGroup = groupName,
                    LastUpdated = DateTime.Now
                };

                Debug.WriteLine($"[PARSER] Импортирован конфиг AmneziaWG: {host}:{port} (обфускация: {amnezia}).");
                return p;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PARSE ERROR] .conf: {ex.Message}");
                return null;
            }
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

                                            if (string.Equals(proto, "vless", StringComparison.OrdinalIgnoreCase))
                                            {
                                                var profile = ParseVlessOutbound(outObj, remarks);
                                                if (profile != null) { list.Add(profile); Report(profile); }
                                                else Skip("vless", "outbound не разобрался: нет id или адреса");
                                            }
                                            else if (string.Equals(proto, "shadowsocks", StringComparison.OrdinalIgnoreCase))
                                            {
                                                var profile = ParseShadowsocksOutbound(outObj, remarks);
                                                if (profile != null) { list.Add(profile); Report(profile); }
                                                else Skip("shadowsocks", "outbound не разобрался: нет адреса, шифра или пароля");
                                            }
                                            else if (!string.IsNullOrEmpty(proto) &&
                                                     !string.Equals(proto, "freedom", StringComparison.OrdinalIgnoreCase) &&
                                                     !string.Equals(proto, "direct", StringComparison.OrdinalIgnoreCase) &&
                                                     !string.Equals(proto, "blackhole", StringComparison.OrdinalIgnoreCase) &&
                                                     !string.Equals(proto, "block", StringComparison.OrdinalIgnoreCase) &&
                                                     !string.Equals(proto, "dns", StringComparison.OrdinalIgnoreCase))
                                            {
                                                // Служебные outbound (freedom/blackhole/dns) есть в каждом
                                                // конфиге и профилями не являются — их молчание штатно.
                                                // А вот vmess/trojan/hysteria2 здесь терялись без следа.
                                                string whyJson = WhyUnsupportedScheme(proto);
                                                Skip(proto, whyJson ?? "протокол outbound не поддерживается");
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
                AppLog.W("JSON-подписка: разбор оборвался — " + ex.Message);
            }
            return list;
        }

        // {"protocol":"shadowsocks","settings":{"servers":[{"address","port","method","password"}]}}
        private static VlessProfile ParseShadowsocksOutbound(JsonObject outObj, string remarks)
        {
            try
            {
                var settings = GetJsonObject(outObj, "settings");
                if (settings == null) return null;

                var servers = GetJsonArray(settings, "servers");
                if (servers == null || servers.Count == 0 || servers[0].ValueType != JsonValueType.Object)
                    return null;

                var srv = servers[0].GetObject();
                string address = GetJsonString(srv, "address");
                int port = (int)GetJsonNumber(srv, "port", 0);
                string method = GetJsonString(srv, "method");
                string password = GetJsonString(srv, "password");

                if (string.IsNullOrEmpty(address) || port <= 0 ||
                    string.IsNullOrEmpty(method) || string.IsNullOrEmpty(password))
                    return null;

                return new VlessProfile
                {
                    Name = string.IsNullOrWhiteSpace(remarks) ? $"Shadowsocks {address}" : remarks,
                    Address = address,
                    Port = port,
                    Type = "shadowsocks",
                    Security = "none",
                    Method = method.ToLowerInvariant(),
                    Password = password,
                    Uuid = ""
                };
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PARSE SS OUTBOUND ERROR] {ex.Message}");
                return null;
            }
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
                        // Имя и short id пишут по-разному: в клиентском конфиге
                        // это serverName/shortId, но встречаются и серверные формы
                        // во множественном числе. Берём первое непустое, иначе
                        // REALITY уходит в рукопожатие с пустым SNI и молчит.
                        profile.Sni = FirstNonEmptyJson(reality, "serverName", "serverNames", "sni", "server_name");
                        // Ключ REALITY приходит в base64url без паддинга — так же,
                        // как в ссылке. В разборе ссылок нормализация была, а здесь
                        // ключ брался как есть и подключение с ним не поднялось бы.
                        profile.PublicKey = NormalizeBase64(
                            FirstNonEmptyJson(reality, "publicKey", "public_key", "pbk"));
                        profile.ShortId = FirstNonEmptyJson(reality, "shortId", "shortIds", "short_id", "sid");
                    }

                    var tls = GetJsonObject(ss, "tlsSettings");
                    if (tls != null)
                    {
                        // Только если там правда есть имя. Раньше эта строка шла
                        // после realitySettings и затирала уже разобранный SNI
                        // пустой строкой, когда tlsSettings в конфиге есть, а
                        // serverName в нём нет — ровно случай Amnezia. Клиент
                        // уходил в рукопожатие REALITY с пустым SNI, и сервер
                        // на такой ClientHello не отвечал вовсе.
                        string tlsSni = GetJsonString(tls, "serverName");
                        if (!string.IsNullOrEmpty(tlsSni)) profile.Sni = tlsSni;
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
        // Первое непустое значение из перечисленных ключей. Строку берём как есть,
        // из массива — первый непустой элемент (формы вида serverNames/shortIds).
        private static string FirstNonEmptyJson(JsonObject obj, params string[] keys)
        {
            if (obj == null) return "";
            foreach (var key in keys)
            {
                if (!obj.ContainsKey(key)) continue;
                try
                {
                    var v = obj.GetNamedValue(key);
                    if (v.ValueType == JsonValueType.String)
                    {
                        string s = v.GetString();
                        if (!string.IsNullOrEmpty(s)) return s;
                    }
                    else if (v.ValueType == JsonValueType.Array)
                    {
                        foreach (var item in v.GetArray())
                            if (item.ValueType == JsonValueType.String &&
                                !string.IsNullOrEmpty(item.GetString()))
                                return item.GetString();
                    }
                }
                catch { }
            }
            return "";
        }

        // base64url → обычный base64 с паддингом.
        private static string NormalizeBase64(string val)
        {
            if (string.IsNullOrEmpty(val)) return val;
            val = val.Replace("-", "+").Replace("_", "/");
            while (val.Length % 4 != 0) val += "=";
            return val;
        }

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