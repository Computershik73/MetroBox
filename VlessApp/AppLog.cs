using System;
using System.Diagnostics;
using System.Text;

namespace VlessApp
{
    // Лог UI-процесса: импорт подписок и решения, принятые до старта туннеля.
    //
    // Отдельный файл, а не общий vpnlog.txt, по той же причине, что и amnezialog.txt:
    // vpnlog обнуляется на каждом старте VPN фоновой задачей, и всё, что произошло на
    // этапе импорта, стёрлось бы ровно перед тем, как его читать. Плюс vpnlog пишет
    // другой процесс — общий файл пришлось бы делить между двумя писателями.
    //
    // До этого разбор подписки существовал только в Debug.WriteLine, то есть у
    // пользователя на телефоне его не было вовсе: ссылка неизвестного протокола
    // молча пропускалась, и снаружи это выглядело как «конфиг работает в Exclave,
    // а в MetroBox его просто нет».
    internal static class AppLog
    {
        public static string LogFileName { get { return "applog.txt"; } }

        private static readonly object FileLock = new object();
        private const long MaxBytes = 512L * 1024;

        public static void W(string message)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "  " + message;
            Debug.WriteLine("[APP] " + message);
            AppendToFile(line);
        }

        // Чистый файл на каждый запуск приложения: лог уходит пользователю целиком,
        // и в нём должна быть одна сессия, а не склейка за все месяцы.
        public static void Reset()
        {
            try
            {
                lock (FileLock)
                {
                    string path = System.IO.Path.Combine(
                        Windows.Storage.ApplicationData.Current.LocalFolder.Path, LogFileName);
                    try { System.IO.File.Delete(path); } catch { }
                }
            }
            catch { }
            W("──── ЗАПУСК ────");
            W("  " + EnvironmentInfo());
        }

        // Шапка: без неё присланный лог не привязать ни к версии, ни к устройству.
        public static string EnvironmentInfo()
        {
            var sb = new StringBuilder();
            try
            {
                var v = Windows.ApplicationModel.Package.Current.Id.Version;
                sb.Append("MetroBox ").Append(v.Major).Append('.').Append(v.Minor)
                  .Append('.').Append(v.Build).Append('.').Append(v.Revision);
            }
            catch { sb.Append("MetroBox <версия неизвестна>"); }
            try
            {
                var info = new Windows.Security.ExchangeActiveSyncProvisioning.EasClientDeviceInformation();
                sb.Append(", ").Append(info.SystemManufacturer).Append(' ').Append(info.SystemProductName);
                if (!string.IsNullOrEmpty(info.OperatingSystem)) sb.Append(", ").Append(info.OperatingSystem);
            }
            catch { }
            try
            {
                string raw = Windows.System.Profile.AnalyticsInfo.VersionInfo.DeviceFamilyVersion;
                ulong n = ulong.Parse(raw);
                sb.Append(", сборка ")
                  .Append((n & 0xFFFF000000000000L) >> 48).Append('.')
                  .Append((n & 0x0000FFFF00000000L) >> 32).Append('.')
                  .Append((n & 0x00000000FFFF0000L) >> 16).Append('.')
                  .Append(n & 0x000000000000FFFFL);
                sb.Append(", ").Append(Windows.System.Profile.AnalyticsInfo.VersionInfo.DeviceFamily);
            }
            catch { }
            return sb.ToString();
        }

        // Заголовок смыслового блока — чтобы в файле было видно границы сессий импорта.
        public static void Section(string title)
        {
            W("──── " + title + " ────");
        }

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
                        if (fi.Exists && fi.Length > MaxBytes) System.IO.File.Delete(path);
                    }
                    catch { }
                    System.IO.File.AppendAllText(path, line + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch { /* лог не должен ломать импорт */ }
        }

        // Секреты в лог не уходят: пользователь присылает этот файл, а в ссылках лежат
        // UUID, пароли Shadowsocks и приватные ключи WireGuard.
        public static string Mask(string s)
        {
            if (string.IsNullOrEmpty(s)) return "<пусто>";
            if (s.Length <= 8) return "<" + s.Length + " симв.>";
            return s.Substring(0, 4) + "…" + s.Substring(s.Length - 2) + " (" + s.Length + " симв.)";
        }

        // Схема ссылки («vless», «vmess», …) без тела — тело может содержать секреты.
        public static string SchemeOf(string link)
        {
            if (string.IsNullOrWhiteSpace(link)) return "<пусто>";
            string s = link.Trim();
            int i = s.IndexOf("://", StringComparison.Ordinal);
            if (i <= 0) return "<без схемы>";
            return s.Substring(0, i).ToLowerInvariant();
        }
    }
}
