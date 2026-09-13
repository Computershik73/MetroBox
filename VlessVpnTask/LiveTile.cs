using System;
using System.Text;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace VlessVpnTask
{
    // Живая плитка со состоянием туннеля. Лежит здесь, а не в UI-проекте, потому что
    // источник правды о подключении — фоновая задача: она поднимает и рвёт туннель
    // даже когда приложение закрыто. VlessApp ссылается на эту сборку и зовёт те же
    // методы, когда сам замечает смену состояния.
    public static class LiveTile
    {
        // Плитку обновляют два процесса (UI и фоновая задача), у каждого свой кэш —
        // он нужен лишь чтобы не переписывать плитку одним и тем же каждую секунду.
        private static string _lastPayload;
        private static readonly object _lock = new object();

        public static void ShowConnected(string profileName, string details)
        {
            string name = string.IsNullOrWhiteSpace(profileName) ? "VPN-сервер" : profileName.Trim();
            string detail = (details ?? "").Trim();
            string since = "с " + DateTime.Now.ToString("HH:mm");

            string payload = BuildTileXml(name, detail, since);

            lock (_lock)
            {
                // Время подключения в тексте меняется, поэтому сравниваем без него:
                // иначе плитка переписывалась бы на каждой проверке статуса.
                string key = "on|" + name + "|" + detail;
                if (_lastPayload == key) return;
                _lastPayload = key;
            }

            try
            {
                var xml = new XmlDocument();
                xml.LoadXml(payload);
                GetUpdater().Update(new TileNotification(xml));
            }
            catch (Exception ex)
            {
                Log("не удалось обновить плитку: " + ex.Message);
            }
        }

        public static void ShowDisconnected()
        {
            lock (_lock)
            {
                if (_lastPayload == "off") return;
                _lastPayload = "off";
            }

            // Пустая плитка = обычная иконка приложения из манифеста.
            try { GetUpdater().Clear(); }
            catch (Exception ex) { Log("не удалось очистить плитку: " + ex.Message); }
        }

        private static TileUpdater GetUpdater()
        {
            try
            {
                return TileUpdateManager.CreateTileUpdaterForApplication();
            }
            catch
            {
                // Из отдельного процесса фоновой задачи безымянная перегрузка иногда не
                // может сама определить приложение — тогда указываем Id из манифеста.
                return TileUpdateManager.CreateTileUpdaterForApplication("App");
            }
        }

        private static string BuildTileXml(string name, string detail, string since)
        {
            string n = Escape(name);
            string d = Escape(detail);
            string s = Escape(since);

            var sb = new StringBuilder();
            sb.Append("<tile><visual branding='name'>");

            // Маленькой плитке binding НЕ даём намеренно: peek там не поддерживается,
            // и статус навсегда вытеснил бы иконку. Без binding'а система показывает
            // обычный логотип из манифеста.

            // placement='peek' — штатный механизм адаптивных плиток: система сама
            // перелистывает плитку между картинкой и содержимым, поэтому иконка
            // остаётся видна и во время подключения.
            sb.Append("<binding template='TileMedium'>");
            Peek(sb, "Square150x150Logo");
            sb.Append("<text hint-style='caption'>Подключен</text>");
            sb.Append("<text hint-style='captionSubtle' hint-wrap='true'>").Append(n).Append("</text>");
            if (d.Length > 0)
                sb.Append("<text hint-style='captionSubtle'>").Append(d).Append("</text>");
            sb.Append("</binding>");

            // Широкая и большая: текст слева, иконка отдельной колонкой справа.
            sb.Append("<binding template='TileWide'>");
            Peek(sb, "Wide310x150Logo");
            SideBySide(sb, 64, "base", n, d, s);
            sb.Append("</binding>");

            sb.Append("<binding template='TileLarge'>");
            Peek(sb, "Square310x310Logo");
            SideBySide(sb, 58, "subtitle", n, d, s);
            sb.Append("</binding>");

            sb.Append("</visual></tile>");
            return sb.ToString();
        }

        private static void Peek(StringBuilder sb, string asset)
        {
            sb.Append("<image placement='peek' src='ms-appx:///Assets/").Append(asset).Append(".png'/>");
        }

        // Две колонки: слева сведения о подключении, справа — иконка приложения.
        private static void SideBySide(StringBuilder sb, int textWeight, string headStyle,
                                       string n, string d, string s)
        {
            sb.Append("<group>");
            sb.Append("<subgroup hint-weight='").Append(textWeight).Append("' hint-textStacking='center'>");
            sb.Append("<text hint-style='").Append(headStyle).Append("'>Подключен</text>");
            sb.Append("<text hint-style='captionSubtle' hint-wrap='true'>").Append(n).Append("</text>");
            if (d.Length > 0)
                sb.Append("<text hint-style='captionSubtle'>").Append(d).Append("</text>");
            sb.Append("<text hint-style='captionSubtle'>").Append(s).Append("</text>");
            sb.Append("</subgroup>");

            sb.Append("<subgroup hint-weight='").Append(100 - textWeight).Append("' hint-textStacking='center'>");
            // Иконка на прозрачном фоне: со своей подложкой она дала бы внутри
            // плитки чужой тёмный квадрат поверх фона плитки.
            sb.Append("<image src='ms-appx:///Assets/TileIcon.png' hint-removeMargin='true'/>");
            sb.Append("</subgroup>");
            sb.Append("</group>");
        }

        // Имя профиля приходит из ссылки и спокойно содержит & и <.
        private static string Escape(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("&", "&amp;")
                    .Replace("<", "&lt;")
                    .Replace(">", "&gt;")
                    .Replace("'", "&apos;")
                    .Replace("\"", "&quot;");
        }

        private static void Log(string message)
        {
            try { FileLog.W("[TILE] " + message); }
            catch { System.Diagnostics.Debug.WriteLine("[TILE] " + message); }
        }
    }
}
