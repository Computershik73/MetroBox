using System;
using Windows.Storage;

namespace VlessVpnTask
{
    // Разбор HTTP-статусов, которыми сервер отвечает на попытку поднять транспорт
    // (WS-апгрейд, xhttp-GET/POST, HTTP/2 :status). Раньше каждый транспорт печатал
    // в лог собственную догадку вида «проверьте path/host» на ЛЮБОЙ не-успешный код,
    // и это уводило в сторону: например, 429 от бесплатного Cloudflare Worker — это
    // исчерпанная квота чужого/публичного конфига, а вовсе не ошибка в path.
    //
    // Здесь же лежит канал «фон -> UI»: плагин крутится в отдельном процессе фоновой
    // задачи, поэтому последнюю причину отказа кладём в LocalSettings (общий контейнер
    // пакета), а MainPage её оттуда читает и показывает подписью под кнопкой.
    // Класс публичный, потому что последнюю причину отказа читает UI-проект;
    // наружу отдаём только ReadLastError(), остальное — внутреннее дело транспортов.
    public static class NetDiag
    {
        internal const string LastErrKey = "v_NetErr";      // текст для пользователя
        internal const string LastErrAtKey = "v_NetErrAt";  // отметка времени (UTC, ISO-8601)

        // Для UI: последняя причина, по которой сервер отверг транспорт, или null.
        public static string ReadLastError()
        {
            try { return ApplicationData.Current.LocalSettings.Values[LastErrKey] as string; }
            catch { return null; }
        }

        // "HTTP/1.1 429 Too Many Requests" -> 429. Возвращает 0, если кода нет.
        internal static int ParseStatus(string statusLine)
        {
            if (string.IsNullOrEmpty(statusLine)) return 0;
            int i = 0;
            // пропускаем "HTTP/x.y" и пробелы перед кодом
            while (i < statusLine.Length && statusLine[i] != ' ') i++;
            while (i < statusLine.Length && statusLine[i] == ' ') i++;
            int start = i;
            while (i < statusLine.Length && statusLine[i] >= '0' && statusLine[i] <= '9') i++;
            if (i - start != 3) return 0;
            return int.Parse(statusLine.Substring(start, 3));
        }

        // Человеческое объяснение кода. Короткая фраза без префиксов — её видит и
        // пользователь в UI, и мы в логе.
        internal static string Explain(int code)
        {
            switch (code)
            {
                case 0: return "сервер прислал ответ без HTTP-статуса";

                case 400: return "сервер не понял запрос: скорее всего транспорт в конфиге (ws/xhttp/grpc) не совпадает с тем, что настроен на сервере";
                case 401:
                case 403: return "сервер отклонил подключение: неверный path/UUID либо доступ закрыт для вашего IP или страны";
                case 404: return "по указанному path на сервере ничего нет — проверьте path в конфиге";
                case 405: return "сервер не принимает такой HTTP-метод по этому path — вероятно, там другой транспорт";
                case 421: return "сервер не обслуживает этот Host — проверьте host/SNI в конфиге";
                case 426: return "сервер требует другой протокол: по этому path не WebSocket";
                case 429: return "сервер исчерпал лимит запросов. Так отвечает бесплатный Cloudflare Worker, когда кончилась суточная квота — обычно это чужой или публичный конфиг. Нужен другой сервер или ждать сброса лимита";

                case 500: return "внутренняя ошибка на сервере";
                case 502: return "промежуточный шлюз получил битый ответ от VPN-сервера";
                case 503: return "сервер временно недоступен: перегрузка или обслуживание";
                case 504: return "шлюз не дождался ответа от VPN-сервера";

                // Cloudflare-специфика: код 5xx приходит от edge, а не от самого сервера.
                case 520: return "Cloudflare не смог разобрать ответ сервера (520)";
                case 521: return "Cloudflare: сервер за ним выключен или не принимает соединения (521)";
                case 522: return "Cloudflare: сервер за ним не отвечает вовремя (522)";
                case 523: return "Cloudflare: сервер за ним недостижим (523)";
                case 524: return "Cloudflare: сервер за ним не ответил вовремя (524)";
                case 525:
                case 526: return "Cloudflare: не удалось установить TLS до сервера за ним (" + code + ")";
                case 530: return "Cloudflare: домен не привязан к рабочему сервису (530)";
            }

            if (code >= 300 && code < 400)
                return "сервер отвечает редиректом (" + code + "): path ведёт на обычную страницу, а не на VPN-эндпоинт";
            if (code >= 400 && code < 500)
                return "сервер отклонил запрос (" + code + ") — проверьте path/host в конфиге";
            if (code >= 500)
                return "ошибка на стороне сервера (" + code + ")";
            if (code >= 200 && code < 300)
                return "сервер ответил " + code + " вместо ожидаемого апгрейда — путь ведёт на обычную страницу, а не на VPN-эндпоинт";
            return "неожиданный ответ сервера (" + code + ")";
        }

        // Пишет в лог разобранную причину и кладёт её же для UI.
        // tag — метка транспорта в логе, например "WS" или "XHTTP".
        internal static void ReportHttp(string tag, int code, string expected)
        {
            string why = Explain(code);
            FileLog.Important("[" + tag + " ERROR] Ожидался " + expected + ", пришёл " + code + ": " + why);
            Publish(why);
        }

        internal static void ReportHttp(string tag, string statusLine, string expected)
        {
            ReportHttp(tag, ParseStatus(statusLine), expected);
        }

        // Произвольная причина, не связанная с HTTP-кодом (таймаут, обрыв, GOAWAY).
        internal static void Report(string tag, string why)
        {
            FileLog.Important("[" + tag + " ERROR] " + why);
            Publish(why);
        }

        // Транспорт поднялся — снимаем прошлую жалобу, чтобы UI не показывал
        // просроченную ошибку поверх рабочего туннеля.
        internal static void ClearError()
        {
            try
            {
                var v = ApplicationData.Current.LocalSettings.Values;
                if (v.ContainsKey(LastErrKey)) v.Remove(LastErrKey);
                if (v.ContainsKey(LastErrAtKey)) v.Remove(LastErrAtKey);
            }
            catch { }
        }

        private static void Publish(string why)
        {
            try
            {
                var v = ApplicationData.Current.LocalSettings.Values;
                v[LastErrKey] = why;
                v[LastErrAtKey] = DateTime.UtcNow.ToString("o");
            }
            catch { }
        }
    }
}
