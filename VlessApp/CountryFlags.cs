using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.UI.Xaml.Media.Imaging;

namespace VlessApp
{
    // Флаги стран для списка серверов.
    //
    // Почему картинки, а не эмодзи: Windows (и Windows 10 Mobile в том числе)
    // намеренно не рисует последовательности regional indicator как флаги —
    // «🇳🇱» показывается буквенным квадратиком «NL». Поэтому эмодзи из имени
    // профиля здесь служит только источником кода страны, а само изображение
    // рисуется попиксельно в WriteableBitmap.
    //
    // Рисуем в 108×72 (ровно 3:2) и показываем в 26×18 — четырёхкратный запас
    // даёт сглаживание при уменьшении средствами XAML, поэтому собственный
    // антиалиасинг не нужен даже кругам и звёздам.
    internal static class CountryFlags
    {
        private const int W = 108;
        private const int H = 72;

        private static readonly Dictionary<string, WriteableBitmap> Cache =
            new Dictionary<string, WriteableBitmap>(StringComparer.OrdinalIgnoreCase);

        // =====================================================================
        // Определение страны по имени профиля
        // =====================================================================

        // Порядок проверок важен: эмодзи однозначен, полное название почти
        // однозначно, а двухбуквенный код легко даёт ложные срабатывания —
        // поэтому он идёт последним и только отдельным словом.
        public static string DetectFromName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "";

            string fromEmoji = FromRegionalIndicators(name);
            if (fromEmoji != "") return fromEmoji;

            string lower = name.ToLowerInvariant();

            // Полные названия. Проверяем от длинных к коротким, иначе
            // «Южная Корея» совпала бы с «Корея» раньше, чем нужно.
            foreach (var kv in NamesByLength)
            {
                if (lower.IndexOf(kv.Key, StringComparison.Ordinal) >= 0)
                    return kv.Value;
            }

            // Коды отдельными словами: сначала трёхбуквенные (RUS, DEU, NLD),
            // потом двухбуквенные (RU, DE, NL). Ищем по исходной строке, а не по
            // lower: регистр — единственное, что отличает код страны от обычного
            // слова, и без него «my-server-01» уезжал в Малайзию.
            string token3 = FindCodeToken(name, 3);
            if (token3 != "") return token3;

            string token2 = FindCodeToken(name, 2);
            if (token2 != "") return token2;

            return "";
        }

        // U+1F1E6..U+1F1FF, в UTF-16 это суррогатные пары D83C DDE6..DDFF.
        private static string FromRegionalIndicators(string s)
        {
            for (int i = 0; i + 3 < s.Length; i++)
            {
                if (s[i] != '\uD83C' || s[i + 2] != '\uD83C') continue;
                int a = s[i + 1], b = s[i + 3];
                if (a < 0xDDE6 || a > 0xDDFF || b < 0xDDE6 || b > 0xDDFF) continue;
                char c1 = (char)('A' + (a - 0xDDE6));
                char c2 = (char)('A' + (b - 0xDDE6));
                string code = new string(new[] { c1, c2 });
                if (Alpha2Set.Contains(code)) return code;
            }
            return "";
        }

        private static bool IsLetter(char c)
        {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        // Коды, которые в нижнем регистре неотличимы от обычных слов. В верхнем
        // регистре они принимаются («[IT] Milan»), в нижнем — отбрасываются,
        // иначе «my-server», «no-log», «it-01» получали бы чужие флаги.
        private static readonly HashSet<string> AmbiguousLower = new HashSet<string>(StringComparer.Ordinal)
        {
            "MY","IN","IT","IS","NO","AT","BE","US","ME","BY","ID","AM","SA","LA","AS","SO","DO","OR","TO","IF","ON","WE","HE","AD","SM",
            "CAN","ARE","EST","PER","NOR","COL","MAR","AUT","IND"
        };

        private static string FindCodeToken(string src, int len)
        {
            for (int i = 0; i + len <= src.Length; i++)
            {
                if (i > 0 && IsLetter(src[i - 1])) continue;
                if (i + len < src.Length && IsLetter(src[i + len])) continue;

                bool allLetters = true;
                bool allUpper = true;
                for (int k = 0; k < len; k++)
                {
                    char c = src[i + k];
                    if (!IsLetter(c)) { allLetters = false; break; }
                    if (c < 'A' || c > 'Z') allUpper = false;
                }
                if (!allLetters) continue;

                string tok = src.Substring(i, len).ToUpperInvariant();
                if (!allUpper && AmbiguousLower.Contains(tok)) continue;

                if (len == 3)
                {
                    string mapped;
                    if (Alpha3.TryGetValue(tok, out mapped)) return mapped;
                }
                else if (Alpha2Set.Contains(tok)) return tok;
            }
            return "";
        }

        // Имя без ведущего флаг-эмодзи: раз флаг теперь рисуется картинкой,
        // буквенный квадратик «NL» рядом с ней выглядел бы мусором.
        public static string StripFlagEmoji(string name)
        {
            if (string.IsNullOrEmpty(name)) return name;
            var sb = new StringBuilder(name.Length);
            for (int i = 0; i < name.Length; i++)
            {
                if (i + 1 < name.Length && name[i] == '\uD83C' &&
                    name[i + 1] >= 0xDDE6 && name[i + 1] <= 0xDDFF)
                {
                    i++;             // пропускаем суррогатную пару целиком
                    continue;
                }
                sb.Append(name[i]);
            }
            return sb.ToString().Trim(' ', '\t', '-', '|', '_');
        }

        // =====================================================================
        // Получение картинки
        // =====================================================================

        // Возвращает флаг или null, если страна неизвестна либо не нарисована.
        // Вызывать только из UI-потока: WriteableBitmap этого требует.
        public static WriteableBitmap GetBitmap(string iso2)
        {
            if (string.IsNullOrEmpty(iso2)) return null;
            iso2 = iso2.ToUpperInvariant();

            WriteableBitmap cached;
            if (Cache.TryGetValue(iso2, out cached)) return cached;

            byte[] px = Paint(iso2);
            if (px == null)
            {
                Cache[iso2] = null;
                return null;
            }

            var bmp = new WriteableBitmap(W, H);
            using (var stream = bmp.PixelBuffer.AsStream())
            {
                stream.Write(px, 0, px.Length);
            }
            bmp.Invalidate();
            Cache[iso2] = bmp;
            return bmp;
        }

        private static byte[] Paint(string code)
        {
            byte[] px = new byte[W * H * 4];

            string spec;
            if (Stripes.TryGetValue(code, out spec))
            {
                PaintStripes(px, spec);
                return px;
            }

            switch (code)
            {
                case "JP": Japan(px); return px;
                case "BD": Disc(px, W / 2.0 - 6, H / 2.0, 21, 0x006A4E, 0xF42A41, true); return px;
                case "CH": SquareCross(px, 0xDA291C, 0xFFFFFF); return px;
                case "GE": SquareCross(px, 0xFFFFFF, 0xFF0000); return px;
                case "DK": Nordic(px, 0xC8102E, 0xFFFFFF); return px;
                case "SE": Nordic(px, 0x006AA7, 0xFECC00); return px;
                case "NO": NorwayCross(px); return px;
                case "FI": Nordic(px, 0xFFFFFF, 0x003580); return px;
                case "IS": IcelandCross(px); return px;
                case "CZ": Czechia(px); return px;
                case "GB": UnionJack(px, 0, 0, W, H); return px;
                case "US": Usa(px); return px;
                case "AU": Australia(px); return px;
                case "NZ": NewZealand(px); return px;
                case "CN": China(px); return px;
                case "VN": FillAll(px, 0xDA251D); Star(px, W / 2.0, H / 2.0, 20, -90, 0xFFFF00); return px;
                case "TR": Turkey(px); return px;
                case "SG": Singapore(px); return px;
                case "KR": Korea(px); return px;
                case "IN": India(px); return px;
                case "GR": Greece(px); return px;
                case "PT": Portugal(px); return px;
                case "BR": Brazil(px); return px;
                case "CA": Canada(px); return px;
                case "CL": Chile(px); return px;
                case "TW": Taiwan(px); return px;
                case "HK": FillAll(px, 0xDE2910); Disc(px, W / 2.0, H / 2.0, 17, 0xFFFFFF); return px;
                case "IL": Israel(px); return px;
                case "ZA": SouthAfrica(px); return px;
                case "MA": FillAll(px, 0xC1272D); Star(px, W / 2.0, H / 2.0, 20, -90, 0x006233); return px;
                case "MY": Malaysia(px); return px;
                case "PH": Philippines(px); return px;
                case "KZ": FillAll(px, 0x00AFCA); Disc(px, W / 2.0, H / 2.0, 16, 0xFEC50C); return px;
                case "UZ": Uzbekistan(px); return px;
                case "AZ": Azerbaijan(px); return px;
                case "SA": FillAll(px, 0x165D31); Fill(px, 18, 46, W - 18, 52, 0xFFFFFF); return px;
                case "PK": Pakistan(px); return px;
                case "MD": Moldova(px); return px;
                case "BY": Belarus(px); return px;
                case "AR": Argentina(px); return px;
                case "KE": Kenya(px); return px;
                default: return null;
            }
        }

        // =====================================================================
        // Примитивы
        // =====================================================================

        private static void Put(byte[] px, int x, int y, uint rgb)
        {
            if (x < 0 || y < 0 || x >= W || y >= H) return;
            int o = (y * W + x) * 4;
            px[o + 0] = (byte)(rgb & 0xFF);           // B
            px[o + 1] = (byte)((rgb >> 8) & 0xFF);    // G
            px[o + 2] = (byte)((rgb >> 16) & 0xFF);   // R
            px[o + 3] = 0xFF;                         // A
        }

        private static void FillAll(byte[] px, uint rgb)
        {
            Fill(px, 0, 0, W, H, rgb);
        }

        private static void Fill(byte[] px, int x0, int y0, int x1, int y1, uint rgb)
        {
            if (x0 < 0) x0 = 0;
            if (y0 < 0) y0 = 0;
            if (x1 > W) x1 = W;
            if (y1 > H) y1 = H;
            for (int y = y0; y < y1; y++)
                for (int x = x0; x < x1; x++)
                    Put(px, x, y, rgb);
        }

        private static void Disc(byte[] px, double cx, double cy, double r, uint rgb)
        {
            int x0 = (int)Math.Floor(cx - r), x1 = (int)Math.Ceiling(cx + r);
            int y0 = (int)Math.Floor(cy - r), y1 = (int)Math.Ceiling(cy + r);
            double r2 = r * r;
            for (int y = y0; y <= y1; y++)
                for (int x = x0; x <= x1; x++)
                {
                    double dx = x + 0.5 - cx, dy = y + 0.5 - cy;
                    if (dx * dx + dy * dy <= r2) Put(px, x, y, rgb);
                }
        }

        // Диск на сплошном фоне: заливка фона + круг. Флаг Бангладеш и подобные.
        private static void Disc(byte[] px, double cx, double cy, double r, uint bg, uint fg, bool fillBg)
        {
            if (fillBg) FillAll(px, bg);
            Disc(px, cx, cy, r, fg);
        }

        // Пятиконечная звезда, заливка по правилу «нечётного пересечения».
        private static void Star(byte[] px, double cx, double cy, double r, double rotDeg, uint rgb)
        {
            const int n = 10;
            double[] xs = new double[n], ys = new double[n];
            double inner = r * 0.382;
            for (int i = 0; i < n; i++)
            {
                double rad = (i % 2 == 0) ? r : inner;
                double a = (rotDeg + i * 36.0) * Math.PI / 180.0;
                xs[i] = cx + rad * Math.Cos(a);
                ys[i] = cy + rad * Math.Sin(a);
            }
            FillPolygon(px, xs, ys, rgb);
        }

        private static void FillPolygon(byte[] px, double[] xs, double[] ys, uint rgb)
        {
            double minY = double.MaxValue, maxY = double.MinValue;
            for (int i = 0; i < ys.Length; i++)
            {
                if (ys[i] < minY) minY = ys[i];
                if (ys[i] > maxY) maxY = ys[i];
            }
            int y0 = Math.Max(0, (int)Math.Floor(minY));
            int y1 = Math.Min(H - 1, (int)Math.Ceiling(maxY));

            var xsAt = new List<double>();
            for (int y = y0; y <= y1; y++)
            {
                double sy = y + 0.5;
                xsAt.Clear();
                for (int i = 0; i < xs.Length; i++)
                {
                    int j = (i + 1) % xs.Length;
                    double ay = ys[i], by = ys[j];
                    if ((ay <= sy && by > sy) || (by <= sy && ay > sy))
                    {
                        double t = (sy - ay) / (by - ay);
                        xsAt.Add(xs[i] + t * (xs[j] - xs[i]));
                    }
                }
                xsAt.Sort();
                for (int k = 0; k + 1 < xsAt.Count; k += 2)
                {
                    int a = (int)Math.Round(xsAt[k]);
                    int b = (int)Math.Round(xsAt[k + 1]);
                    for (int x = a; x < b; x++) Put(px, x, y, rgb);
                }
            }
        }

        // =====================================================================
        // Полосатые флаги — таблица спецификаций
        // =====================================================================
        // "h:" горизонтальные, "v:" вертикальные. Вес полосы — префиксом "2*".
        private static void PaintStripes(byte[] px, string spec)
        {
            bool horizontal = spec[0] == 'h';
            string body = spec.Substring(2);
            string[] parts = body.Split(',');

            int[] weights = new int[parts.Length];
            uint[] colors = new uint[parts.Length];
            int total = 0;
            for (int i = 0; i < parts.Length; i++)
            {
                string p = parts[i];
                int star = p.IndexOf('*');
                int wgt = 1;
                if (star > 0)
                {
                    wgt = int.Parse(p.Substring(0, star));
                    p = p.Substring(star + 1);
                }
                weights[i] = wgt;
                total += wgt;
                colors[i] = Convert.ToUInt32(p, 16);
            }

            int span = horizontal ? H : W;
            int acc = 0;
            for (int i = 0; i < parts.Length; i++)
            {
                int from = (int)Math.Round(acc * (double)span / total);
                acc += weights[i];
                int to = (int)Math.Round(acc * (double)span / total);
                if (horizontal) Fill(px, 0, from, W, to, colors[i]);
                else Fill(px, from, 0, to, H, colors[i]);
            }
        }

        private static readonly Dictionary<string, string> Stripes =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Горизонтальные
            { "RU", "h:FFFFFF,0039A6,D52B1E" },
            { "NL", "h:AE1C28,FFFFFF,21468B" },
            { "DE", "h:000000,DD0000,FFCE00" },
            { "AT", "h:ED2939,FFFFFF,ED2939" },
            { "LV", "h:2*9E3039,1*FFFFFF,2*9E3039" },
            { "EE", "h:0072CE,000000,FFFFFF" },
            { "LT", "h:FDB913,006A44,C1272D" },
            { "LU", "h:ED2939,FFFFFF,00A1DE" },
            { "HU", "h:CE2939,FFFFFF,477050" },
            { "BG", "h:FFFFFF,00966E,D62612" },
            { "RS", "h:C6363C,0C4076,FFFFFF" },
            { "SI", "h:FFFFFF,005DA4,D50000" },
            { "SK", "h:FFFFFF,0B4EA2,EE1620" },
            { "HR", "h:FF0000,FFFFFF,171796" },
            { "AM", "h:D90012,0033A0,F2A800" },
            { "PL", "h:FFFFFF,DC143C" },
            { "UA", "h:0057B7,FFD700" },
            { "ID", "h:FF0000,FFFFFF" },
            { "MC", "h:CE1126,FFFFFF" },
            { "EG", "h:CE1126,FFFFFF,000000" },
            { "SY", "h:CE1126,FFFFFF,000000" },
            { "YE", "h:CE1126,FFFFFF,000000" },
            { "ES", "h:1*AA151B,2*F1BF00,1*AA151B" },
            { "TH", "h:1*A51931,1*F4F5F8,2*2D2A4A,1*F4F5F8,1*A51931" },
            { "CO", "h:2*FCD116,1*003893,1*CE1126" },
            { "VE", "h:FFCC00,00247D,CF0821" },
            { "EC", "h:2*FFDD00,1*034EA2,1*ED1C24" },
            { "DE_AT", "h:ED2939,FFFFFF,ED2939" },

            // Вертикальные
            { "FR", "v:002395,FFFFFF,ED2939" },
            { "IT", "v:008C45,F4F5F0,CD212A" },
            { "IE", "v:169B62,FFFFFF,FF883E" },
            { "BE", "v:000000,FDDA24,EF3340" },
            { "RO", "v:002B7F,FCD116,CE1126" },
            { "MX", "v:006847,FFFFFF,CE1126" },
            { "PE", "v:D91023,FFFFFF,D91023" },
            { "NG", "v:008751,FFFFFF,008751" },
            { "FR_MC", "v:002395,FFFFFF,ED2939" },
        };

        // =====================================================================
        // Особые флаги
        // =====================================================================

        private static void Japan(byte[] px)
        {
            FillAll(px, 0xFFFFFF);
            Disc(px, W / 2.0, H / 2.0, 21.6, 0xBC002D);
        }

        // Скандинавский крест: вертикаль смещена к древку.
        private static void Nordic(byte[] px, uint bg, uint cross)
        {
            FillAll(px, bg);
            int t = 12;                    // толщина креста
            int vx = 34;                   // центр вертикали
            Fill(px, 0, H / 2 - t / 2, W, H / 2 + t / 2, cross);
            Fill(px, vx - t / 2, 0, vx + t / 2, H, cross);
        }

        private static void NorwayCross(byte[] px)
        {
            Nordic(px, 0xBA0C2F, 0xFFFFFF);
            int t = 6;
            int vx = 34;
            Fill(px, 0, H / 2 - t / 2, W, H / 2 + t / 2, 0x00205B);
            Fill(px, vx - t / 2, 0, vx + t / 2, H, 0x00205B);
        }

        private static void IcelandCross(byte[] px)
        {
            Nordic(px, 0x02529C, 0xFFFFFF);
            int t = 6;
            int vx = 34;
            Fill(px, 0, H / 2 - t / 2, W, H / 2 + t / 2, 0xDC1E35);
            Fill(px, vx - t / 2, 0, vx + t / 2, H, 0xDC1E35);
        }

        // Центрированный крест (Швейцария, Грузия — без малых крестов).
        private static void SquareCross(byte[] px, uint bg, uint cross)
        {
            FillAll(px, bg);
            int t = 14;
            Fill(px, 0, H / 2 - t / 2, W, H / 2 + t / 2, cross);
            Fill(px, W / 2 - t / 2, 0, W / 2 + t / 2, H, cross);
        }

        private static void Czechia(byte[] px)
        {
            Fill(px, 0, 0, W, H / 2, 0xFFFFFF);
            Fill(px, 0, H / 2, W, H, 0xD7141A);
            double[] xs = { 0, 54, 0 };
            double[] ys = { 0, H / 2.0, H };
            FillPolygon(px, xs, ys, 0x11457E);
        }

        private static void UnionJack(byte[] px, int ox, int oy, int w, int h)
        {
            uint blue = 0x012169, white = 0xFFFFFF, red = 0xC8102E;
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                    Put(px, ox + x, oy + y, blue);

            // Косой крест (Андреевский + Патрика) белым, затем красным потоньше.
            DiagBand(px, ox, oy, w, h, w * 0.30, white);
            DiagBand(px, ox, oy, w, h, w * 0.12, red);

            // Прямой крест: белый широкий, красный узкий.
            int tw = (int)(h * 0.32), tr = (int)(h * 0.18);
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                    if (Math.Abs(y - h / 2.0) < tw / 2.0 || Math.Abs(x - w / 2.0) < tw / 2.0)
                        Put(px, ox + x, oy + y, white);
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                    if (Math.Abs(y - h / 2.0) < tr / 2.0 || Math.Abs(x - w / 2.0) < tr / 2.0)
                        Put(px, ox + x, oy + y, red);
        }

        // Полоса вдоль обеих диагоналей прямоугольника.
        private static void DiagBand(byte[] px, int ox, int oy, int w, int h, double thick, uint rgb)
        {
            double k = h / (double)w;
            double half = thick * k / 2.0;
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                {
                    if (Math.Abs(y - k * x) < half || Math.Abs(y - (h - k * x)) < half)
                        Put(px, ox + x, oy + y, rgb);
                }
        }

        private static void Usa(byte[] px)
        {
            for (int i = 0; i < 13; i++)
            {
                int y0 = (int)Math.Round(i * H / 13.0);
                int y1 = (int)Math.Round((i + 1) * H / 13.0);
                Fill(px, 0, y0, W, y1, (i % 2 == 0) ? 0xB31942u : 0xFFFFFFu);
            }
            int cw = (int)(W * 0.40), ch = (int)Math.Round(7 * H / 13.0);
            Fill(px, 0, 0, cw, ch, 0x0A3161);
            // Звёзды сеткой 5×4 — на 26 px итогового размера отдельные лучи
            // всё равно не читаются, важна фактура.
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < 5; c++)
                {
                    double sx = cw * (c + 0.5) / 5.0;
                    double sy = ch * (r + 0.5) / 4.0;
                    Star(px, sx, sy, 3.6, -90, 0xFFFFFF);
                }
        }

        // Австралия: шесть белых звёзд — Южный Крест плюс большая звезда
        // Содружества под кантоном.
        private static void Australia(byte[] px)
        {
            FillAll(px, 0x00247D);
            UnionJack(px, 0, 0, W / 2, H / 2);
            Star(px, W * 0.74, H * 0.22, 6, -90, 0xFFFFFF);
            Star(px, W * 0.84, H * 0.48, 6, -90, 0xFFFFFF);
            Star(px, W * 0.66, H * 0.58, 6, -90, 0xFFFFFF);
            Star(px, W * 0.74, H * 0.82, 6, -90, 0xFFFFFF);
            Star(px, W * 0.76, H * 0.50, 3, -90, 0xFFFFFF);
            Star(px, W * 0.25, H * 0.78, 9, -90, 0xFFFFFF);
        }

        // Новая Зеландия: четыре красных звезды с белой обводкой, без звезды
        // Содружества — этим и отличается от австралийского флага.
        private static void NewZealand(byte[] px)
        {
            FillAll(px, 0x00247D);
            UnionJack(px, 0, 0, W / 2, H / 2);
            double[,] pts = { { 0.80, 0.26 }, { 0.88, 0.52 }, { 0.68, 0.56 }, { 0.78, 0.80 } };
            for (int i = 0; i < 4; i++)
            {
                Star(px, W * pts[i, 0], H * pts[i, 1], 7.5, -90, 0xFFFFFF);
                Star(px, W * pts[i, 0], H * pts[i, 1], 5.0, -90, 0xCC142B);
            }
        }

        private static void China(byte[] px)
        {
            FillAll(px, 0xDE2910);
            Star(px, 20, 18, 11, -90, 0xFFDE00);
            Star(px, 37, 8, 4, -90, 0xFFDE00);
            Star(px, 44, 17, 4, -90, 0xFFDE00);
            Star(px, 44, 28, 4, -90, 0xFFDE00);
            Star(px, 37, 36, 4, -90, 0xFFDE00);
        }

        private static void Turkey(byte[] px)
        {
            FillAll(px, 0xE30A17);
            Disc(px, 40, H / 2.0, 17, 0xFFFFFF);
            Disc(px, 46, H / 2.0, 13.5, 0xE30A17);   // вырез — получается полумесяц
            Star(px, 66, H / 2.0, 9, -90, 0xFFFFFF);
        }

        private static void Singapore(byte[] px)
        {
            Fill(px, 0, 0, W, H / 2, 0xEE2536);
            Fill(px, 0, H / 2, W, H, 0xFFFFFF);
            Disc(px, 26, 18, 12, 0xFFFFFF);
            Disc(px, 33, 18, 10, 0xEE2536);
            for (int i = 0; i < 5; i++)
            {
                double a = -90 + i * 72.0;
                double rad = a * Math.PI / 180.0;
                Star(px, 46 + 9 * Math.Cos(rad), 18 + 9 * Math.Sin(rad), 3.2, -90, 0xFFFFFF);
            }
        }

        private static void Korea(byte[] px)
        {
            FillAll(px, 0xFFFFFF);
            // Тхэгык: круг из двух половин, верх красный, низ синий.
            Disc(px, W / 2.0, H / 2.0, 16, 0xCD2E3A);
            for (int y = H / 2; y < H / 2 + 17; y++)
                for (int x = W / 2 - 17; x < W / 2 + 17; x++)
                {
                    double dx = x + 0.5 - W / 2.0, dy = y + 0.5 - H / 2.0;
                    if (dx * dx + dy * dy <= 16 * 16) Put(px, x, y, 0x0047A0);
                }
            Disc(px, W / 2.0 - 8, H / 2.0, 8, 0xCD2E3A);
            Disc(px, W / 2.0 + 8, H / 2.0, 8, 0x0047A0);
            // Четыре триграммы — упрощённо, сплошными брусками по углам.
            Fill(px, 12, 14, 30, 18, 0x000000);
            Fill(px, 12, 54, 30, 58, 0x000000);
            Fill(px, 78, 14, 96, 18, 0x000000);
            Fill(px, 78, 54, 96, 58, 0x000000);
        }

        private static void India(byte[] px)
        {
            PaintStripes(px, "h:FF9933,FFFFFF,138808");
            Disc(px, W / 2.0, H / 2.0, 10, 0x000080);
            Disc(px, W / 2.0, H / 2.0, 7, 0xFFFFFF);
            Disc(px, W / 2.0, H / 2.0, 2.5, 0x000080);
        }

        private static void Greece(byte[] px)
        {
            for (int i = 0; i < 9; i++)
            {
                int y0 = (int)Math.Round(i * H / 9.0);
                int y1 = (int)Math.Round((i + 1) * H / 9.0);
                Fill(px, 0, y0, W, y1, (i % 2 == 0) ? 0x0D5EAFu : 0xFFFFFFu);
            }
            int c = (int)Math.Round(5 * H / 9.0);
            Fill(px, 0, 0, c, c, 0x0D5EAF);
            int t = 8;
            Fill(px, 0, c / 2 - t / 2, c, c / 2 + t / 2, 0xFFFFFF);
            Fill(px, c / 2 - t / 2, 0, c / 2 + t / 2, c, 0xFFFFFF);
        }

        private static void Portugal(byte[] px)
        {
            Fill(px, 0, 0, (int)(W * 0.40), H, 0x006600);
            Fill(px, (int)(W * 0.40), 0, W, H, 0xFF0000);
            Disc(px, W * 0.40, H / 2.0, 13, 0xFFFF00);
            Disc(px, W * 0.40, H / 2.0, 9, 0xFFFFFF);
            Disc(px, W * 0.40, H / 2.0, 5, 0xFF0000);
        }

        private static void Brazil(byte[] px)
        {
            FillAll(px, 0x009B3A);
            double[] xs = { 8, W / 2.0, W - 8, W / 2.0 };
            double[] ys = { H / 2.0, 6, H / 2.0, H - 6 };
            FillPolygon(px, xs, ys, 0xFEDF00);
            Disc(px, W / 2.0, H / 2.0, 14, 0x002776);
        }

        private static void Canada(byte[] px)
        {
            Fill(px, 0, 0, (int)(W * 0.25), H, 0xFF0000);
            Fill(px, (int)(W * 0.25), 0, (int)(W * 0.75), H, 0xFFFFFF);
            Fill(px, (int)(W * 0.75), 0, W, H, 0xFF0000);
            // Кленовый лист упрощён до узнаваемого силуэта.
            double cx = W / 2.0;
            double[] xs = { cx, cx + 5, cx + 14, cx + 9, cx + 17, cx + 6, cx + 5, cx, cx - 5, cx - 6, cx - 17, cx - 9, cx - 14, cx - 5 };
            double[] ys = { 14, 26, 22, 32, 38, 40, 56, 50, 56, 40, 38, 32, 22, 26 };
            FillPolygon(px, xs, ys, 0xFF0000);
        }

        private static void Chile(byte[] px)
        {
            Fill(px, 0, 0, W, H / 2, 0xFFFFFF);
            Fill(px, 0, H / 2, W, H, 0xD52B1E);
            Fill(px, 0, 0, H / 2, H / 2, 0x0039A6);
            Star(px, H / 4.0, H / 4.0, 12, -90, 0xFFFFFF);
        }

        private static void Taiwan(byte[] px)
        {
            FillAll(px, 0xFE0000);
            Fill(px, 0, 0, W / 2, H / 2, 0x000095);
            Disc(px, W / 4.0, H / 4.0, 11, 0xFFFFFF);
            Disc(px, W / 4.0, H / 4.0, 7, 0x000095);
            Disc(px, W / 4.0, H / 4.0, 5, 0xFFFFFF);
        }

        private static void Israel(byte[] px)
        {
            FillAll(px, 0xFFFFFF);
            Fill(px, 0, 8, W, 15, 0x0038B8);
            Fill(px, 0, H - 15, W, H - 8, 0x0038B8);
            // Щит Давида — два треугольника.
            double cx = W / 2.0, cy = H / 2.0, r = 14;
            double[] ax = { cx, cx - r * 0.866, cx + r * 0.866 };
            double[] ay = { cy - r, cy + r * 0.5, cy + r * 0.5 };
            FillPolygon(px, ax, ay, 0x0038B8);
            double[] bx = { cx, cx - r * 0.866, cx + r * 0.866 };
            double[] by = { cy + r, cy - r * 0.5, cy - r * 0.5 };
            FillPolygon(px, bx, by, 0x0038B8);
            Disc(px, cx, cy, r * 0.42, 0xFFFFFF);
        }

        private static void SouthAfrica(byte[] px)
        {
            Fill(px, 0, 0, W, H / 2, 0xDE3831);
            Fill(px, 0, H / 2, W, H, 0x002395);
            double[] xs = { 0, 46, 0 };
            double[] ys = { 0, H / 2.0, H };
            FillPolygon(px, xs, ys, 0x007A4D);
            Fill(px, 0, H / 2 - 6, 46, H / 2 + 6, 0x007A4D);
            Fill(px, 0, H / 2 - 12, 12, H / 2 + 12, 0xFFB612);
        }

        private static void Malaysia(byte[] px)
        {
            for (int i = 0; i < 14; i++)
            {
                int y0 = (int)Math.Round(i * H / 14.0);
                int y1 = (int)Math.Round((i + 1) * H / 14.0);
                Fill(px, 0, y0, W, y1, (i % 2 == 0) ? 0xCC0001u : 0xFFFFFFu);
            }
            Fill(px, 0, 0, (int)(W * 0.5), (int)Math.Round(8 * H / 14.0), 0x010066);
            Disc(px, 24, 20, 11, 0xFFCC00);
            Disc(px, 30, 20, 9, 0x010066);
            Star(px, 44, 20, 7, -90, 0xFFCC00);
        }

        private static void Philippines(byte[] px)
        {
            Fill(px, 0, 0, W, H / 2, 0x0038A8);
            Fill(px, 0, H / 2, W, H, 0xCE1126);
            double[] xs = { 0, 46, 0 };
            double[] ys = { 0, H / 2.0, H };
            FillPolygon(px, xs, ys, 0xFFFFFF);
            Disc(px, 14, H / 2.0, 6, 0xFCD116);
        }

        private static void Uzbekistan(byte[] px)
        {
            PaintStripes(px, "h:1*0099B5,1*FFFFFF,1*1EB53A");
            Disc(px, 22, 12, 7, 0xFFFFFF);
            Disc(px, 27, 12, 6, 0x0099B5);
        }

        private static void Azerbaijan(byte[] px)
        {
            PaintStripes(px, "h:00B5E2,ED2939,3F9C35");
            Disc(px, 50, H / 2.0, 10, 0xFFFFFF);
            Disc(px, 55, H / 2.0, 8, 0xED2939);
            Star(px, 66, H / 2.0, 6, -90, 0xFFFFFF);
        }

        private static void Pakistan(byte[] px)
        {
            Fill(px, 0, 0, (int)(W * 0.25), H, 0xFFFFFF);
            Fill(px, (int)(W * 0.25), 0, W, H, 0x01411C);
            Disc(px, 66, H / 2.0, 15, 0xFFFFFF);
            Disc(px, 72, H / 2.0, 13, 0x01411C);
            Star(px, 82, 26, 6, -90, 0xFFFFFF);
        }

        private static void Moldova(byte[] px)
        {
            PaintStripes(px, "v:0046AE,FFD200,CC092F");
            Disc(px, W / 2.0, H / 2.0, 9, 0xB07A28);
        }

        private static void Belarus(byte[] px)
        {
            Fill(px, 0, 0, W, (int)Math.Round(H * 2 / 3.0), 0xCE1720);
            Fill(px, 0, (int)Math.Round(H * 2 / 3.0), W, H, 0x007C30);
            Fill(px, 0, 0, 14, H, 0xFFFFFF);
            for (int y = 0; y < H; y += 8)
                Fill(px, 3, y, 11, y + 4, 0xCE1720);
        }

        private static void Argentina(byte[] px)
        {
            PaintStripes(px, "h:74ACDF,FFFFFF,74ACDF");
            Disc(px, W / 2.0, H / 2.0, 8, 0xF6B40E);
        }

        private static void Kenya(byte[] px)
        {
            PaintStripes(px, "h:6*000000,1*FFFFFF,6*BB0000,1*FFFFFF,6*006600");
            Disc(px, W / 2.0, H / 2.0, 11, 0xBB0000);
            Fill(px, W / 2 - 3, 10, W / 2 + 3, H - 10, 0xFFFFFF);
        }

        // =====================================================================
        // Справочники
        // =====================================================================

        private static readonly HashSet<string> Alpha2Set = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RU","NL","DE","FR","IT","GB","US","CA","ES","PT","PL","UA","BY","MD","RO","BG","GR","TR",
            "CZ","SK","SI","HR","RS","HU","AT","CH","BE","LU","IE","DK","SE","NO","FI","IS","EE","LV",
            "LT","JP","KR","CN","HK","TW","SG","IN","ID","TH","VN","MY","PH","AE","IL","SA","QA","IR",
            "PK","BD","AU","NZ","BR","AR","CL","MX","CO","PE","VE","EC","ZA","EG","NG","KE","MA","AM",
            "GE","AZ","KZ","UZ","KG","TJ","MC","MT","CY","AL","MK","BA","ME","LI","AD","SM","SY","YE"
        };

        private static readonly Dictionary<string, string> Alpha3 = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            {"RUS","RU"},{"NLD","NL"},{"DEU","DE"},{"GER","DE"},{"FRA","FR"},{"ITA","IT"},{"GBR","GB"},
            {"UKR","UA"},{"USA","US"},{"CAN","CA"},{"ESP","ES"},{"PRT","PT"},{"POL","PL"},{"ROU","RO"},
            {"BGR","BG"},{"GRC","GR"},{"TUR","TR"},{"CZE","CZ"},{"SVK","SK"},{"SVN","SI"},{"HRV","HR"},
            {"SRB","RS"},{"HUN","HU"},{"AUT","AT"},{"CHE","CH"},{"BEL","BE"},{"LUX","LU"},{"IRL","IE"},
            {"DNK","DK"},{"SWE","SE"},{"NOR","NO"},{"FIN","FI"},{"ISL","IS"},{"EST","EE"},{"LVA","LV"},
            {"LTU","LT"},{"JPN","JP"},{"KOR","KR"},{"CHN","CN"},{"HKG","HK"},{"TWN","TW"},{"SGP","SG"},
            {"IND","IN"},{"IDN","ID"},{"THA","TH"},{"VNM","VN"},{"MYS","MY"},{"PHL","PH"},{"ARE","AE"},
            {"ISR","IL"},{"SAU","SA"},{"IRN","IR"},{"PAK","PK"},{"BGD","BD"},{"AUS","AU"},{"NZL","NZ"},
            {"BRA","BR"},{"ARG","AR"},{"CHL","CL"},{"MEX","MX"},{"COL","CO"},{"PER","PE"},{"ZAF","ZA"},
            {"EGY","EG"},{"NGA","NG"},{"KEN","KE"},{"MAR","MA"},{"ARM","AM"},{"GEO","GE"},{"AZE","AZ"},
            {"KAZ","KZ"},{"UZB","UZ"},{"BLR","BY"},{"MDA","MD"}
        };

        // Названия стран, по которым чаще всего подписаны узлы. Ключи — в нижнем
        // регистре; список отсортирован по убыванию длины при инициализации,
        // чтобы «южная корея» проверялась раньше, чем «корея».
        private static readonly List<KeyValuePair<string, string>> NamesByLength = BuildNames();

        private static List<KeyValuePair<string, string>> BuildNames()
        {
            var d = new Dictionary<string, string>
            {
                {"нидерланд","NL"},{"голланд","NL"},{"netherland","NL"},{"holland","NL"},{"amsterdam","NL"},
                {"герман","DE"},{"germany","DE"},{"deutschland","DE"},{"frankfurt","DE"},{"франкфурт","DE"},
                {"франц","FR"},{"france","FR"},{"paris","FR"},{"париж","FR"},
                {"росси","RU"},{"russia","RU"},{"москв","RU"},{"moscow","RU"},{"питер","RU"},{"spb","RU"},
                {"великобритан","GB"},{"британ","GB"},{"англи","GB"},{"united kingdom","GB"},{"england","GB"},{"london","GB"},{"лондон","GB"},
                {"соединённые штаты","US"},{"соединенные штаты","US"},{"united states","US"},{"америк","US"},{"america","US"},
                {"канад","CA"},{"canada","CA"},
                {"испан","ES"},{"spain","ES"},{"madrid","ES"},
                {"португал","PT"},{"portugal","PT"},{"lisbon","PT"},
                {"польш","PL"},{"poland","PL"},{"warsaw","PL"},
                {"украин","UA"},{"ukraine","UA"},{"kyiv","UA"},{"kiev","UA"},
                {"беларус","BY"},{"belarus","BY"},
                {"молдов","MD"},{"moldova","MD"},
                {"румын","RO"},{"romania","RO"},{"bucharest","RO"},
                {"болгар","BG"},{"bulgaria","BG"},{"sofia","BG"},
                {"греци","GR"},{"greece","GR"},{"athens","GR"},
                {"турци","TR"},{"turkey","TR"},{"turkiye","TR"},{"istanbul","TR"},{"стамбул","TR"},
                {"чехи","CZ"},{"czech","CZ"},{"prague","CZ"},{"прага","CZ"},
                {"словаки","SK"},{"slovakia","SK"},
                {"словени","SI"},{"slovenia","SI"},
                {"хорват","HR"},{"croatia","HR"},
                {"серби","RS"},{"serbia","RS"},
                {"венгри","HU"},{"hungary","HU"},{"budapest","HU"},
                {"австри","AT"},{"austria","AT"},{"vienna","AT"},{"вена","AT"},
                {"швейцар","CH"},{"switzerland","CH"},{"zurich","CH"},
                {"бельги","BE"},{"belgium","BE"},
                {"люксембург","LU"},{"luxembourg","LU"},
                {"ирланди","IE"},{"ireland","IE"},{"dublin","IE"},
                {"дани","DK"},{"denmark","DK"},{"copenhagen","DK"},
                {"швеци","SE"},{"sweden","SE"},{"stockholm","SE"},
                {"норвег","NO"},{"norway","NO"},{"oslo","NO"},
                {"финлянд","FI"},{"finland","FI"},{"helsinki","FI"},{"хельсинки","FI"},
                {"исланди","IS"},{"iceland","IS"},
                {"эстони","EE"},{"estonia","EE"},{"tallinn","EE"},
                {"латви","LV"},{"latvia","LV"},{"riga","LV"},
                {"литв","LT"},{"lithuania","LT"},{"vilnius","LT"},
                {"япони","JP"},{"japan","JP"},{"tokyo","JP"},{"токио","JP"},
                {"южная коре","KR"},{"south korea","KR"},{"корея","KR"},{"korea","KR"},{"seoul","KR"},
                {"китай","CN"},{"china","CN"},{"shanghai","CN"},{"beijing","CN"},
                {"гонконг","HK"},{"hong kong","HK"},{"hongkong","HK"},
                {"тайван","TW"},{"taiwan","TW"},
                {"сингапур","SG"},{"singapore","SG"},
                {"инди","IN"},{"india","IN"},{"mumbai","IN"},
                {"индонези","ID"},{"indonesia","ID"},
                {"таиланд","TH"},{"thailand","TH"},{"bangkok","TH"},
                {"вьетнам","VN"},{"vietnam","VN"},
                {"малайзи","MY"},{"malaysia","MY"},
                {"филиппин","PH"},{"philippines","PH"},
                {"эмират","AE"},{"emirates","AE"},{"dubai","AE"},{"дубай","AE"},
                {"израил","IL"},{"israel","IL"},
                {"саудов","SA"},{"saudi","SA"},
                {"катар","QA"},{"qatar","QA"},
                {"пакистан","PK"},{"pakistan","PK"},
                {"бангладеш","BD"},{"bangladesh","BD"},
                {"австрали","AU"},{"australia","AU"},{"sydney","AU"},
                {"новая зеланди","NZ"},{"new zealand","NZ"},
                {"бразили","BR"},{"brazil","BR"},{"sao paulo","BR"},
                {"аргентин","AR"},{"argentina","AR"},
                {"чили","CL"},{"chile","CL"},
                {"мексик","MX"},{"mexico","MX"},
                {"колумби","CO"},{"colombia","CO"},
                {"перу","PE"},{"peru","PE"},
                {"юар","ZA"},{"south africa","ZA"},
                {"египет","EG"},{"egypt","EG"},
                {"нигери","NG"},{"nigeria","NG"},
                {"кени","KE"},{"kenya","KE"},
                {"марокк","MA"},{"morocco","MA"},
                {"армени","AM"},{"armenia","AM"},{"yerevan","AM"},
                {"грузи","GE"},{"georgia","GE"},{"tbilisi","GE"},
                {"азербайджан","AZ"},{"azerbaijan","AZ"},{"baku","AZ"},
                {"казахстан","KZ"},{"kazakhstan","KZ"},{"almaty","KZ"},
                {"узбекистан","UZ"},{"uzbekistan","UZ"},
                {"итали","IT"},{"italy","IT"},{"milan","IT"},{"милан","IT"},{"rome","IT"},
                {"монако","MC"},{"monaco","MC"},
                {"иран","IR"},{"iran","IR"}
            };

            var list = new List<KeyValuePair<string, string>>(d);
            list.Sort((a, b) => b.Key.Length.CompareTo(a.Key.Length));
            return list;
        }
    }
}
