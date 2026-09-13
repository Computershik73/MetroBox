using System;
using System.Collections.Generic;

namespace VlessVpnTask
{
    // Конфигурация AmneziaWG: обычный WireGuard .conf плюс поля обфускации Amnezia
    // (Jc/Jmin/Jmax — мусорные пакеты перед хендшейком, S1..S4 — случайный префикс перед
    // каждым типом пакета, H1..H4 — подмена номеров типов пакетов).
    internal sealed class AwgConfig
    {
        public byte[] PrivateKey = new byte[32];
        public byte[] PeerPublicKey = new byte[32];
        public byte[] PresharedKey = new byte[32];
        public bool HasPresharedKey;

        public readonly List<string> Addresses = new List<string>();  // "10.8.0.2/32"
        public readonly List<string> Dns = new List<string>();

        public string EndpointHost = "";
        public ushort EndpointPort;
        public ushort Mtu = 1420;
        public ushort PersistentKeepalive;

        public uint Jc, Jmin, Jmax;

        // S1..S4 — длина случайного префикса: [0]=init, [1]=response, [2]=cookie, [3]=transport.
        public readonly uint[] Padding = new uint[4];

        // H1..H4 — допустимый диапазон номера типа пакета (в оригинале это просто 1..4).
        public readonly uint[] HeaderMin = { 1, 2, 3, 4 };
        public readonly uint[] HeaderMax = { 1, 2, 3, 4 };

        // I1..I5 (AmneziaWG 1.5+) — шаблоны «подписных» датаграмм, которые уходят перед
        // хендшейком, чтобы начало сессии выглядело как чужой протокол (DNS, STUN и т.п.).
        // Синтаксис: <b 0xHEX> — готовые байты, <r N> — N случайных байт,
        // <rd N> — N случайных цифр, <rc N> — N случайных латинских букв, <t> — время (4 байта BE).
        public readonly string[] Signature = { "", "", "", "", "" };

        public string Error { get; private set; }

        private static byte[] TryBase64Key(string s)
        {
            try
            {
                byte[] b = Convert.FromBase64String(s.Trim());
                return b.Length == 32 ? b : null;
            }
            catch { return null; }
        }

        // Разбирает текст .conf. Возвращает null и заполняет reason при ошибке.
        public static AwgConfig Parse(string text, out string reason)
        {
            reason = null;
            var c = new AwgConfig();
            if (string.IsNullOrEmpty(text)) { reason = "пустой конфиг"; return null; }

            string section = "";
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
                if (val.Length == 0) continue;

                if (section == "interface")
                {
                    if (Eq(key, "PrivateKey"))
                    {
                        var k = TryBase64Key(val);
                        if (k == null) { reason = "PrivateKey: ожидается base64 длиной 32 байта"; return null; }
                        c.PrivateKey = k;
                    }
                    else if (Eq(key, "Address")) AddCsv(c.Addresses, val);
                    else if (Eq(key, "DNS")) AddCsv(c.Dns, val);
                    else if (Eq(key, "MTU")) { ushort m; if (ushort.TryParse(val, out m) && m >= 576) c.Mtu = m; }
                    else if (Eq(key, "Jc")) { uint v; if (uint.TryParse(val, out v) && v <= 128) c.Jc = v; }
                    else if (Eq(key, "Jmin")) { uint v; if (uint.TryParse(val, out v)) c.Jmin = v; }
                    else if (Eq(key, "Jmax")) { uint v; if (uint.TryParse(val, out v)) c.Jmax = v; }
                    else if (key.Length == 2 && (key[0] == 'S' || key[0] == 's') && key[1] >= '1' && key[1] <= '4')
                    {
                        uint v; if (uint.TryParse(val, out v)) c.Padding[key[1] - '1'] = v;
                    }
                    else if (key.Length == 2 && (key[0] == 'H' || key[0] == 'h') && key[1] >= '1' && key[1] <= '4')
                    {
                        uint lo, hi;
                        if (!ParseRange(val, out lo, out hi))
                        { reason = $"{key}: ожидается число или диапазон вида 100-200"; return null; }
                        c.HeaderMin[key[1] - '1'] = lo;
                        c.HeaderMax[key[1] - '1'] = hi;
                    }
                    else if (key.Length == 2 && (key[0] == 'I' || key[0] == 'i') && key[1] >= '1' && key[1] <= '5')
                    {
                        if (!SignatureSyntaxOk(val))
                        { reason = $"{key}: непонятный шаблон подписи"; return null; }
                        c.Signature[key[1] - '1'] = val;
                    }
                }
                else if (section == "peer")
                {
                    if (Eq(key, "PublicKey"))
                    {
                        var k = TryBase64Key(val);
                        if (k == null) { reason = "PublicKey: ожидается base64 длиной 32 байта"; return null; }
                        c.PeerPublicKey = k;
                    }
                    else if (Eq(key, "PresharedKey"))
                    {
                        var k = TryBase64Key(val);
                        if (k == null) { reason = "PresharedKey: ожидается base64 длиной 32 байта"; return null; }
                        c.PresharedKey = k; c.HasPresharedKey = true;
                    }
                    else if (Eq(key, "Endpoint"))
                    {
                        int colon = val.LastIndexOf(':');
                        if (colon <= 0) { reason = "Endpoint: ожидается host:port"; return null; }
                        c.EndpointHost = val.Substring(0, colon).Trim().Trim('[', ']');
                        ushort p;
                        if (!ushort.TryParse(val.Substring(colon + 1).Trim(), out p) || p == 0)
                        { reason = "Endpoint: некорректный порт"; return null; }
                        c.EndpointPort = p;
                    }
                    else if (Eq(key, "PersistentKeepalive"))
                    {
                        ushort v; if (ushort.TryParse(val, out v)) c.PersistentKeepalive = v;
                    }
                }
            }

            if (IsAllZero(c.PrivateKey)) { reason = "не задан PrivateKey в [Interface]"; return null; }
            if (IsAllZero(c.PeerPublicKey)) { reason = "не задан PublicKey в [Peer]"; return null; }
            if (string.IsNullOrEmpty(c.EndpointHost) || c.EndpointPort == 0)
            { reason = "не задан Endpoint в [Peer]"; return null; }
            if (c.Jmin > c.Jmax || c.Jmax > 65507)
            { reason = "некорректные Jmin/Jmax"; return null; }
            for (int i = 0; i < 4; i++)
            {
                if (c.HeaderMin[i] > c.HeaderMax[i]) { reason = $"H{i + 1}: min больше max"; return null; }
                if (c.Padding[i] > c.Mtu) { reason = $"S{i + 1} больше MTU"; return null; }
            }
            if (c.Addresses.Count == 0) c.Addresses.Add("10.8.0.2/32");

            return c;
        }

        private static bool Eq(string a, string b) { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }

        // Быстрая проверка формы шаблона I1..I5: цепочка блоков <...> без мусора между ними.
        private static bool SignatureSyntaxOk(string s)
        {
            int i = 0;
            while (i < s.Length)
            {
                if (s[i] != '<') return false;
                int close = s.IndexOf('>', i + 1);
                if (close < 0) return false;
                string body = s.Substring(i + 1, close - i - 1).Trim();
                if (body == "t") { i = close + 1; continue; }
                if (body.StartsWith("b 0x", StringComparison.Ordinal))
                {
                    string hex = body.Substring(4);
                    if (hex.Length == 0 || (hex.Length & 1) != 0) return false;
                    foreach (char ch in hex)
                        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')))
                            return false;
                    i = close + 1; continue;
                }
                string num = null;
                if (body.StartsWith("rd ", StringComparison.Ordinal) || body.StartsWith("rc ", StringComparison.Ordinal))
                    num = body.Substring(3);
                else if (body.StartsWith("r ", StringComparison.Ordinal))
                    num = body.Substring(2);
                if (num == null) return false;
                uint n;
                if (!uint.TryParse(num.Trim(), out n) || n > 65507) return false;
                i = close + 1;
            }
            return true;
        }

        public bool HasSignatures()
        {
            foreach (var s in Signature) if (!string.IsNullOrEmpty(s)) return true;
            return false;
        }

        private static bool IsAllZero(byte[] b)
        {
            if (b == null) return true;
            foreach (var x in b) if (x != 0) return false;
            return true;
        }

        private static void AddCsv(List<string> dst, string val)
        {
            foreach (var part in val.Split(','))
            {
                string s = part.Trim();
                if (s.Length > 0) dst.Add(s);
            }
        }

        private static bool ParseRange(string val, out uint lo, out uint hi)
        {
            lo = hi = 0;
            int dash = val.IndexOf('-');
            if (dash > 0)
            {
                return uint.TryParse(val.Substring(0, dash).Trim(), out lo) &&
                       uint.TryParse(val.Substring(dash + 1).Trim(), out hi) && lo <= hi;
            }
            if (!uint.TryParse(val.Trim(), out lo)) return false;
            hi = lo;
            return true;
        }

        // Первый IPv4-адрес интерфейса без маски — им настраивается TUN.
        public string FirstIpv4Address()
        {
            foreach (var a in Addresses)
            {
                string ip = a.Split('/')[0].Trim();
                if (ip.IndexOf(':') < 0 && ip.Length > 0) return ip;
            }
            return null;
        }
    }
}
