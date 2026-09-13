using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.Networking.Vpn;
using Windows.ApplicationModel;

namespace VlessApp
{
    public class VpnManager
    {
        public const string ProfileName = "VLESS Client";

        public async Task ConnectVlessAsync(VlessProfile p)
        {
            WriteSettings(p);

            var mine = await FindOwnProfileAsync();
            if (mine == null)
            {
                AppLog.W("  ОТКАЗ: VPN-профиль «" + ProfileName + "» не найден в системе");
                throw new Exception("VPN-профиль не найден в системе.");
            }

            Debug.WriteLine($"[PROFILE] Использую существующий профиль '{mine.ProfileName}'.");
            try
            {
                var agent = new VpnManagementAgent();
                var dStatus = await agent.DisconnectProfileAsync(mine);
                Debug.WriteLine($"[PROFILE] Pre-connect Disconnect => {dStatus}");
                AppLog.W("  предварительное отключение профиля: " + dStatus);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PROFILE] Disconnect ignored: {ex.Message}");
                AppLog.W("  предварительное отключение не удалось (не помеха): " + ex.Message);
            }

            await Task.Delay(1000);

            try
            {
                var agent = new VpnManagementAgent();
                var st = await agent.ConnectProfileAsync(mine);
                Debug.WriteLine($"[PROFILE] Connect existing => {st}");
                // Ответ системы виден только здесь: без него «ничего не происходит»
                // после нажатия остаётся без объяснения.
                AppLog.W("  система вернула на подключение профиля: " + st);
                if (st != VpnManagementErrorStatus.Ok)
                    throw new Exception($"Ошибка подключения: {st}");
            }
            catch (Exception ex)
            {
                AppLog.W("  ОТКАЗ при запуске профиля: " + ex.Message);
                throw new Exception($"Ошибка запуска профиля: {ex.Message}");
            }
        }

        public async Task DisconnectAsync()
        {
            try
            {
                var agent = new VpnManagementAgent();
                var mine = await FindOwnProfileAsync();
                if (mine != null)
                {
                    await agent.DisconnectProfileAsync(mine);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PROFILE] Disconnect failed: {ex.Message}");
            }
        }

        public async Task<bool> HasProfileAsync()
        {
            return (await FindOwnProfileAsync()) != null;
        }

        public void WriteSettings(VlessProfile p)
        {
            var s = Windows.Storage.ApplicationData.Current.LocalSettings.Values;
            // Имя нужно фоновой задаче только для живой плитки — на подключение не влияет.
            s["v_Name"] = p.Name ?? "";
            s["v_Address"] = p.Address ?? "";
            s["v_Port"] = p.Port;
            s["v_Uuid"] = p.Uuid ?? "";
            s["v_Type"] = p.Type ?? "tcp";
            s["v_Security"] = p.Security ?? "reality";
            s["v_Sni"] = p.Sni ?? "";
            s["v_PublicKey"] = p.PublicKey ?? "";
            s["v_ShortId"] = p.ShortId ?? "";
            s["v_Path"] = p.Path ?? "";
            s["v_Host"] = p.Host ?? "";
            s["v_Flow"] = p.Flow ?? "";
            s["v_Alpn"] = p.Alpn ?? "";
            s["v_XhttpMode"] = p.Mode ?? "stream-one";
            // Второе звено цепочки Amnezia: реле доводит только до этого узла,
            // а он проверяет уже свои ключи REALITY — поэтому нужны все параметры,
            // а не только адрес.
            s["v_ChainExitHost"] = p.AmneziaExitHost ?? "";
            s["v_ChainExitPort"] = p.AmneziaExitPort;
            s["v_ChainExitUuid"] = p.AmneziaExitUuid ?? "";
            s["v_ChainExitPublicKey"] = p.AmneziaExitPublicKey ?? "";
            s["v_ChainExitSni"] = p.AmneziaExitSni ?? "";
            s["v_ChainExitShortId"] = p.AmneziaExitShortId ?? "";
            s["v_ChainExitFlow"] = p.AmneziaExitFlow ?? "";
            s["v_AwgConfig"] = p.IsAmneziaWg ? (p.AwgConfig ?? "") : "";
            // Shadowsocks/Outline: без этих трёх ключей фоновая задача не знает ни шифра,
            // ни пароля — профиль импортировался бы, но соединение не поднималось.
            s["v_SsMethod"] = p.IsShadowsocks ? (p.Method ?? "") : "";
            s["v_SsPassword"] = p.IsShadowsocks ? (p.Password ?? "") : "";
            s["v_SsPrefix"] = p.IsShadowsocks ? (p.SsPrefix ?? "") : "";
            // Адрес TUN-интерфейса, по которому интерфейс понимает, что туннель поднят.
            s["v_TunIp"] = p.IsAmneziaWg ? (AwgAddressOf(p.AwgConfig) ?? "") : "11.16.1.1";
            s["v_DebugLog"] = true;
        }

        // Первый IPv4 из строки Address в [Interface] — им поднимается TUN у AmneziaWG.
        private static string AwgAddressOf(string conf)
        {
            if (string.IsNullOrEmpty(conf)) return null;
            foreach (var rawLine in conf.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
            {
                string line = rawLine.Trim();
                if (!line.StartsWith("Address", StringComparison.OrdinalIgnoreCase)) continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                foreach (var part in line.Substring(eq + 1).Split(','))
                {
                    string ip = part.Split('/')[0].Trim();
                    if (ip.Length > 0 && ip.IndexOf(':') < 0) return ip;
                }
            }
            return null;
        }

        public async Task<IVpnProfile> FindOwnProfileAsync()
        {
            string fam = Package.Current.Id.FamilyName;
            try
            {
                var agent = new VpnManagementAgent();
                var profiles = await agent.GetProfilesAsync();

               /* Debug.WriteLine("=== [DIAGNOSTIC] НАЧАЛО СПИСКА VPN-ПРОФИЛЕЙ СИСТЕМЫ ===");
                Debug.WriteLine($"Текущий PFN приложения (Семейство пакета): '{fam}'");
                Debug.WriteLine($"Всего профилей найдено в ОС: {profiles.Count}");

                foreach (var pr in profiles)
                {
                    Debug.WriteLine($"[PROFILE] Имя профиля: '{pr.ProfileName}'");
                    if (pr is VpnPlugInProfile plug)
                    {
                        //Debug.WriteLine($"  Тип профиля: VpnPlugInProfile (Кастомный плагин)");
                        Debug.WriteLine($"  PFN плагина в профиле: '{plug.VpnPluginPackageFamilyName}'");
                        Debug.WriteLine($"  Совпадение PFN с приложением: {string.Equals(plug.VpnPluginPackageFamilyName, fam, StringComparison.OrdinalIgnoreCase)}");
                    }
                    else
                    {
                        Debug.WriteLine($"  Тип профиля: {pr.GetType().Name} (Встроенный L2TP/IKEv2/PPTP)");
                    }
                }
                Debug.WriteLine("=== [DIAGNOSTIC] КОНЕЦ СПИСКА VPN-ПРОФИЛЕЙ СИСТЕМЫ ===");*/

                foreach (var pr in profiles)
                {
                    if (pr is VpnPlugInProfile plug)
                    {
                        // СИСТЕМНЫЙ ФИКС: Если PFN пустой (баг ручного создания профиля в Windows 10 Mobile) 
                        // или совпадает с нашим текущим PFN — это гарантированно наш рабочий профиль!
                        if (string.IsNullOrEmpty(plug.VpnPluginPackageFamilyName) ||
                            string.Equals(plug.VpnPluginPackageFamilyName, fam, StringComparison.OrdinalIgnoreCase))
                        {
                            return pr;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PROFILE] GetProfilesAsync failed: {ex.Message}");
            }
            return null;
        }
    }
}