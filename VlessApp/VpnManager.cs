using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Vpn;
using Windows.ApplicationModel;

namespace VlessApp
{
    public class VpnManager
    {
        public const string ProfileName = "MetroBox";

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
            if (!string.IsNullOrEmpty(p.Address) && System.Net.IPAddress.TryParse(p.Address, out var ip))
            {
                s["v_ServerIp"] = ip.ToString();
                s["v_ServerIps"] = ip.ToString();
                s["v_LastServerIp"] = ip.ToString();
                s["v_LastServerIpFor"] = p.Address;
            }
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
            s["v_Fingerprint"] = !string.IsNullOrEmpty(p.Fingerprint) ? p.Fingerprint : "firefox";
            s["v_Mtu"] = p.Mtu > 0 ? p.Mtu : 1400;
            s["v_XhttpMode"] = p.Mode ?? "stream-one";
            // Второе звено цепочки (Amnezia или универсальный Multi-Hop):
            // трафик через первое звено (реле/входной узел) доводится до выходного узла,
            // а тот проверяет свои ключи REALITY / TLS.
            s["v_ChainExitHost"] = p.EffectiveExitHost ?? "";
            s["v_ChainExitPort"] = p.EffectiveExitPort;
            s["v_ChainExitUuid"] = p.EffectiveExitUuid ?? "";
            s["v_ChainExitPublicKey"] = p.EffectiveExitPublicKey ?? "";
            s["v_ChainExitSni"] = p.EffectiveExitSni ?? "";
            s["v_ChainExitShortId"] = p.EffectiveExitShortId ?? "";
            s["v_ChainExitFlow"] = p.EffectiveExitFlow ?? "";
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
            try
            {
                var agent = new VpnManagementAgent();
                var profiles = await agent.GetProfilesAsync();

                AppLog.W($"[VPN MGR] Всего профилей в ОС: {profiles.Count}");

                IVpnProfile candidate = null;

                foreach (var pr in profiles)
                {
                    VpnManagementConnectionStatus status = VpnManagementConnectionStatus.Disconnected;
                    if (pr is VpnPlugInProfile plug)
                    {
                        try { status = plug.ConnectionStatus; } catch { }
                        AppLog.W($"[VPN MGR] Профиль '{pr.ProfileName}', статус: {status}, PFN плагина: '{plug.VpnPluginPackageFamilyName}'");
                    }
                    else
                    {
                        AppLog.W($"[VPN MGR] Профиль '{pr.ProfileName}' (тип {pr.GetType().Name})");
                    }

                    bool nameMatch = string.Equals(pr.ProfileName, ProfileName, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(pr.ProfileName, "VLESS Client", StringComparison.OrdinalIgnoreCase);

                    if (nameMatch)
                    {
                        if (status == VpnManagementConnectionStatus.Connected)
                        {
                            return pr;
                        }
                        candidate = pr;
                    }
                }

                if (candidate != null) return candidate;

                if (profiles.Count > 0) return profiles[0];
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PROFILE] GetProfilesAsync failed: {ex.Message}");
                AppLog.W($"[VPN MGR] GetProfilesAsync failed: {ex.Message}");
            }
            return null;
        }

        // Сохранение учетных данных в хранилище Windows Credential Manager (PasswordVault),
        // чтобы системный диалер RAS и параметры ОС не требовали ввода данных и не выдавали ошибку 691.
        public static void EnsurePasswordVaultCredentials()
        {
            try
            {
                var vault = new Windows.Security.Credentials.PasswordVault();
                try
                {
                    vault.Retrieve(ProfileName, "vpn");
                }
                catch
                {
                    vault.Add(new Windows.Security.Credentials.PasswordCredential(ProfileName, "vpn", "vpn"));
                    AppLog.W("[VPN MGR] Учётные данные (vpn/vpn) сохранены в PasswordVault для обхода RAS 691");
                }
            }
            catch (Exception ex)
            {
                AppLog.W($"[VPN MGR] Предупреждение PasswordVault: {ex.Message}");
            }
        }

        // Удаление битого приватного rasphone.pbk из LocalFolder (созданного некорректным AddProfileFromObjectAsync),
        // чтобы приложение и система использовали единый чистый системный профиль.
        public static void CleanupBrokenPrivatePhonebook()
        {
            try
            {
                var folder = Windows.Storage.ApplicationData.Current.LocalFolder;
                string pbkPath = System.IO.Path.Combine(folder.Path, "rasphone.pbk");
                if (System.IO.File.Exists(pbkPath))
                {
                    System.IO.File.Delete(pbkPath);
                    AppLog.W("[VPN MGR] Удален поврежденный приватный rasphone.pbk из LocalState");
                }
            }
            catch (Exception ex)
            {
                AppLog.W($"[VPN MGR] CleanupBrokenPrivatePhonebook: {ex.Message}");
            }
        }

        public async Task<IVpnProfile> EnsureOwnProfileAsync()
        {
            CleanupBrokenPrivatePhonebook();
            EnsurePasswordVaultCredentials();

            return await FindOwnProfileAsync();
        }
    }
}