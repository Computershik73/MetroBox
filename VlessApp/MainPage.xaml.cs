using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI;
using Windows.Networking.Vpn;
using Windows.Networking;

namespace VlessApp
{
    public class ProfileGroup : ObservableCollection<VlessProfile>
    {
        public string Key { get; set; }

        private bool _isExpanded = true;
        public bool IsExpanded
        {
            get => _isExpanded;
            set
            {
                if (_isExpanded != value)
                {
                    _isExpanded = value;
                    OnPropertyChanged(new PropertyChangedEventArgs(nameof(IsExpanded)));
                    OnPropertyChanged(new PropertyChangedEventArgs(nameof(ArrowIcon)));
                    ToggleItems();
                }
            }
        }

        public string ArrowIcon => IsExpanded ? "\uE70D" : "\uE76C";

        // \u0427\u0442\u043E \u043F\u043E\u043A\u0430\u0437\u044B\u0432\u0430\u0442\u044C \u0432 \u0448\u0430\u043F\u043A\u0435. \u041A\u043B\u044E\u0447\u043E\u043C \u0433\u0440\u0443\u043F\u043F\u044B \u0441\u043B\u0443\u0436\u0438\u0442 \u0441\u0441\u044B\u043B\u043A\u0430 \u043F\u043E\u0434\u043F\u0438\u0441\u043A\u0438, \u0438 \u0434\u043E
        // \u044D\u0442\u043E\u0433\u043E \u043E\u043D\u0430 \u043F\u043E\u043F\u0430\u0434\u0430\u043B\u0430 \u0432 \u0437\u0430\u0433\u043E\u043B\u043E\u0432\u043E\u043A \u043A\u0430\u043A \u0435\u0441\u0442\u044C \u2014 \u0443 \u0441\u0441\u044B\u043B\u043E\u043A Amnezia \u0432 \u043D\u0451\u043C
        // \u043E\u0441\u0442\u0430\u0432\u0430\u043B\u043E\u0441\u044C \u00ABvpn:/\u00BB, \u0443 \u043E\u0431\u044B\u0447\u043D\u044B\u0445 \u043F\u043E\u0434\u043F\u0438\u0441\u043E\u043A \u2014 \u0432\u0435\u0441\u044C URL.
        public string Title
        {
            get
            {
                if (_allItems.Count > 0 && !string.IsNullOrWhiteSpace(_allItems[0].GroupTitle))
                    return _allItems[0].GroupTitle;
                return FriendlyName(Key);
            }
        }

        public static string FriendlyName(string key)
        {
            if (string.IsNullOrWhiteSpace(key)) return "\u0411\u0435\u0437 \u0433\u0440\u0443\u043F\u043F\u044B";

            if (key.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase))
                return "\u041F\u043E\u0434\u043F\u0438\u0441\u043A\u0430 Amnezia";

            if (key.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                key.StartsWith("ssconf://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string forUri = key.StartsWith("ssconf://", StringComparison.OrdinalIgnoreCase)
                        ? "https://" + key.Substring("ssconf://".Length)
                        : key;
                    string host = new Uri(forUri).Host;
                    if (!string.IsNullOrEmpty(host)) return host;
                }
                catch { }
            }
            return key;
        }

        public string LastUpdatedText
        {
            get
            {
                if (_allItems.Count == 0) return "Импортировано: не обновлялось";
                string when = _allItems[0].LastUpdated.ToString("dd.MM.yyyy HH:mm");
                if (MainPage.IsAutoRefreshableGroup(Key)) return when + " | Автообновление - 1 ч.";
                if (MainPage.IsRefreshableGroup(Key)) return when + " | Только вручную";
                return when;
            }
        }

        public bool IsAmnezia => !string.IsNullOrEmpty(Key) &&
                                Key.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase);

        public Visibility CountryPickerVisibility => IsAmnezia ? Visibility.Visible : Visibility.Collapsed;

        // Счётчик устройств и срок подписки — приходят от шлюза вместе с конфигом.
        public string AmneziaInfo => _allItems.Count > 0 ? _allItems[0].AmneziaInfo : "";

        public Visibility AmneziaInfoVisibility => !string.IsNullOrEmpty(AmneziaInfo)
            ? Visibility.Visible : Visibility.Collapsed;

        public string Description => _allItems.Count > 0 ? _allItems[0].Description : "";
        public string InfoUrl => _allItems.Count > 0 ? _allItems[0].InfoUrl : "";
        public string TelegramUrl => _allItems.Count > 0 ? _allItems[0].TelegramUrl : "";

        public Visibility InfoButtonsVisibility => (!string.IsNullOrEmpty(InfoUrl) || !string.IsNullOrEmpty(TelegramUrl))
            ? Visibility.Visible : Visibility.Collapsed;

        public Visibility DescriptionVisibility => !string.IsNullOrEmpty(Description)
            ? Visibility.Visible : Visibility.Collapsed;

        private List<VlessProfile> _allItems = new List<VlessProfile>();

        public void SetAllItems(IEnumerable<VlessProfile> items)
        {
            _allItems = items.ToList();
            ToggleItems();
        }

        private void ToggleItems()
        {
            this.Clear();
            if (IsExpanded)
            {
                foreach (var item in _allItems)
                {
                    this.Add(item);
                }
            }
        }
    }

    public sealed partial class MainPage : Page
    {
        public static bool IsRedirectingToSettings = false;

        // Одна кисть на все акцентные элементы вместо шести одинаковых.
        private static readonly Brush AccentBrush = new SolidColorBrush(Color.FromArgb(255, 56, 189, 248));

        private VpnManager _vpnManager = new VpnManager();
        private List<VlessProfile> _allProfiles = new List<VlessProfile>();
        private ObservableCollection<ProfileGroup> _groupedProfiles = new ObservableCollection<ProfileGroup>();
        private Dictionary<string, bool> _groupExpansionStates = new Dictionary<string, bool>();

        private DispatcherTimer _timer;
        private DispatcherTimer _statusTimer;
        private DispatcherTimer _autoUpdateTimer;
        private TimeSpan _activeTime;
        private bool _isConnected = false;
        private bool _isCheckingStatus = false;
        private VlessProfile _selectedProfile = null;
        private IVpnProfile _cachedProfile = null;

        public MainPage()
        {
            this.InitializeComponent();

            IsRedirectingToSettings = false;
            GroupedProfilesCVS.Source = _groupedProfiles;

            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _timer.Tick += Timer_Tick;

            _statusTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _statusTimer.Tick += StatusTimer_Tick;
            _statusTimer.Start();

            _autoUpdateTimer = new DispatcherTimer { Interval = TimeSpan.FromMinutes(5) };
            _autoUpdateTimer.Tick += AutoUpdateTimer_Tick;
            _autoUpdateTimer.Start();

            Application.Current.Resuming += Current_Resuming;

            Loaded += MainPage_Loaded;
        }

        private async void AutoUpdateTimer_Tick(object sender, object e)
        {
            await CheckAndAutoUpdateSubscriptionsAsync();
        }

        private void Current_Resuming(object sender, object e)
        {
            System.Diagnostics.Debug.WriteLine("[RESUME] Приложение восстановлено.");
            _cachedProfile = null;
            _isCheckingStatus = false;
            IsRedirectingToSettings = false;
        }

        private async Task<IVpnProfile> GetProfileAsync()
        {
            if (_cachedProfile == null)
            {
                _cachedProfile = await _vpnManager.FindOwnProfileAsync();
            }
            return _cachedProfile;
        }

        private async void MainPage_Loaded(object sender, RoutedEventArgs e)
        {
            await LoadProfilesAsync();
            await CheckAndAutoUpdateSubscriptionsAsync();
        }

        private void Timer_Tick(object sender, object e)
        {
            _activeTime = _activeTime.Add(TimeSpan.FromSeconds(1));
            TimeText.Text = _activeTime.ToString(@"hh\:mm\:ss");
        }

        private async void StatusTimer_Tick(object sender, object e)
        {
            if (_isCheckingStatus) return;
            _isCheckingStatus = true;
            try
            {
                await CheckVpnStatusAsync();
            }
            finally
            {
                _isCheckingStatus = false;
            }
        }

        private static bool IsVpnProfileConnectedByIana()
        {
            try
            {
                var connections = Windows.Networking.Connectivity.NetworkInformation.GetConnectionProfiles();
                foreach (var conn in connections)
                {
                    if (conn.NetworkAdapter != null)
                    {
                        uint type = conn.NetworkAdapter.IanaInterfaceType;
                        if (type == 131 || type == 150)
                        {
                            var level = conn.GetNetworkConnectivityLevel();
                            if (level == Windows.Networking.Connectivity.NetworkConnectivityLevel.InternetAccess ||
                                level == Windows.Networking.Connectivity.NetworkConnectivityLevel.ConstrainedInternetAccess)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private static bool IsVpnInterfaceActive()
        {
            try
            {
                // У VLESS адрес туннеля всегда 11.16.1.1, а у AmneziaWG он свой из конфига
                // (например 10.8.1.47), поэтому нужный адрес плагин кладёт в v_TunIp.
                string tunIp = Windows.Storage.ApplicationData.Current.LocalSettings.Values["v_TunIp"] as string;
                if (string.IsNullOrEmpty(tunIp)) tunIp = "11.16.1.1";

                var hostNames = Windows.Networking.Connectivity.NetworkInformation.GetHostNames();
                foreach (var hn in hostNames)
                {
                    if (hn.Type == HostNameType.Ipv4)
                    {
                        if (hn.RawName == tunIp || hn.RawName == "11.16.1.1")
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        // Состояние туннеля глазами системы. Порядок доверия важен: сначала спрашиваем
        // сам профиль, и только если он не отвечает — смотрим на след, оставленный
        // плагином. Раньше исключение при опросе считалось подтверждением подключения,
        // и приложение застревало в состоянии «подключён» после отключения VPN из
        // настроек системы: адрес туннеля у машины ещё оставался, профиль уже не
        // отвечал, а приложение делало из этого вывод «работает».
        private static VpnManagementConnectionStatus ReadVpnState(VpnPlugInProfile plug)
        {
            bool traceOfTunnel;
            try { traceOfTunnel = IsVpnInterfaceActive() || IsVpnProfileConnectedByIana(); }
            catch { traceOfTunnel = false; }

            if (!traceOfTunnel) return VpnManagementConnectionStatus.Disconnected;

            try { return plug.ConnectionStatus; }
            catch { }

            bool pluginSaysUp = false;
            try
            {
                pluginSaysUp = (Windows.Storage.ApplicationData.Current.LocalSettings.Values["v_TunnelUp"] as bool?) ?? false;
            }
            catch { }

            return pluginSaysUp
                ? VpnManagementConnectionStatus.Connected
                : VpnManagementConnectionStatus.Disconnected;
        }

        private async Task CheckVpnStatusAsync()
        {
            try
            {
                var mine = await GetProfileAsync();
                if (mine != null && mine is VpnPlugInProfile plug)
                {
                    // Всё это — синхронные вызовы системы, и каждый из них умеет задуматься
                    // на секунды, пока служба VPN занята разрывом. На потоке интерфейса это
                    // выглядело как намертво зависшее приложение, поэтому спрашиваем в фоне
                    // и со сроком: не ответили — оставляем прежнее состояние до следующего
                    // тика, окно при этом живое.
                    var ask = Task.Run(() => ReadVpnState(plug));
                    if (await Task.WhenAny(ask, Task.Delay(3000)) != ask) return;

                    VpnManagementConnectionStatus status = ask.Result;

                    RefreshTransportWarning(status == VpnManagementConnectionStatus.Connected);

                    if (status == VpnManagementConnectionStatus.Connected)
                    {
                        if (!_isConnected)
                        {
                            _isConnected = true;
                            _activeTime = TimeSpan.Zero;
                            _timer.Start();

                            GlowRing1.BorderBrush = AccentBrush;
                            GlowRing2.BorderBrush = AccentBrush;
                            GlowRing1.Opacity = 0.15;
                            GlowRing2.Opacity = 0.35;
                            PowerIcon.Foreground = AccentBrush;

                            TimeText.Visibility = Visibility.Visible;
                            TimeText.Foreground = AccentBrush;

                            ConnectBtnText.Text = "ПОДКЛЮЧЕН";
                            ConnectBtnText.Foreground = AccentBrush;
                            ConnectBtn.BorderBrush = AccentBrush;
                            ConnectBtn.Background = this.Resources["ButtonGlowConnected"] as Brush;

                            string connName = _selectedProfile != null ? _selectedProfile.Name : mine.ProfileName;
                            StatusText.Text = $"Подключен (глобально): {connName}";
                            CheckConnectionText.Text = "Проверить текущее подключение";

                            UpdateLiveTileConnected(connName);
                        }
                    }
                    else if (status == VpnManagementConnectionStatus.Connecting)
                    {
                        StatusText.Text = "Подключение в системе...";
                    }
                    else if (status == VpnManagementConnectionStatus.Disconnecting)
                    {
                        StatusText.Text = "Отключение в системе...";
                    }
                    else // Disconnected
                    {
                        // Плитку снимаем и здесь, а не только в Disconnect() плагина:
                        // если процесс туннеля умер аварийно, его Disconnect не отработал
                        // и плитка осталась бы висеть «подключено».
                        VlessVpnTask.LiveTile.ShowDisconnected();

                        if (_isConnected)
                        {
                            HardResetMainPage();
                        }
                    }
                }
                else
                {
                    VlessVpnTask.LiveTile.ShowDisconnected();
                    RefreshTransportWarning(false);

                    // Если профиль не найден в ОС и мы были подключены — сбрасываем кэш и перезапускаемся.
                    // В штатном отключенном состоянии не сбрасываем кэш каждую секунду, чтобы не вызывать повторный поиск.
                    if (_isConnected)
                    {
                        _cachedProfile = null;
                        HardResetMainPage();
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[STATUS CHECK FAIL] {ex.Message}");
            }
        }

        // Туннель может стоять поднятым, а сервер при этом отвергать каждое соединение:
        // в логе это выглядит как поток «HTTP/1.1 429» на апгрейд WS, а в интерфейсе — как
        // рабочий VPN, через который ничего не грузится. Плагин живёт в отдельном процессе
        // фоновой задачи, поэтому причину он кладёт в LocalSettings пакета, а мы её здесь
        // забираем. Ключ снимается при успешном хендшейке и в начале Connect(), так что
        // видимая надпись всегда относится к текущей сессии.
        private void RefreshTransportWarning(bool connected)
        {
            try
            {
                if (!connected)
                {
                    if (TransportWarnText.Visibility != Visibility.Collapsed)
                        TransportWarnText.Visibility = Visibility.Collapsed;
                    return;
                }

                string why = VlessVpnTask.NetDiag.ReadLastError();

                if (string.IsNullOrEmpty(why))
                {
                    if (TransportWarnText.Visibility != Visibility.Collapsed)
                        TransportWarnText.Visibility = Visibility.Collapsed;
                    return;
                }

                string text = "Внимание: " + why;
                if (TransportWarnText.Text != text) TransportWarnText.Text = text;
                if (TransportWarnText.Visibility != Visibility.Visible)
                    TransportWarnText.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[TRANSPORT WARN] {ex.Message}");
            }
        }

        // Дублирует то, что делает плагин: если он по какой-то причине не смог обновить
        // плитку, приложение поправит её, как только само увидит поднятый туннель.
        private void UpdateLiveTileConnected(string connName)
        {
            try
            {
                var p = _selectedProfile;
                string details = "";
                if (p != null)
                {
                    string proto = p.IsShadowsocks ? "shadowsocks"
                                 : p.IsAmneziaWg ? "amneziawg"
                                 : "vless";
                    details = string.IsNullOrEmpty(p.Address) ? proto : $"{proto} · {p.Address}";
                }
                VlessVpnTask.LiveTile.ShowConnected(connName, details);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[TILE] {ex.Message}");
            }
        }

        private void HardResetMainPage()
        {
            System.Diagnostics.Debug.WriteLine("[HARD RESET] Полное закрытие для очистки ресурсов...");
            _timer?.Stop();
            _statusTimer?.Stop();

            try
            {
                Application.Current.Resuming -= Current_Resuming;
            }
            catch { }

            Application.Current.Exit();
        }

        private async void ConnectBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_isConnected)
            {
                // Кнопку приходилось жать помногу раз: приложение просило систему
                // отключиться и, не дожидаясь ответа, закрывалось. Если система просьбу не
                // выполнила, при следующем запуске всё выглядело по-прежнему подключённым,
                // и нажатие как будто не срабатывало. Теперь ждём, пока туннель отпустит,
                // и говорим вслух, если он не отпустил.
                ConnectBtn.IsEnabled = false;
                StatusText.Text = "Отключение...";
                AppLog.Section("ОТКЛЮЧЕНИЕ");
                try
                {
                    await ForceDisconnectActiveProfileAsync();

                    var mine = await GetProfileAsync() as VpnPlugInProfile;
                    bool released = mine == null;
                    for (int i = 0; !released && i < 16; i++)
                    {
                        await Task.Delay(500);
                        var ask = Task.Run(() => ReadVpnState(mine));
                        if (await Task.WhenAny(ask, Task.Delay(2000)) != ask) continue;
                        released = ask.Result != VpnManagementConnectionStatus.Connected;
                        StatusText.Text = $"Отключение... ({(i + 1) / 2 + 1} с)";
                    }

                    if (released)
                    {
                        AppLog.W("  туннель отпущен, закрываю приложение");
                        HardResetMainPage();
                        return;
                    }

                    AppLog.W("  система за 8 секунд туннель не отпустила");
                    StatusText.Text = "Система не отпускает туннель. Отключите VPN в настройках системы.";
                }
                finally
                {
                    ConnectBtn.IsEnabled = true;
                }
            }
            else
            {
                if (_selectedProfile == null)
                {
                    StatusText.Text = "Выберите профиль!";
                    return;
                }

                AppLog.Section("ПОДКЛЮЧЕНИЕ: " + (_selectedProfile.Name ?? "?"));
                AppLog.W("  " + VlessProfile.Describe(_selectedProfile));

                string badSecurity = VlessProfile.WhySecurityWontWork(_selectedProfile);
                if (badSecurity != null) AppLog.W("  ВНИМАНИЕ: " + badSecurity);

                // XTLS-Vision (flow=xtls-rprx-vision) и WebSocket теперь реализованы
                // (Vision.cs + WsTransport.cs), поэтому прежние блокирующие диалоги убраны.

                // Транспорт, для которого у нас нет кода, раньше молча уезжал в ветку
                // raw TCP и не поднимался: пользователь видел «сервер не отвечает»
                // вместо «этого транспорта тут нет». gRPC ниже — частный случай с
                // собственным текстом, он проверяется первым.
                string badTransport = VlessProfile.WhyUnsupportedTransport(_selectedProfile);
                if (badTransport != null &&
                    !string.Equals(_selectedProfile.Type, "grpc", StringComparison.OrdinalIgnoreCase))
                {
                    AppLog.W("  ОТКАЗ: " + badTransport);
                    var trDialog = new ContentDialog
                    {
                        Title = "Транспорт не поддерживается",
                        Content = $"Профиль «{_selectedProfile.Name}»: {badTransport}.\n\n" +
                                  "Поддерживаются: TCP (в том числе XTLS-Vision), WebSocket и XHTTP/SplitHTTP.",
                        CloseButtonText = "ОК"
                    };
                    await trDialog.ShowAsync();
                    StatusText.Text = "Подключение отменено (транспорт не поддерживается).";
                    return;
                }

                // Блокировка gRPC транспорта
                if (string.Equals(_selectedProfile.Type, "grpc", StringComparison.OrdinalIgnoreCase))
                {
                    var grpcDialog = new ContentDialog
                    {
                        Title = "Транспорт не поддерживается",
                        Content = "Транспорт gRPC пока не поддерживается данным приложением.\n\n" +
                                  "Пожалуйста, выберите профиль с другим типом транспорта (например, TCP или XHTTP).",
                        CloseButtonText = "ОК"
                    };

                    await grpcDialog.ShowAsync();
                    AppLog.W("  ОТКАЗ: транспорт gRPC не реализован");
                    StatusText.Text = "Подключение отменено (gRPC не поддерживается).";
                    return;
                }

                // Shadowsocks: сразу отсекаем шифры, которых у нас нет (2022-blake3-*,
                // старые потоковые). Иначе профиль молча не подключался бы.
                if (_selectedProfile.IsShadowsocks &&
                    !VlessProfile.IsSupportedSsMethod(_selectedProfile.Method))
                {
                    var ssDialog = new ContentDialog
                    {
                        Title = "Шифр не поддерживается",
                        Content = $"Shadowsocks-шифр «{_selectedProfile.Method}» не реализован.\n\n" +
                                  "Поддерживаются: chacha20-ietf-poly1305, aes-128-gcm, aes-192-gcm, aes-256-gcm.",
                        CloseButtonText = "ОК"
                    };

                    AppLog.W("  ОТКАЗ: шифр Shadowsocks «" + (_selectedProfile.Method ?? "?") + "» не реализован");
                    await ssDialog.ShowAsync();
                    StatusText.Text = "Подключение отменено (шифр Shadowsocks не поддерживается).";
                    return;
                }

                if (string.Equals(_selectedProfile.Type, "xhttp", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(_selectedProfile.Type, "splithttp", StringComparison.OrdinalIgnoreCase))
                {
                    var xhttpDialog = new ContentDialog
                    {
                        Title = "Ограниченная поддержка",
                        Content = "Транспорт XHTTP реализован лишь частично и работает не со всеми серверами. " +
                                  "Совместимость зависит от конфигурации сервера (режим и версия Reality). " +
                                  "Если подключение не установится — используйте профиль с другим транспортом.",
                        PrimaryButtonText = "Всё равно подключиться",
                        CloseButtonText = "Отмена"
                    };

                    var choice = await xhttpDialog.ShowAsync();
                    if (choice != ContentDialogResult.Primary)
                    {
                        StatusText.Text = "Подключение отменено.";
                        return;
                    }
                }

                var mine = await _vpnManager.FindOwnProfileAsync();
                if (mine == null)
                {
                    await ShowNoProfileDialogAsync();
                    return;
                }

                IsRedirectingToSettings = true;
                AppLog.W("  настройки записаны, туннель поднимает фоновая задача (дальше — vpnlog.txt)");
                _vpnManager.WriteSettings(_selectedProfile);

                await ForceDisconnectActiveProfileAsync();
                await Task.Delay(700);

                StatusText.Text = "Настройки применены...";
                await Windows.System.Launcher.LaunchUriAsync(new Uri("ms-settings:network-vpn"));
            }
        }

        public async Task<bool> ForceDisconnectActiveProfileAsync()
        {
            try
            {
                var agent = new Windows.Networking.Vpn.VpnManagementAgent();
                var profiles = await agent.GetProfilesAsync();

                if (profiles.Count == 0)
                {
                    System.Diagnostics.Debug.WriteLine("[VPN MGR] Профилей нет — отключать нечего.");
                    return false;
                }

                bool any = false;
                foreach (var p in profiles)
                {
                    try
                    {
                        var status = await agent.DisconnectProfileAsync(p);

                        // Ответ системы раньше уходил в отладочный вывод, которого на
                        // телефоне нет. Без него «кнопка не работает» было нечем объяснить.
                        AppLog.W($"  отключение профиля '{p.ProfileName}': {status}");
                        any = true;
                    }
                    catch (Exception ex)
                    {
                        AppLog.W($"  отключить профиль '{p.ProfileName}' не вышло: {ex.Message}");
                    }
                }
                return any;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[VPN MGR ERROR] {ex.Message}");
                return false;
            }
        }

        private async Task ShowNoProfileDialogAsync()
        {
            ContentDialog dialog = new ContentDialog
            {
                Title = "VPN-профиль не обнаружен",
                Content = "Добавьте профиль вручную в параметрах.",
                PrimaryButtonText = "Открыть настройки",
                CloseButtonText = "Закрыть"
            };

            var result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary)
            {
                await Windows.System.Launcher.LaunchUriAsync(new Uri("ms-settings:network-vpn"));
            }
        }

        // =========================================================================
        // ЛОГИКА ДОБАВЛЕНИЯ ПРОФИЛЕЙ (Из буфера обмена / Офлайн-распознавание QR)
        // =========================================================================

        private async void ImportFromClipboard_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dataPackageView = Clipboard.GetContent();
                if (dataPackageView.Contains(StandardDataFormats.Text))
                {
                    string text = await dataPackageView.GetTextAsync();
                    await ProcessAndAddImportTextAsync(text);
                }
                else
                {
                    StatusText.Text = "Буфер обмена пуст";
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Ошибка импорта: " + ex.Message;
            }
        }

        private async void ScanQrCode_Click(object sender, RoutedEventArgs e)
        {
            var selectSourceDialog = new ContentDialog
            {
                Title = "Сканирование QR-кода",
                Content = "Выберите источник изображения с QR-кодом:",
                PrimaryButtonText = "Камера",
                SecondaryButtonText = "Галерея",
                CloseButtonText = "Отмена"
            };

            var choice = await selectSourceDialog.ShowAsync();
            Windows.Storage.StorageFile file = null;

            try
            {
                if (choice == ContentDialogResult.Primary)
                {
                    var captureUI = new Windows.Media.Capture.CameraCaptureUI();
                    captureUI.PhotoSettings.Format = Windows.Media.Capture.CameraCaptureUIPhotoFormat.Jpeg;
                    file = await captureUI.CaptureFileAsync(Windows.Media.Capture.CameraCaptureUIMode.Photo);
                }
                else if (choice == ContentDialogResult.Secondary)
                {
                    var picker = new Windows.Storage.Pickers.FileOpenPicker();
                    picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.PicturesLibrary;
                    picker.ViewMode = Windows.Storage.Pickers.PickerViewMode.Thumbnail;
                    picker.FileTypeFilter.Add(".jpg");
                    picker.FileTypeFilter.Add(".jpeg");
                    picker.FileTypeFilter.Add(".png");
                    picker.FileTypeFilter.Add(".bmp");

                    file = await picker.PickSingleFileAsync();
                }

                if (file == null)
                {
                    StatusText.Text = "Сканирование отменено";
                    return;
                }

                StatusText.Text = "Обработка и распознавание (многопроходный анализ)...";
                string qrResult = null;

                using (var stream = await file.OpenAsync(Windows.Storage.FileAccessMode.Read))
                {
                    qrResult = await DecodeQrCodeFromStreamAsync(stream);
                }

                if (!string.IsNullOrEmpty(qrResult))
                {
                    StatusText.Text = "Код успешно распознан!";
                    await ProcessAndAddImportTextAsync(qrResult);
                }
                else
                {
                    StatusText.Text = "Не удалось распознать QR-код.";
                    var failDialog = new ContentDialog
                    {
                        Title = "Ошибка распознавания",
                        Content = "Локальный декодер не смог распознать QR-код даже после многопроходного анализа.\n\n" +
                                  "Убедитесь, что QR-код находится в фокусе, полностью попадает в кадр и не перекрыт бликами от освещения.",
                        CloseButtonText = "ОК"
                    };
                    await failDialog.ShowAsync();
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Ошибка сканирования: " + ex.Message;
            }
        }

        // Многопроходное декодирование потока изображения в разных разрешениях
        // Снимок с камеры телефона — это шестнадцать мегапикселей, и ZXing прогоняет
        // по ним два бинаризатора. Раньше счёт шёл прямо в потоке интерфейса, да ещё
        // начиная с полного разрешения: приложение замирало намертво, и со стороны это
        // выглядело как зависание. Теперь счёт уходит в фоновый поток, а проходы идут
        // от мелких размеров к крупным — код обычно читается уже на первом из них.
        private async Task<string> DecodeQrCodeFromStreamAsync(Windows.Storage.Streams.IRandomAccessStream stream)
        {
            try
            {
                var decoder = await Windows.Graphics.Imaging.BitmapDecoder.CreateAsync(stream);
                uint origWidth = decoder.PixelWidth;
                uint origHeight = decoder.PixelHeight;
                AppLog.W($"[QR] Снимок {origWidth}×{origHeight}, начинаю разбор.");

                foreach (uint targetSize in new uint[] { 600, 900, 1400, 0 })
                {
                    var transform = new Windows.Graphics.Imaging.BitmapTransform();

                    // 0 — последний проход, по оригиналу: он самый дорогой, и нужен только
                    // там, где мелкий код на крупном кадре после сжатия рассыпается.
                    if (targetSize != 0)
                    {
                        if (origWidth <= targetSize && origHeight <= targetSize) continue;

                        float ratio = (float)origWidth / origHeight;
                        if (origWidth > origHeight)
                        {
                            transform.ScaledWidth = targetSize;
                            transform.ScaledHeight = (uint)(targetSize / ratio);
                        }
                        else
                        {
                            transform.ScaledHeight = targetSize;
                            transform.ScaledWidth = (uint)(targetSize * ratio);
                        }
                        transform.InterpolationMode = Windows.Graphics.Imaging.BitmapInterpolationMode.Linear;
                    }

                    StatusText.Text = targetSize != 0
                        ? $"Распознавание ({targetSize} точек)..."
                        : "Распознавание (полный размер)...";

                    using (var bmp = await decoder.GetSoftwareBitmapAsync(
                        Windows.Graphics.Imaging.BitmapPixelFormat.Bgra8,
                        Windows.Graphics.Imaging.BitmapAlphaMode.Premultiplied,
                        transform,
                        Windows.Graphics.Imaging.ExifOrientationMode.RespectExifOrientation,
                        Windows.Graphics.Imaging.ColorManagementMode.ColorManageToSRgb))
                    {
                        // Именно этот счёт и держал интерфейс. Ожидание здесь возвращает
                        // управление окну: полоса состояния обновляется, кнопки живые.
                        string res = await Task.Run(() => DecodeWithBinarizers(bmp));
                        if (!string.IsNullOrEmpty(res))
                        {
                            AppLog.W($"[QR] Код прочитан на проходе {(targetSize != 0 ? targetSize.ToString() : "оригинал")}, длина {res.Length}.");
                            return res;
                        }
                    }
                }

                AppLog.W("[QR] Код не прочитан ни на одном проходе.");
            }
            catch (Exception ex)
            {
                AppLog.W("[QR] Ошибка разбора снимка: " + ex.Message);
            }
            return null;
        }

        // Попытка декодирования конкретного кадра двумя разными математическими бинаризаторами
        private string DecodeWithBinarizers(Windows.Graphics.Imaging.SoftwareBitmap bmp)
        {
            try
            {
                // Метод 1: HybridBinarizer (по умолчанию). Отлично справляется с тенями и градиентами освещения.
                var readerHybrid = new ZXing.BarcodeReader();
                readerHybrid.Options = new ZXing.Common.DecodingOptions
                {
                    TryHarder = true,
                    TryInverted = true,
                    PossibleFormats = new List<ZXing.BarcodeFormat> { ZXing.BarcodeFormat.QR_CODE }
                };
                var src = new ZXing.SoftwareBitmapLuminanceSource(bmp);
                var result = readerHybrid.Decode(src);
                if (result != null && !string.IsNullOrEmpty(result.Text)) return result.Text;

                // Метод 2: GlobalHistogramBinarizer. Отлично восстанавливает смазанные/расфокусированные границы.
                var readerGlobal = new ZXing.BarcodeReader(
                    null,
                    (b) => new ZXing.SoftwareBitmapLuminanceSource(b),
                    (luminanceSource) => new ZXing.Common.GlobalHistogramBinarizer(luminanceSource)
                );
                readerGlobal.Options = new ZXing.Common.DecodingOptions
                {
                    TryHarder = true,
                    TryInverted = true,
                    PossibleFormats = new List<ZXing.BarcodeFormat> { ZXing.BarcodeFormat.QR_CODE }
                };
                result = readerGlobal.Decode(bmp);
                if (result != null && !string.IsNullOrEmpty(result.Text)) return result.Text;
            }
            catch { }
            return null;
        }

        // Локальное офлайн-декодирование с использованием библиотеки ZXing.Net
        private string DecodeQrCodeOffline(Windows.Graphics.Imaging.SoftwareBitmap softwareBitmap)
        {
            try
            {
                // Конвертируем SoftwareBitmap в Bgra8 для стабильного попиксельного анализа библиотекой ZXing
                var convertedBmp = Windows.Graphics.Imaging.SoftwareBitmap.Convert(
                    softwareBitmap,
                    Windows.Graphics.Imaging.BitmapPixelFormat.Bgra8,
                    Windows.Graphics.Imaging.BitmapAlphaMode.Premultiplied);

                var luminanceSource = new ZXing.SoftwareBitmapLuminanceSource(convertedBmp);
                var reader = new ZXing.BarcodeReader();

                reader.Options = new ZXing.Common.DecodingOptions
                {
                    TryHarder = true,
                    PossibleFormats = new List<ZXing.BarcodeFormat> { ZXing.BarcodeFormat.QR_CODE }
                };

                var result = reader.Decode(luminanceSource);
                return result?.Text;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[OFFLINE QR DECODE ERROR] {ex.Message}");
            }
            return null;
        }

        // Часть подписки может не импортироваться: у sing-box-клиентов (Exclave)
        // протоколов больше, чем у нас. StatusText в этой вёрстке скрыт, поэтому
        // молчание было полным — пользователь видел укороченный список и считал,
        // что «конфиг не работает». Показываем разницу явно и только когда она есть.
        private async Task ShowImportReportAsync(int added)
        {
            try
            {
                var rep = VlessProfile.LastImport;
                if (rep == null) return;
                if (rep.Skipped.Count == 0 && rep.Warnings.Count == 0) return;

                var sb = new StringBuilder();
                sb.Append("Добавлено серверов: ").Append(added).AppendLine();

                if (rep.Skipped.Count > 0)
                {
                    sb.AppendLine();
                    sb.Append("Пропущено: ").Append(rep.Skipped.Count)
                      .Append(" (").Append(rep.SkippedSummary()).AppendLine(")");
                    sb.AppendLine("Эти протоколы приложением не поддерживаются.");
                }

                if (rep.Warnings.Count > 0)
                {
                    sb.AppendLine();
                    sb.AppendLine("Импортированы, но не подключатся:");
                    int shown = 0;
                    foreach (var w in rep.Warnings)
                    {
                        if (shown++ == 6) { sb.AppendLine("  … и ещё " + (rep.Warnings.Count - 6)); break; }
                        sb.Append("  • ").AppendLine(w);
                    }
                }

                sb.AppendLine();
                sb.Append("Подробности — в файле ").Append(AppLog.LogFileName).Append('.');

                var dlg = new ContentDialog
                {
                    Title = "Импортировано не всё",
                    Content = sb.ToString(),
                    CloseButtonText = "ОК"
                };
                await dlg.ShowAsync();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[IMPORT REPORT] {ex.Message}");
            }
        }

        private async Task ProcessAndAddImportTextAsync(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return;

            StatusText.Text = "Загрузка/Парсинг...";
            AddBtn.IsEnabled = false;

            try
            {
                var newProfiles = await VlessProfile.ProcessInputAsync(text);

                if (newProfiles.Count > 0)
                {
                    var incomingSubscriptions = newProfiles
                        .Select(p => p.SubscriptionGroup)
                        .Distinct()
                        .Where(IsRefreshableGroup)
                        .ToList();

                    foreach (var subUrl in incomingSubscriptions)
                    {
                        _allProfiles.RemoveAll(p => string.Equals(p.SubscriptionGroup, subUrl, StringComparison.OrdinalIgnoreCase));
                    }

                    PopulateMetadata(newProfiles, text);
                    foreach (var g in incomingSubscriptions) ExpandAmneziaRows(newProfiles, g);
                    _allProfiles.AddRange(newProfiles);

                    UpdateGroupedUI();
                    await SaveProfilesAsync();
                    AppLog.W($"[ИМПОРТ] Добавлено {newProfiles.Count} шт., групп: " +
                             string.Join(", ", newProfiles.Select(p => p.SubscriptionGroup).Distinct()));
                    StatusText.Text = $"Импортировано {newProfiles.Count} серверов";
                    await ShowImportReportAsync(newProfiles.Count);
                }
                else
                {
                    StatusText.Text = "В импортированных данных не найдено профилей";
                    await ShowImportReportAsync(0);
                }
            }
            catch (AmneziaApi.UnsupportedConfigException ex)
            {
                StatusText.Text = "Конфиг получен, но не разобран.";
                await ShowUnsupportedConfigAsync(ex);
            }
            catch (Exception ex)
            {
                StatusText.Text = "Ошибка импорта: " + ex.Message;
                // Для ссылок Amnezia показываем лог обмена: причина отказа
                // почти всегда в теле ответа шлюза, а не в тексте исключения.
                if (AmneziaLink.IsAmneziaLink(text)) await ShowAmneziaErrorAsync(ex);
            }
            finally
            {
                AddBtn.IsEnabled = true;
            }
        }

        private void PopulateMetadata(List<VlessProfile> profiles, string url)
        {
            foreach (var p in profiles)
            {
                p.LastUpdated = DateTime.Now;
            }
        }

        // Подписка Amnezia приходит одним выданным сервером, но стран в ней
        // два десятка. Разворачиваем их в обычные строки списка — конфиг под
        // каждой запрашивается при нажатии.
        private static void ExpandAmneziaRows(List<VlessProfile> profiles, string groupName)
        {
            var issued = profiles.FirstOrDefault(p => p.IsAmneziaRow && !p.AmneziaNotIssued);
            if (issued == null) return;
            profiles.AddRange(AmneziaApi.BuildCountryRows(issued, groupName));
        }

        // Запросить конфиг для строки, под которой его ещё нет.
        private async Task IssueAmneziaRowAsync(VlessProfile row)
        {
            var sub = AmneziaLink.TryGetApiSubscription(row.SubscriptionGroup);
            if (sub == null)
            {
                StatusText.Text = "Не удалось прочитать ключ подписки из ссылки.";
                return;
            }
            sub.ServerCountryCode = row.AmneziaCountryCode;
            sub.ServiceProtocol = row.AmneziaProtocol;

            AmneziaApi.ClearLog();
            AmneziaApi.Log($"Запрос конфига для строки списка: {row.AmneziaCountryCode}/{row.AmneziaCountryName}, протокол {row.AmneziaProtocol}.");

            string was = row.CleanPingText;
            row.CleanPingText = "Запрашиваем...";
            try
            {
                var fetched = await AmneziaApi.FetchAsync(sub, row.SubscriptionGroup);
                var issued = fetched.FirstOrDefault();
                if (issued == null)
                {
                    row.CleanPingText = was;
                    StatusText.Text = "Шлюз не выдал конфиг для этой страны.";
                    return;
                }

                // Заменяем строку на месте, остальные не трогаем: ранее выданные
                // конфиги могут остаться рабочими, и терять их незачем.
                int idx = _allProfiles.IndexOf(row);
                issued.GroupTitle = row.GroupTitle;
                issued.GroupTitleCustom = row.GroupTitleCustom;
                if (idx >= 0) _allProfiles[idx] = issued; else _allProfiles.Add(issued);

                // Список стран и сведения о подписке обновились — раздаём всем строкам.
                foreach (var p in _allProfiles.Where(p => p.SubscriptionGroup == row.SubscriptionGroup))
                {
                    p.AmneziaCountries = issued.AmneziaCountries;
                    p.AmneziaInfo = issued.AmneziaInfo;
                }

                UpdateGroupedUI();
                await SaveProfilesAsync();

                StatusText.Text = $"Проверяем {issued.Address}...";
                await PingServerAsync(issued);

                // Конфиг к этому моменту уже выдан, вставлен в список и сохранён.
                // Неудачный замер задержки — не отказ выдачи, и сообщать о нём
                // как об ошибке нельзя: пользователь считал, что запрос не прошёл,
                // и повторял его, зря перевыпуская ключи.
                string ping = issued.CleanPingText ?? "";
                bool pingFailed = ping.StartsWith("Таймаут") || ping.StartsWith("Ошибка");
                SelectProfile(issued);
                if (pingFailed)
                {
                    StatusText.Text = $"Конфиг получен: {issued.Name}. Задержку измерить не удалось.";
                    AmneziaApi.Log($"  выданный узел {issued.Address}:{issued.Port} не ответил на пробу ({ping}). " +
                                   "Конфиг сохранён, подключение возможно.");
                }
                else
                {
                    StatusText.Text = $"Конфиг получен: {issued.Name} ({ping})";
                }
            }
            catch (AmneziaApi.UnsupportedConfigException ex)
            {
                row.CleanPingText = was;
                await ShowUnsupportedConfigAsync(ex);
            }
            catch (Exception ex)
            {
                row.CleanPingText = was;
                StatusText.Text = "Не удалось получить конфиг.";
                await ShowAmneziaErrorAsync(ex);
            }
        }

        private async void Item_Tapped(object sender, TappedRoutedEventArgs e)
        {
            var grid = sender as Grid;
            var profile = grid?.DataContext as VlessProfile;
            if (profile == null) return;

            // Строка страны Amnezia без конфига: сначала получаем его у шлюза.
            if (profile.AmneziaNotIssued)
            {
                await IssueAmneziaRowAsync(profile);
                return;
            }

            SelectProfile(profile);
        }

        private void SelectProfile(VlessProfile profile)
        {
            if (profile == null || string.IsNullOrEmpty(profile.Address)) return;

            _selectedProfile = profile;
            if (!_isConnected) StatusText.Text = $"Выбран: {profile.Name}";

            _vpnManager.WriteSettings(profile);

            foreach (var p in _allProfiles)
            {
                p.IsSelected = (p == profile);
            }

            var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
            localSettings.Values["v_LastSelectedAddress"] = profile.Address;
            localSettings.Values["v_LastSelectedPort"] = profile.Port;
        }

        private void ProfilesList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
        }

        private void GroupHeader_Tapped(object sender, TappedRoutedEventArgs e)
        {
            var border = sender as Border;
            var group = border?.Tag as ProfileGroup;
            if (group != null)
            {
                group.IsExpanded = !group.IsExpanded;
                _groupExpansionStates[group.Key] = group.IsExpanded;
                UpdateHideAllButtonVisibility();
            }
        }

        private void UpdateHideAllButtonVisibility()
        {
            bool hasAnyExpanded = _groupedProfiles.Any(g => g.IsExpanded);
            HideAllBtn.Visibility = hasAnyExpanded ? Visibility.Visible : Visibility.Collapsed;
        }

        private void HideAll_Tapped(object sender, TappedRoutedEventArgs e)
        {
            foreach (var group in _groupedProfiles)
            {
                group.IsExpanded = false;
                _groupExpansionStates[group.Key] = false;
            }
            UpdateGroupedUI();
            UpdateHideAllButtonVisibility();
            StatusText.Text = "Все группы свернуты";
        }

        private async void CheckConnection_Tapped(object sender, TappedRoutedEventArgs e)
        {
            if (!_isConnected)
            {
                StatusText.Text = "Сначала подключите VPN!";
                return;
            }

            CheckConnectionText.Text = "Проверка пинга...";

            string backupBtnText = ConnectBtnText.Text;
            var backupBtnVisibility = TimeText.Visibility;

            ConnectBtnText.Text = "ПРОВЕРКА...";
            TimeText.Visibility = Visibility.Collapsed;

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            string resultText = "";

            try
            {
                var socket = new Windows.Networking.Sockets.StreamSocket();
                var connectTask = socket.ConnectAsync(
                    new Windows.Networking.HostName("1.1.1.1"),
                    "80",
                    Windows.Networking.Sockets.SocketProtectionLevel.PlainSocket
                ).AsTask();

                var timeoutTask = Task.Delay(3000);
                var completedTask = await Task.WhenAny(connectTask, timeoutTask);

                if (completedTask == connectTask)
                {
                    await connectTask;
                    stopwatch.Stop();
                    resultText = $"Успешно: {stopwatch.ElapsedMilliseconds} мс";
                }
                else
                {
                    resultText = "Ошибка: Таймаут";
                }
                socket.Dispose();
            }
            catch
            {
                resultText = "Ошибка соединения";
            }

            CheckConnectionText.Text = resultText;
            ConnectBtnText.Text = resultText;

            await Task.Delay(3000);

            if (_isConnected)
            {
                ConnectBtnText.Text = backupBtnText;
                TimeText.Visibility = backupBtnVisibility;
            }
        }

        private void Item_ManipulationDelta(object sender, ManipulationDeltaRoutedEventArgs e)
        {
            var grid = sender as Grid;
            var contentGrid = grid?.FindName("ContentGrid") as Grid;
            var transform = contentGrid?.RenderTransform as TranslateTransform;
            if (transform != null)
            {
                double newX = transform.X + e.Delta.Translation.X;
                if (newX < -60) newX = -60;
                if (newX > 120) newX = 120;
                transform.X = newX;
            }
        }

        private void ContentGrid_Loaded(object sender, RoutedEventArgs e)
        {
            var grid = sender as Grid;
            var transform = grid?.RenderTransform as TranslateTransform;
            if (transform != null)
            {
                transform.X = 0;
            }
        }

        private void Item_ManipulationCompleted(object sender, ManipulationCompletedRoutedEventArgs e)
        {
            var grid = sender as Grid;
            var contentGrid = grid?.FindName("ContentGrid") as Grid;
            var transform = contentGrid?.RenderTransform as TranslateTransform;
            if (transform != null)
            {
                if (transform.X > 60)
                {
                    transform.X = 120;
                }
                else if (transform.X < -30)
                {
                    transform.X = -60;
                }
                else
                {
                    transform.X = 0;

                    var profile = grid.DataContext as VlessProfile;
                    if (profile != null)
                    {
                        profile.IsShareOpen = false;
                    }
                }
            }
        }

        private async void SwipePing_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.Tag as VlessProfile;
            if (profile != null)
            {
                CloseSwipePanel(button);
                await PingServerAsync(profile);
            }
        }

        private void SwipeShare_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.Tag as VlessProfile;
            if (profile != null)
            {
                profile.IsShareOpen = true;
            }
        }

        private async void SwipeDelete_Click(object sender, TappedRoutedEventArgs e)
        {
            var grid = sender as Grid;
            var profile = grid?.Tag as VlessProfile;
            if (profile != null)
            {
                _allProfiles.Remove(profile);
                UpdateGroupedUI();
                await SaveProfilesAsync();
                StatusText.Text = $"Сервер '{profile.Name}' удален.";
                if (_selectedProfile == profile)
                {
                    _selectedProfile = null;
                    StatusText.Text = "Выберите профиль!";
                }
            }
        }

        private void CloseSwipePanel(DependencyObject btn)
        {
            var parentGrid = FindParent<Grid>(btn);
            var contentGrid = parentGrid?.FindName("ContentGrid") as Grid;
            var transform = contentGrid?.RenderTransform as TranslateTransform;
            if (transform != null)
            {
                transform.X = 0;
            }
        }

        private T FindParent<T>(DependencyObject child) where T : DependencyObject
        {
            DependencyObject parentObject = VisualTreeHelper.GetParent(child);
            if (parentObject == null) return null;
            T parent = parentObject as T;
            if (parent != null) return parent;
            return FindParent<T>(parentObject);
        }

        private void ShareUrl_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.DataContext as VlessProfile;
            if (profile != null)
            {
                string url = ReconstructVlessUrl(profile);
                var dp = new DataPackage();
                dp.SetText(url);
                Clipboard.SetContent(dp);
                StatusText.Text = "URL скопирован в буфер!";

                CloseSwipePanel(button);
                profile.IsShareOpen = false;
            }
        }

        private void ShareQr_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.DataContext as VlessProfile;
            if (profile != null)
            {
                string url = ReconstructVlessUrl(profile);
                var dp = new DataPackage();
                dp.SetText(url);
                Clipboard.SetContent(dp);
                StatusText.Text = "QR-Ссылка скопирована!";

                CloseSwipePanel(button);
                profile.IsShareOpen = false;
            }
        }

        private void ShareJson_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var profile = button?.DataContext as VlessProfile;
            if (profile != null)
            {
                string json = ReconstructJson(profile);
                var dp = new DataPackage();
                dp.SetText(json);
                Clipboard.SetContent(dp);
                StatusText.Text = "JSON скопирован в буфер!";

                CloseSwipePanel(button);
                profile.IsShareOpen = false;
            }
        }

        private string ReconstructVlessUrl(VlessProfile p)
        {
            // У AmneziaWG нет ссылочного формата — делимся исходным .conf.
            if (p.IsAmneziaWg) return p.AwgConfig ?? "";
            if (p.IsShadowsocks)
            {
                // SIP002: userinfo = base64url(method:password) без паддинга.
                string userInfo = Convert.ToBase64String(
                        System.Text.Encoding.UTF8.GetBytes($"{p.Method}:{p.Password}"))
                    .TrimEnd('=').Replace('+', '-').Replace('/', '_');
                // prefix хранится в hex — в ссылку он идёт как percent-encoded UTF-8,
                // ровно так же, как его пишет сам Outline.
                string rawPrefix = VlessProfile.PrefixFromHex(p.SsPrefix);
                string query = string.IsNullOrEmpty(rawPrefix)
                    ? "" : "?prefix=" + Uri.EscapeDataString(rawPrefix);
                return $"ss://{userInfo}@{p.Address}:{p.Port}/{query}#{Uri.EscapeDataString(p.Name)}";
            }
            // Ссылка обязана пережить цикл «поделиться → импортировать обратно»: любое
            // потерянное поле молча меняет профиль. Так терялся flow — профиль с
            // xtls-rprx-vision после реимпорта становился обычным и уходил в MUX-режим
            // вместо DIRECT, то есть вёл себя совсем иначе, чем исходная ссылка.
            var q = new List<string>();
            Action<string, string> add = (k, v) =>
            {
                if (!string.IsNullOrEmpty(v)) q.Add(k + "=" + Uri.EscapeDataString(v));
            };

            add("type", p.Type);
            add("security", p.Security);
            add("encryption", "none");          // в ссылках VLESS поле обязательное
            add("sni", p.Sni);
            // PublicKey хранится в обычном base64 (парсер его туда переводит), а в ссылке
            // он должен быть base64url без паддинга — иначе «+» в query другие клиенты
            // прочитают как пробел и ключ развалится.
            add("pbk", string.IsNullOrEmpty(p.PublicKey)
                ? null
                : p.PublicKey.TrimEnd('=').Replace('+', '-').Replace('/', '_'));
            add("sid", p.ShortId);
            add("flow", p.Flow);
            add("path", p.Path);
            add("host", p.Host);
            add("alpn", p.Alpn);
            add("mode", p.Mode);

            // UUID парсер хранит без дефисов; отдаём в каноническом виде — так его
            // примут и сторонние клиенты.
            string uuid = p.Uuid;
            Guid g;
            if (Guid.TryParseExact(uuid ?? "", "N", out g)) uuid = g.ToString("D");

            return $"vless://{uuid}@{p.Address}:{p.Port}?{string.Join("&", q)}"
                 + $"#{Uri.EscapeDataString(p.Name ?? "")}";
        }

        private string ReconstructJson(VlessProfile p)
        {
            if (p.IsAmneziaWg) return p.AwgConfig ?? "";
            if (p.IsShadowsocks)
                return $"{{\n  \"server\": \"{p.Address}\",\n  \"server_port\": {p.Port},\n  \"method\": \"{p.Method}\",\n  \"password\": \"{p.Password}\"\n}}";
            return $"{{\n  \"server\": \"{p.Address}\",\n  \"port\": {p.Port},\n  \"uuid\": \"{p.Uuid}\",\n  \"type\": \"{p.Type}\",\n  \"security\": \"{p.Security}\",\n  \"sni\": \"{p.Sni}\",\n  \"public_key\": \"{p.PublicKey}\",\n  \"short_id\": \"{p.ShortId}\"\n}}";
        }

        private async void InfoLink_Tapped(object sender, TappedRoutedEventArgs e)
        {
            var border = sender as Border;
            var group = border?.DataContext as ProfileGroup;
            if (group != null && !string.IsNullOrEmpty(group.InfoUrl))
            {
                await Windows.System.Launcher.LaunchUriAsync(new Uri(group.InfoUrl));
            }
        }

        private async void TelegramLink_Tapped(object sender, TappedRoutedEventArgs e)
        {
            var border = sender as Border;
            var group = border?.DataContext as ProfileGroup;
            if (group != null && !string.IsNullOrEmpty(group.TelegramUrl))
            {
                await Windows.System.Launcher.LaunchUriAsync(new Uri(group.TelegramUrl));
            }
        }

        private async void UpdateSubscription_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var group = button?.DataContext as ProfileGroup;
            if (group != null)
            {
                await PerformSubscriptionUpdateAsync(group.Key);
            }
        }

        // Группы, которые можно перезапросить по их же ключу. Ключ Outline-профилей —
        // сам ssconf://-адрес, а он такой же перевыпускаемый источник, как и подписка.
        // Группу можно перезапросить по требованию пользователя.
        internal static bool IsRefreshableGroup(string group)
        {
            return !string.IsNullOrEmpty(group) &&
                   (group.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    group.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                    group.StartsWith("ssconf://", StringComparison.OrdinalIgnoreCase) ||
                    group.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase));
        }

        // Группу можно перезапрашивать САМИМ, без участия пользователя.
        // Подписки Amnezia Premium (группа — ссылка vpn://) сюда намеренно не
        // входят: каждый такой запрос идёт к платному API за новым конфигом,
        // и делать это в фоне по таймеру нельзя. Обновляются только по кнопке.
        internal static bool IsAutoRefreshableGroup(string group)
        {
            return IsRefreshableGroup(group) &&
                   !group.StartsWith("vpn://", StringComparison.OrdinalIgnoreCase);
        }

        private async Task PerformSubscriptionUpdateAsync(string url)
        {
            if (!IsRefreshableGroup(url)) return;

            StatusText.Text = "Обновление...";
            try
            {
                var newProfiles = await VlessProfile.ProcessInputAsync(url);
                if (newProfiles.Count > 0)
                {
                    // Своё имя подписки переживает обновление: профили пересоздаются,
                    // и иначе его затёрло бы то, что пришло от сервера.
                    var renamed = _allProfiles.FirstOrDefault(p => p.SubscriptionGroup == url && p.GroupTitleCustom);
                    string customTitle = renamed != null ? renamed.GroupTitle : null;

                    _allProfiles.RemoveAll(p => p.SubscriptionGroup == url);

                    PopulateMetadata(newProfiles, url);
                    if (!string.IsNullOrEmpty(customTitle))
                    {
                        foreach (var p in newProfiles) { p.GroupTitle = customTitle; p.GroupTitleCustom = true; }
                    }
                    ExpandAmneziaRows(newProfiles, url);
                    _allProfiles.AddRange(newProfiles);

                    UpdateGroupedUI();
                    await SaveProfilesAsync();
                    StatusText.Text = $"Подписка успешно обновлена! Найдено {newProfiles.Count} серверов.";
                }
                else
                {
                    StatusText.Text = "Подписка пуста.";
                }
            }
            catch (Exception ex)
            {
                StatusText.Text = "Ошибка обновления: " + ex.Message;
            }
        }

        private async Task CheckAndAutoUpdateSubscriptionsAsync()
        {
            var subscriptionsToUpdate = _allProfiles
                .Where(p => IsAutoRefreshableGroup(p.SubscriptionGroup))
                .GroupBy(p => p.SubscriptionGroup)
                .Where(g => (DateTime.Now - g.First().LastUpdated).TotalHours >= 1)
                .Select(g => g.Key)
                .ToList();

            if (subscriptionsToUpdate.Count > 0)
            {
                System.Diagnostics.Debug.WriteLine($"[AUTO-UPDATE] Запуск автообновления: {subscriptionsToUpdate.Count}");
                foreach (var url in subscriptionsToUpdate)
                {
                    await PerformSubscriptionUpdateAsync(url);
                }
            }
        }

        // Amnezia Premium выдаёт ОДИН активный конфиг на устройство, поэтому
        // страна тут не «ещё один сервер в списке», а переключатель: новый
        // запрос к шлюзу отзывает прежний конфиг. Ровно так же это устроено
        // в официальном клиенте, где страны показаны радиокнопками.
        private async void PickAmneziaCountry_Click(object sender, RoutedEventArgs e)
        {
            var group = (sender as Button)?.DataContext as ProfileGroup;
            if (group == null) return;

            var current = _allProfiles.FirstOrDefault(p => p.SubscriptionGroup == group.Key);
            if (current == null) return;

            var countries = AmneziaApi.DeserializeCountries(current.AmneziaCountries);
            if (countries.Count == 0)
            {
                StatusText.Text = "Шлюз не прислал список стран — обновите подписку.";
                await new ContentDialog
                {
                    Title = "Список стран пуст",
                    Content = "Шлюз Amnezia не прислал available_countries. Нажмите «обновить» у подписки и попробуйте снова.",
                    PrimaryButtonText = "Понятно"
                }.ShowAsync();
                return;
            }

            var list = new ListView
            {
                SelectionMode = ListViewSelectionMode.Single,
                ItemsSource = countries,
                Height = 320
            };
            var preselected = countries.FirstOrDefault(c =>
                string.Equals(c.Code, current.AmneziaCountryCode, StringComparison.OrdinalIgnoreCase));
            if (preselected != null) list.SelectedItem = preselected;

            var dialog = new ContentDialog
            {
                Title = "Страна подключения",
                Content = list,
                PrimaryButtonText = "Переключить",
                SecondaryButtonText = "Отмена",
                DefaultButton = ContentDialogButton.Secondary
            };
            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

            var chosen = list.SelectedItem as AmneziaApi.Country;
            if (chosen == null) return;

            var sub = AmneziaLink.TryGetApiSubscription(group.Key);
            if (sub == null)
            {
                StatusText.Text = "Не удалось прочитать ключ подписки из ссылки.";
                return;
            }

            sub.ServerCountryCode = chosen.Code;

            // Протокол должен быть из числа доступных именно в этой стране.
            // Если их несколько — спрашиваем, иначе VLESS невозможно было бы
            // выбрать вообще: awg есть почти везде и всегда побеждал бы сам.
            if (chosen.Protocols.Count > 1)
            {
                var protoList = new ListView
                {
                    SelectionMode = ListViewSelectionMode.Single,
                    ItemsSource = chosen.Protocols.Select(p => p.ToUpperInvariant()).ToList()
                };
                string currentProto = (current.AmneziaProtocol ?? "").ToUpperInvariant();
                var preProto = chosen.Protocols.Select(p => p.ToUpperInvariant())
                                               .FirstOrDefault(p => p == currentProto);
                protoList.SelectedItem = preProto ?? chosen.Protocols[0].ToUpperInvariant();

                var protoDialog = new ContentDialog
                {
                    Title = $"Протокол · {chosen.Name}",
                    Content = protoList,
                    PrimaryButtonText = "Выбрать",
                    SecondaryButtonText = "Отмена",
                    DefaultButton = ContentDialogButton.Primary
                };
                if (await protoDialog.ShowAsync() != ContentDialogResult.Primary) return;

                string pickedProto = protoList.SelectedItem as string;
                sub.ServiceProtocol = chosen.Protocols.FirstOrDefault(p =>
                    string.Equals(p, pickedProto, StringComparison.OrdinalIgnoreCase)) ?? chosen.Protocols[0];
            }
            else if (chosen.Protocols.Count == 1)
            {
                sub.ServiceProtocol = chosen.Protocols[0];
            }

            // Ничего не меняется — не тратим запрос к платному API.
            if (string.Equals(chosen.Code, current.AmneziaCountryCode, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(sub.ServiceProtocol, current.AmneziaProtocol, StringComparison.OrdinalIgnoreCase))
            {
                StatusText.Text = "Эта страна и протокол уже выбраны.";
                return;
            }

            AmneziaApi.ClearLog();
            AmneziaApi.Log($"Пользователь выбрал: страна {chosen.Code}/{chosen.Name}, " +
                           $"протоколы страны [{(chosen.Protocols.Count == 0 ? "список пуст" : string.Join(", ", chosen.Protocols))}], " +
                           $"запрашиваем протокол {sub.ServiceProtocol}. Было: {current.AmneziaCountryCode}/{current.AmneziaProtocol}.");

            StatusText.Text = $"Переключаем на {chosen.Name} ({sub.ServiceProtocol})...";
            try
            {
                var fetched = await AmneziaApi.FetchAsync(sub, group.Key);
                if (fetched.Count == 0)
                {
                    StatusText.Text = "Шлюз не выдал конфиг для этой страны.";
                    return;
                }

                var renamed = _allProfiles.FirstOrDefault(p => p.SubscriptionGroup == group.Key && p.GroupTitleCustom);
                string customTitle = renamed != null ? renamed.GroupTitle : null;

                _allProfiles.RemoveAll(p => p.SubscriptionGroup == group.Key);
                foreach (var p in fetched)
                {
                    p.LastUpdated = DateTime.Now;
                    if (!string.IsNullOrEmpty(customTitle)) { p.GroupTitle = customTitle; p.GroupTitleCustom = true; }
                }
                _allProfiles.AddRange(fetched);

                _selectedProfile = null;
                UpdateGroupedUI();
                await SaveProfilesAsync();

                // Выданный узел может быть недоступен из нашей сети — у Amnezia
                // это обычное дело для части стран. Проверяем сразу: иначе
                // единственным признаком была бы неудача подключения через
                // восемь секунд таймаута на каждое соединение.
                var issued = fetched[0];
                StatusText.Text = $"Проверяем {issued.Address}...";
                await PingServerAsync(issued);

                string ping = issued.CleanPingText ?? "";
                if (ping.StartsWith("Таймаут") || ping.StartsWith("Ошибка"))
                {
                    StatusText.Text = $"{chosen.Name}: сервер недоступен.";
                    AmneziaApi.Log($"  выданный узел {issued.Address}:{issued.Port} не отвечает ({ping}).");
                    await new ContentDialog
                    {
                        Title = "Сервер не отвечает",
                        Content = $"Страна переключена на {chosen.Name}, конфиг получен, но узел " +
                                  $"{issued.Address}:{issued.Port} не отвечает на подключение.\n\n" +
                                  "Скорее всего он заблокирован в вашей сети. Попробуйте другую страну " +
                                  "или другой протокол для этой же страны.",
                        PrimaryButtonText = "Понятно"
                    }.ShowAsync();
                }
                else
                {
                    StatusText.Text = $"Страна переключена: {chosen.Name} ({ping})";
                }
            }
            catch (AmneziaApi.UnsupportedConfigException ex)
            {
                StatusText.Text = "Конфиг получен, но не разобран.";
                await ShowUnsupportedConfigAsync(ex);
            }
            catch (Exception ex)
            {
                StatusText.Text = "Не удалось переключить страну.";
                await ShowAmneziaErrorAsync(ex);
            }
        }

        // Любая неудача с API Amnezia показывается вместе с полным логом обмена
        // и кладёт его в буфер: без этого причина отказа оставалась невидимой.
        private async Task ShowAmneziaErrorAsync(Exception ex)
        {
            string log = AmneziaApi.GetLog();

            var logBox = new TextBox
            {
                Text = log,
                IsReadOnly = true,
                AcceptsReturn = true,
                TextWrapping = TextWrapping.NoWrap,
                Height = 260,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 10
            };

            var panel = new StackPanel();
            panel.Children.Add(new TextBlock
            {
                Text = ex.Message,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            });
            panel.Children.Add(new TextBlock
            {
                Text = "Лог обмена скопирован в буфер обмена.",
                TextWrapping = TextWrapping.Wrap,
                FontSize = 11,
                Margin = new Thickness(0, 0, 0, 8)
            });
            panel.Children.Add(logBox);

            try
            {
                var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
                data.SetText(log);
                Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
            }
            catch (Exception clip)
            {
                System.Diagnostics.Debug.WriteLine($"[AMNEZIA API] Буфер обмена недоступен: {clip.Message}");
            }

            await new ContentDialog
            {
                Title = "Ошибка Amnezia API",
                Content = panel,
                PrimaryButtonText = "Понятно"
            }.ShowAsync();
        }

        // Шлюз выдал конфиг протокола, который мы ещё не разбираем. Показываем
        // обезличенную структуру ответа и кладём её в буфер: по ней дописывается
        // разбор, а ключи и адреса из неё уже вычищены.
        private async Task ShowUnsupportedConfigAsync(AmneziaApi.UnsupportedConfigException ex)
        {
            var text = new TextBox
            {
                Text = ex.Dump,
                IsReadOnly = true,
                AcceptsReturn = true,
                TextWrapping = TextWrapping.NoWrap,
                Height = 300,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11
            };

            var panel = new StackPanel();
            panel.Children.Add(new TextBlock
            {
                Text = ex.Message + "\n\nСтруктура ответа скопирована в буфер обмена — ключи и адреса из неё убраны.",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            });
            panel.Children.Add(text);

            try
            {
                var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
                data.SetText(ex.Dump);
                Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
            }
            catch (Exception clip)
            {
                System.Diagnostics.Debug.WriteLine($"[AMNEZIA API] Буфер обмена недоступен: {clip.Message}");
            }

            System.Diagnostics.Debug.WriteLine("[AMNEZIA API] Структура неразобранного конфига:\n" + ex.Dump);

            await new ContentDialog
            {
                Title = "Протокол пока не поддержан",
                Content = panel,
                PrimaryButtonText = "Понятно"
            }.ShowAsync();
        }

        private async void RenameSubscription_Click(object sender, RoutedEventArgs e)
        {
            var group = (sender as Button)?.DataContext as ProfileGroup;
            if (group == null) return;

            var input = new TextBox
            {
                Text = group.Title,
                PlaceholderText = "Имя подписки",
                AcceptsReturn = false,
                SelectionStart = 0,
                SelectionLength = group.Title != null ? group.Title.Length : 0
            };

            var dialog = new ContentDialog
            {
                Title = "Переименовать подписку",
                Content = input,
                PrimaryButtonText = "Сохранить",
                SecondaryButtonText = "Отмена"
            };

            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

            string name = (input.Text ?? "").Trim();
            // Пустое имя не ошибка: это возврат к имени по умолчанию, которое
            // выводится из ссылки. Иначе стереть своё имя было бы нечем.
            foreach (var p in _allProfiles.Where(p => p.SubscriptionGroup == group.Key))
            {
                p.GroupTitle = name;
                p.GroupTitleCustom = !string.IsNullOrEmpty(name);
            }

            UpdateGroupedUI();
            await SaveProfilesAsync();
            StatusText.Text = string.IsNullOrEmpty(name) ? "Имя подписки сброшено." : $"Подписка переименована: {name}";
        }

        private async void DeleteSubscription_Click(object sender, RoutedEventArgs e)
        {
            var menuItem = sender as Button;
            var group = menuItem?.DataContext as ProfileGroup;
            if (group == null) return;

            int count = _allProfiles.Count(p => p.SubscriptionGroup == group.Key);
            var dialog = new ContentDialog
            {
                Title = "Удалить подписку?",
                Content = $"«{group.Title}» и все серверы из неё ({count} шт.) будут удалены. Отменить это будет нельзя.",
                PrimaryButtonText = "Удалить",
                SecondaryButtonText = "Отмена",
                DefaultButton = ContentDialogButton.Secondary
            };

            if (await dialog.ShowAsync() != ContentDialogResult.Primary) return;

            _allProfiles.RemoveAll(p => p.SubscriptionGroup == group.Key);
            UpdateGroupedUI();
            await SaveProfilesAsync();
            StatusText.Text = "Подписка удалена.";
            _selectedProfile = null;
        }

        private async void PingGroup_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var group = button?.DataContext as ProfileGroup;
            if (group != null)
            {
                // В подписке Amnezia проверяемы только выданные vless-узлы:
                // у невыданных строк адреса ещё нет, а awg работает по UDP.
                // Считаем их отдельно, чтобы итог не выглядел так, будто
                // проверили всё и всё молчит.
                int checkedCount = 0, skipped = 0;
                StatusText.Text = "Пингуем...";
                foreach (var profile in group)
                {
                    bool measurable = !profile.AmneziaNotIssued && !profile.IsAmneziaWg
                                      && !string.IsNullOrEmpty(profile.Address) && profile.Port > 0;
                    await PingServerAsync(profile);
                    if (measurable) checkedCount++; else skipped++;
                }
                StatusText.Text = skipped > 0
                    ? $"Проверено серверов: {checkedCount}. Пропущено (нет адреса или WireGuard): {skipped}."
                    : "Пинг группы завершен.";
            }
        }

        private void UpdateGroupedUI()
        {
            _groupedProfiles.Clear();
            var groups = _allProfiles
                .GroupBy(p => p.SubscriptionGroup)
                .OrderBy(g => g.Key == "Ручной импорт" || g.Key == "Импорт из буфера" ? 1 : 0)
                .Select(g =>
                {
                    var pg = new ProfileGroup { Key = g.Key };
                    if (_groupExpansionStates.TryGetValue(g.Key, out bool isExpanded))
                    {
                        pg.IsExpanded = isExpanded;
                    }
                    else
                    {
                        pg.IsExpanded = true;
                    }
                    pg.SetAllItems(g);
                    return pg;
                });

            foreach (var g in groups)
            {
                _groupedProfiles.Add(g);
            }

            UpdateHideAllButtonVisibility();
        }

        // Список живёт в одном файле. Пишется он через FileIO: поток, который выдаёт
        // OpenStreamForWriteAsync, дописывает файл уже после Dispose, и если телефон
        // усыплял приложение сразу после импорта, запись не доходила — подписка была в
        // списке до перезапуска и пропадала после него.
        private const string ProfilesFile = "profiles.json";

        private readonly System.Threading.SemaphoreSlim _saveLock = new System.Threading.SemaphoreSlim(1, 1);

        private static string SerializeProfiles(List<VlessProfile> profiles)
        {
            using (var ms = new MemoryStream())
            {
                new DataContractJsonSerializer(typeof(List<VlessProfile>)).WriteObject(ms, profiles);
                return Encoding.UTF8.GetString(ms.ToArray(), 0, (int)ms.Length);
            }
        }

        private async Task SaveProfilesAsync()
        {
            await _saveLock.WaitAsync();
            try
            {
                string json = SerializeProfiles(_allProfiles);
                var folder = Windows.Storage.ApplicationData.Current.LocalFolder;

                var file = await folder.CreateFileAsync(ProfilesFile, Windows.Storage.CreationCollisionOption.ReplaceExisting);

                // Байтами, а не текстом: WriteTextAsync ставит в начало метку порядка
                // байтов, а разборщик JSON о неё спотыкается — файл, записанный этой
                // версией, не прочитала бы ни одна прежняя.
                await Windows.Storage.FileIO.WriteBytesAsync(file, Encoding.UTF8.GetBytes(json));

                // Записанное перечитывается: «сохранил» без проверки уже один раз означало
                // пустой список после перезапуска, и в журнале это выглядело как успех.
                ulong written = (await file.GetBasicPropertiesAsync()).Size;
                AppLog.W($"[ПРОФИЛИ] Сохранено: {_allProfiles.Count} шт., на диске {written} байт.");
            }
            catch (Exception ex)
            {
                AppLog.W("[ПРОФИЛИ] СОХРАНИТЬ НЕ УДАЛОСЬ: " + ex);
            }
            finally
            {
                _saveLock.Release();
            }
        }

        // Возвращает null, если файла нет или он не читается.
        private static async Task<List<VlessProfile>> TryReadProfilesFileAsync(string name)
        {
            try
            {
                var file = await Windows.Storage.ApplicationData.Current.LocalFolder.GetFileAsync(name);

                // Через FileIO, а не через поток: файл могли положить с меткой порядка
                // байтов, и разборщик JSON споткнулся бы о неё на первом же символе.
                string text = await Windows.Storage.FileIO.ReadTextAsync(file);
                text = text.TrimStart('﻿');
                using (var ms = new MemoryStream(Encoding.UTF8.GetBytes(text)))
                {
                    var serializer = new DataContractJsonSerializer(typeof(List<VlessProfile>));
                    return (List<VlessProfile>)serializer.ReadObject(ms) ?? new List<VlessProfile>();
                }
            }
            catch (Exception ex)
            {
                AppLog.W($"[ПРОФИЛИ] {name} не прочитан: {ex.Message}");
                return null;
            }
        }

        private async Task LoadProfilesAsync()
        {
            try
            {
                var list = await TryReadProfilesFileAsync(ProfilesFile);

                {
                    _allProfiles.Clear();
                    if (list != null)
                    {
                        _allProfiles.AddRange(list);
                    }
                    AppLog.W($"[ПРОФИЛИ] Загружено при старте: {_allProfiles.Count} шт.");

                    // REALITY без SNI не поднимется никогда: сервер не отвечает на
                    // такой ClientHello. Конфиги, сохранённые до исправления разбора,
                    // возвращаем в состояние «не выдан», чтобы их можно было
                    // перезапросить нажатием, а не гадать, почему нет соединения.
                    foreach (var p in _allProfiles)
                    {
                        if (p.IsAmneziaRow && !p.AmneziaNotIssued &&
                            string.Equals(p.Security, "reality", StringComparison.OrdinalIgnoreCase) &&
                            string.IsNullOrEmpty(p.Sni))
                        {
                            System.Diagnostics.Debug.WriteLine(
                                $"[LOAD] {p.Name}: конфиг REALITY без SNI — помечен как невыданный, нужен перезапрос.");
                            p.AmneziaNotIssued = true;
                            p.Address = "";
                            p.CleanPingText = "";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                AppLog.W("[ПРОФИЛИ] ЗАГРУЗКА СОРВАЛАСЬ: " + ex);
            }

            var localSettings = Windows.Storage.ApplicationData.Current.LocalSettings;
            string lastAddress = localSettings.Values["v_LastSelectedAddress"] as string;
            int? lastPort = localSettings.Values["v_LastSelectedPort"] as int?;

            UpdateGroupedUI();

            if (!string.IsNullOrEmpty(lastAddress) && lastPort.HasValue)
            {
                _selectedProfile = _allProfiles.FirstOrDefault(p => p.Address == lastAddress && p.Port == lastPort.Value);
                if (_selectedProfile != null)
                {
                    _selectedProfile.IsSelected = true;
                    StatusText.Text = $"Выбран: {_selectedProfile.Name}";
                }
            }
        }

        private async System.Threading.Tasks.Task PingServerAsync(VlessProfile profile)
        {
            // AmneziaWG работает по UDP, и точка входа лежит внутри конфига
            // WireGuard, а не в Address. TCP-проба тут бессмысленна: HostName
            // с пустым адресом бросала исключение, и пользователь видел
            // «Ошибка … hostname» — будто конфиг не выдали, хотя он уже сохранён.
            // Строка страны без выданного конфига адреса ещё не имеет: шлюз
            // отдаёт конфиги по одному, и узнать узел заранее нельзя. Проверять
            // такую строку нечего — помечаем, а не пробуем подключиться.
            if (profile.AmneziaNotIssued)
            {
                profile.CleanPingText = "Не выдан";
                return;
            }
            if (profile.IsAmneziaWg)
            {
                profile.CleanPingText = "WireGuard";
                return;
            }
            if (string.IsNullOrEmpty(profile.Address) || profile.Port <= 0)
            {
                profile.CleanPingText = "Нет адреса";
                return;
            }

            profile.CleanPingText = "Проверка...";

            var socket = new Windows.Networking.Sockets.StreamSocket();
            var timer = System.Diagnostics.Stopwatch.StartNew();

            try
            {
                var connectTask = socket.ConnectAsync(
                    new Windows.Networking.HostName(profile.Address),
                    profile.Port.ToString(),
                    Windows.Networking.Sockets.SocketProtectionLevel.PlainSocket
                ).AsTask();

                var timeoutTask = System.Threading.Tasks.Task.Delay(3000);
                var completedTask = await System.Threading.Tasks.Task.WhenAny(connectTask, timeoutTask);

                if (completedTask == connectTask)
                {
                    await connectTask;
                    timer.Stop();
                    profile.CleanPingText = $"{timer.ElapsedMilliseconds} мс";
                }
                else
                {
                    timer.Stop();
                    profile.CleanPingText = "Таймаут (🔴)";
                }
            }
            catch (Exception)
            {
                timer.Stop();
                profile.CleanPingText = "Ошибка (🔴)";
            }
            finally
            {
                socket.Dispose();
            }
        }

        private void SettingsBtn_Click(object sender, RoutedEventArgs e)
        {
            AboutPageGrid.Visibility = Visibility.Visible;
        }

        private void AboutBackBtn_Click(object sender, RoutedEventArgs e)
        {
            AboutPageGrid.Visibility = Visibility.Collapsed;
        }

        // ===================== отправка журналов =====================

        private List<Windows.Storage.StorageFile> _logFilesToShare;

        // Разбирать «не подключается» без журналов нечем: applog.txt — что решило
        // приложение при импорте и подключении, vpnlog.txt — что делал туннель.
        private async void ShareLogBtn_Click(object sender, RoutedEventArgs e)
        {
            var files = await CollectLogFilesAsync();
            if (files.Count == 0)
            {
                ShareLogHint.Text = "Журнал пуст. Попробуйте подключиться к серверу и повторите отправку.";
                return;
            }

            _logFilesToShare = files;
            var names = new List<string>();
            foreach (var f in files) names.Add(f.Name);
            ShareLogHint.Text = "Отправляются файлы: " + string.Join(", ", names) + ".";

            var dtm = DataTransferManager.GetForCurrentView();
            dtm.DataRequested -= OnLogShareRequested;
            dtm.DataRequested += OnLogShareRequested;
            try
            {
                DataTransferManager.ShowShareUI();
            }
            catch (Exception ex)
            {
                ShareLogHint.Text = "Не удалось открыть окно отправки: " + ex.Message;
            }
        }

        private void OnLogShareRequested(DataTransferManager sender, DataRequestedEventArgs args)
        {
            var files = _logFilesToShare;
            if (files == null || files.Count == 0)
            {
                args.Request.FailWithDisplayText("Журнал пуст.");
                return;
            }
            var data = args.Request.Data;
            data.Properties.Title = "Журнал MetroBox";
            data.Properties.Description = AppLog.EnvironmentInfo();
            data.SetStorageItems(files);
        }

        private static async Task<List<Windows.Storage.StorageFile>> CollectLogFilesAsync()
        {
            var names = new[] { AppLog.LogFileName, "vpnlog.txt", "vpnlog.prev.txt", AmneziaApi.LogFileName };
            var folder = Windows.Storage.ApplicationData.Current.LocalFolder;
            var result = new List<Windows.Storage.StorageFile>();
            foreach (var name in names)
            {
                try
                {
                    var file = await folder.TryGetItemAsync(name) as Windows.Storage.StorageFile;
                    if (file == null) continue;
                    var props = await file.GetBasicPropertiesAsync();
                    if (props.Size > 0) result.Add(file);   // пустые файлы получателю не нужны
                }
                catch { /* один недоступный файл не должен ломать отправку остальных */ }
            }
            return result;
        }
    }
}