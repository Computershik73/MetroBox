using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
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

        // Метаданные извлекаются из резервного кэша серверов подписки
        // Это предотвращает их исчезновение при сворачивании группы
        public string LastUpdatedText => _allItems.Count > 0
            ? $"Обновлено: {_allItems[0].LastUpdated:dd.MM.yyyy HH:mm}"
            : "Импортировано: не обновлялось";

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

        private VpnManager _vpnManager = new VpnManager();
        private List<VlessProfile> _allProfiles = new List<VlessProfile>();
        private ObservableCollection<ProfileGroup> _groupedProfiles = new ObservableCollection<ProfileGroup>();
        private Dictionary<string, bool> _groupExpansionStates = new Dictionary<string, bool>();

        private DispatcherTimer _timer;
        private DispatcherTimer _statusTimer;
        private DispatcherTimer _autoUpdateTimer; // Таймер автообновления
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

            // Автообновление подписок раз в час (проверяем каждые 5 минут)
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
            await CheckAndAutoUpdateSubscriptionsAsync(); // Проверка автообновления при старте
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

      
      

        // Проверка активности виртуального адаптера на уровне IANA-интерфейсов Windows 10 Mobile
        private bool IsVpnProfileConnectedByIana()
        {
            try
            {
                // Запрашиваем все активные сетевые подключения
                var connections = Windows.Networking.Connectivity.NetworkInformation.GetConnectionProfiles();
                foreach (var conn in connections)
                {
                    if (conn.NetworkAdapter != null)
                    {
                        uint type = conn.NetworkAdapter.IanaInterfaceType;

                        // 131 = Tunnel (IPsec/туннель), 150 = PropVirtual (Виртуальный интерфейс/VPN)
                        if (type == 131 || type == 150)
                        {
                            var level = conn.GetNetworkConnectivityLevel();
                            // Проверяем, что интерфейс активен и готов передавать трафик
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

        private bool IsVpnInterfaceActive()
        {
            try
            {
                var hostNames = Windows.Networking.Connectivity.NetworkInformation.GetHostNames();
                foreach (var hn in hostNames)
                {
                    if (hn.Type == HostNameType.Ipv4)
                    {
                        if (hn.RawName == "11.16.1.1")
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private async Task CheckVpnStatusAsync()
        {
            try
            {
                var mine = await GetProfileAsync();
                if (mine != null && mine is VpnPlugInProfile plug)
                {
                    VpnManagementConnectionStatus status;
                    try
                    {
                        status = plug.ConnectionStatus;
                    }
                    catch (Exception)
                    {
                        _cachedProfile = null;
                        status = VpnManagementConnectionStatus.Disconnected;
                    }

                    // СУПЕР-БЭКАП ДАТЧИК (Комбинация IP-зонда и IANA-интерфейса)
                    // Если ConnectionStatus сбоит, но в ядре Lumia активен виртуальный IP (11.16.1.1) 
                    // или поднят системный адаптер типа 150/131 — VPN гарантированно успешно работает!
                    bool isVpnActive = IsVpnInterfaceActive() || IsVpnProfileConnectedByIana();

                    if (status != VpnManagementConnectionStatus.Connected && isVpnActive)
                    {
                        status = VpnManagementConnectionStatus.Connected;
                    }

                    if (status == VpnManagementConnectionStatus.Connected)
                    {
                        if (!_isConnected)
                        {
                            _isConnected = true;
                            _activeTime = TimeSpan.Zero;
                            _timer.Start();

                            GlowRing1.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 56, 189, 248));
                            GlowRing2.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 56, 189, 248));
                            GlowRing1.Opacity = 0.15;
                            GlowRing2.Opacity = 0.35;
                            PowerIcon.Foreground = new SolidColorBrush(Color.FromArgb(255, 56, 189, 248));

                            TimeText.Visibility = Visibility.Visible;
                            TimeText.Foreground = new SolidColorBrush(Color.FromArgb(255, 56, 189, 248));

                            ConnectBtnText.Text = "ПОДКЛЮЧЕН";
                            ConnectBtnText.Foreground = new SolidColorBrush(Color.FromArgb(255, 56, 189, 248));
                            ConnectBtn.BorderBrush = new SolidColorBrush(Color.FromArgb(255, 56, 189, 248));
                            ConnectBtn.Background = this.Resources["ButtonGlowConnected"] as Brush;

                            string connName = _selectedProfile != null ? _selectedProfile.Name : mine.ProfileName;
                            StatusText.Text = $"Подключен (глобально): {connName}";
                            CheckConnectionText.Text = "Проверить текущее подключение";
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
                        if (_isConnected)
                        {
                            HardResetMainPage();
                        }
                    }
                }
                else
                {
                    _cachedProfile = null;
                    if (_isConnected)
                    {
                        HardResetMainPage();
                    }
                }
            }
            catch (Exception ex)
            {
                _cachedProfile = null;
                System.Diagnostics.Debug.WriteLine($"[STATUS CHECK FAIL] {ex.Message}");
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
                StatusText.Text = "Отключение...";
                await ForceDisconnectActiveProfileAsync();
                await Task.Delay(700);   // дать платформе освободить tunnel
                HardResetMainPage();
            }
            else
            {
                if (_selectedProfile == null)
                {
                    StatusText.Text = "Выберите профиль!";
                    return;
                }

                var mine = await _vpnManager.FindOwnProfileAsync();
                if (mine == null)
                {
                    await ShowNoProfileDialogAsync();
                    return;
                }

                IsRedirectingToSettings = true;
                _vpnManager.WriteSettings(_selectedProfile);

                await ForceDisconnectActiveProfileAsync();
                await Task.Delay(700);   // дать платформе освободить tunnel

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

                // Наш клиент обслуживает один VPN-профиль. Имя в системе задаёт пользователь
                // вручную, оно не совпадает с меткой сервера в приложении — поэтому по имени
                // не ищем. Отключаем все профили нашего провайдера (обычно он один).
                bool any = false;
                foreach (var p in profiles)
                {
                    try
                    {
                        var status = await agent.DisconnectProfileAsync(p);
                        System.Diagnostics.Debug.WriteLine($"[VPN MGR] DisconnectProfile '{p.ProfileName}': {status}");
                        any = true;
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[VPN MGR] Не удалось отключить '{p.ProfileName}': {ex.Message}");
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

        private async void ImportBtn_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var dataPackageView = Clipboard.GetContent();
                if (dataPackageView.Contains(StandardDataFormats.Text))
                {
                    string text = await dataPackageView.GetTextAsync();
                    StatusText.Text = "Загрузка/Парсинг...";
                    AddBtn.IsEnabled = false;

                    var newProfiles = await VlessProfile.ProcessInputAsync(text);

                    if (newProfiles.Count > 0)
                    {
                        var incomingSubscriptions = newProfiles
                            .Select(p => p.SubscriptionGroup)
                            .Distinct()
                            .Where(g => g.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                                         g.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                            .ToList();

                        foreach (var subUrl in incomingSubscriptions)
                        {
                            _allProfiles.RemoveAll(p => string.Equals(p.SubscriptionGroup, subUrl, StringComparison.OrdinalIgnoreCase));
                        }

                        // Наполняем метаданными по умолчанию
                        PopulateMetadata(newProfiles, text);

                        _allProfiles.AddRange(newProfiles);

                        UpdateGroupedUI();
                        await SaveProfilesAsync();
                        StatusText.Text = $"Импортировано {newProfiles.Count} серверов";
                    }
                    else
                    {
                        StatusText.Text = "В буфере не найдено vless:// профилей";
                    }
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
            finally
            {
                AddBtn.IsEnabled = true;
            }
        }

        // Заполнение метаданных подписки по умолчанию
        // Обновлено: заглушки удалены. Поля остаются пустыми и автоматически скрываются в UI,
        // если сервер не передал реальных метаданных в заголовках.
        private void PopulateMetadata(List<VlessProfile> profiles, string url)
        {
            foreach (var p in profiles)
            {
                p.LastUpdated = DateTime.Now;
                // p.Description, p.InfoUrl и p.TelegramUrl сохраняют свои реальные значения,
                // полученные от парсера VlessProfile.ProcessInputAsync
            }
        }

        private void Item_Tapped(object sender, TappedRoutedEventArgs e)
        {
            var grid = sender as Grid;
            var profile = grid?.DataContext as VlessProfile;
            if (profile != null)
            {
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

        // Проверка пинга по туннелю (активный VPN) с выводом "Проверка пинга..." внутри кнопки
        // Проверка пинга по туннелю (активный VPN) с фиксацией результата на экране
        private async void CheckConnection_Tapped(object sender, TappedRoutedEventArgs e)
        {
            if (!_isConnected)
            {
                StatusText.Text = "Сначала подключите VPN!";
                return;
            }

            CheckConnectionText.Text = "Проверка пинга...";

            // Временный бэкап надписей на центральной кнопке
            string backupBtnText = ConnectBtnText.Text;
            var backupBtnVisibility = TimeText.Visibility;

            // Замещаем текст внутри кнопки "ПОДКЛЮЧИТЬ" на индикатор теста
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

            // Выводим результат в оба индикатора
            CheckConnectionText.Text = resultText;
            ConnectBtnText.Text = resultText;

            // Ожидаем 3 секунды и восстанавливаем прежний вид только центральной кнопки
            await Task.Delay(3000);

            if (_isConnected)
            {
                // Возвращаем таймер и статус "ПОДКЛЮЧЕН" на сферу подключения
                ConnectBtnText.Text = backupBtnText;
                TimeText.Visibility = backupBtnVisibility;

                // Текст надписи CheckConnectionText НЕ восстанавливаем, оставляя результат последнего пинга
            }
        }

        // === РЕАЛИЗАЦИЯ ЖЕСТОВ СВАЙПА ВПРАВО (Actions) И ВЛЕВО (Delete) ===

        private void Item_ManipulationDelta(object sender, ManipulationDeltaRoutedEventArgs e)
        {
            var grid = sender as Grid;
            var contentGrid = grid?.FindName("ContentGrid") as Grid;
            var transform = contentGrid?.RenderTransform as TranslateTransform;
            if (transform != null)
            {
                double newX = transform.X + e.Delta.Translation.X;
                if (newX < -60) newX = -60; // Предел сдвига влево (мусорный бак)
                if (newX > 120) newX = 120; // Предел сдвига вправо (меню)
                transform.X = newX;
            }
        }

        // Сброс сдвига при переиспользовании визуального контейнера (виртуализация UWP)
        private void ContentGrid_Loaded(object sender, RoutedEventArgs e)
        {
            var grid = sender as Grid;
            var transform = grid?.RenderTransform as TranslateTransform;
            if (transform != null)
            {
                transform.X = 0; // Принудительно закрываем свайп-панель у новой ячейки
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
                    transform.X = 120; // Открыто меню быстрых действий
                }
                else if (transform.X < -30)
                {
                    transform.X = -60; // Открыта кнопка удаления
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

        // === МЕНЮ ПОДЕЛИТЬСЯ (URL / QR / JSON) ===

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
            return $"vless://{p.Uuid}@{p.Address}:{p.Port}?type={p.Type}&security={p.Security}&sni={p.Sni}&pbk={p.PublicKey}&sid={p.ShortId}#{Uri.EscapeDataString(p.Name)}";
        }

        private string ReconstructJson(VlessProfile p)
        {
            return $"{{\n  \"server\": \"{p.Address}\",\n  \"port\": {p.Port},\n  \"uuid\": \"{p.Uuid}\",\n  \"type\": \"{p.Type}\",\n  \"security\": \"{p.Security}\",\n  \"sni\": \"{p.Sni}\",\n  \"public_key\": \"{p.PublicKey}\",\n  \"short_id\": \"{p.ShortId}\"\n}}";
        }

        // === ИНФО И ТЕЛЕГРАМ КНОПКИ ===

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

        // === ФУНКЦИИ ОБНОВЛЕНИЯ И АВТООБНОВЛЕНИЯ ПОДПИСОК ===

        private async void UpdateSubscription_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var group = button?.DataContext as ProfileGroup;
            if (group != null)
            {
                await PerformSubscriptionUpdateAsync(group.Key);
            }
        }

        private async Task PerformSubscriptionUpdateAsync(string url)
        {
            if (string.IsNullOrEmpty(url) || (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                return;

            StatusText.Text = "Обновление...";
            try
            {
                var newProfiles = await VlessProfile.ProcessInputAsync(url);
                if (newProfiles.Count > 0)
                {
                    _allProfiles.RemoveAll(p => p.SubscriptionGroup == url);

                    PopulateMetadata(newProfiles, url);
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

        // Логика автообновления каждые 60 минут
        private async Task CheckAndAutoUpdateSubscriptionsAsync()
        {
            var subscriptionsToUpdate = _allProfiles
                .Where(p => p.SubscriptionGroup.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                            p.SubscriptionGroup.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
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

        private async void DeleteSubscription_Click(object sender, RoutedEventArgs e)
        {
            var menuItem = sender as Button;
            var group = menuItem?.DataContext as ProfileGroup;
            if (group != null)
            {
                _allProfiles.RemoveAll(p => p.SubscriptionGroup == group.Key);
                UpdateGroupedUI();
                await SaveProfilesAsync();
                StatusText.Text = "Подписка удалена.";
                _selectedProfile = null;
            }
        }

        private async void PingGroup_Click(object sender, RoutedEventArgs e)
        {
            var button = sender as Button;
            var group = button?.DataContext as ProfileGroup;
            if (group != null)
            {
                StatusText.Text = "Пингуем...";
                foreach (var profile in group)
                {
                    await PingServerAsync(profile);
                }
                StatusText.Text = "Пинг группы завершен.";
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

        private async Task SaveProfilesAsync()
        {
            try
            {
                var file = await Windows.Storage.ApplicationData.Current.LocalFolder.CreateFileAsync("profiles.json", Windows.Storage.CreationCollisionOption.ReplaceExisting);
                using (var stream = await file.OpenStreamForWriteAsync())
                {
                    var serializer = new DataContractJsonSerializer(typeof(List<VlessProfile>));
                    serializer.WriteObject(stream, _allProfiles);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[SAVE FAIL] {ex.Message}");
            }
        }

        private async Task LoadProfilesAsync()
        {
            try
            {
                var file = await Windows.Storage.ApplicationData.Current.LocalFolder.GetFileAsync("profiles.json");
                using (var stream = await file.OpenStreamForReadAsync())
                {
                    var serializer = new DataContractJsonSerializer(typeof(List<VlessProfile>));
                    var list = (List<VlessProfile>)serializer.ReadObject(stream);
                    _allProfiles.Clear();
                    if (list != null)
                    {
                        _allProfiles.AddRange(list);
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[LOAD INFO] {ex.Message}");
                _allProfiles.Clear();
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
                    // Изменен формат вывода пинга отдельного сервера: без молнии, в формате "*** мс"
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

        // Обработчик кнопки «Назад» на странице «О приложении»
        private void AboutBackBtn_Click(object sender, RoutedEventArgs e)
        {
            AboutPageGrid.Visibility = Visibility.Collapsed;
        }
    }
}