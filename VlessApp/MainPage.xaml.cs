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

        private bool IsVpnProfileConnectedByIana()
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
                    // Проверяем активность системных сетевых IANA-интерфейсов ядра (без генерации исключений)
                    bool isVpnActive = IsVpnInterfaceActive() || IsVpnProfileConnectedByIana();
                    VpnManagementConnectionStatus status = VpnManagementConnectionStatus.Disconnected;

                    if (isVpnActive)
                    {
                        // Если туннель уже поднят, пробуем запросить точный статус.
                        // Если системный API выбросит исключение (из-за инициализации плагина) — 
                        // мы все равно знаем, что туннель работает, поэтому ставим Connected.
                        try
                        {
                            status = plug.ConnectionStatus;
                        }
                        catch (Exception)
                        {
                            status = VpnManagementConnectionStatus.Connected;
                        }
                    }
                    else
                    {
                        // Если в системе нет активных VPN-интерфейсов, мы гарантированно отключены.
                        // Избегаем вызова plug.ConnectionStatus, предотвращая тормоза интерфейса и спам в логи.
                        status = VpnManagementConnectionStatus.Disconnected;
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
                await Task.Delay(700);
                HardResetMainPage();
            }
            else
            {
                if (_selectedProfile == null)
                {
                    StatusText.Text = "Выберите профиль!";
                    return;
                }

                // Блокировка XTLS-Vision
                if (!string.IsNullOrEmpty(_selectedProfile.Flow) &&
                    _selectedProfile.Flow.IndexOf("vision", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    var visionDialog = new ContentDialog
                    {
                        Title = "Протокол не поддерживается",
                        Content = "Протокол XTLS Vision (flow=xtls-rprx-vision) пока не поддерживается данным приложением.\n\n" +
                                  "Пожалуйста, выберите конфигурацию с другим типом flow (например, без flow или с классическим Reality).",
                        CloseButtonText = "ОК"
                    };

                    await visionDialog.ShowAsync();
                    StatusText.Text = "Подключение отменено (Vision не поддерживается).";
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
                    StatusText.Text = "Подключение отменено (gRPC не поддерживается).";
                    return;
                }

                if (string.Equals(_selectedProfile.Type, "ws", StringComparison.OrdinalIgnoreCase))
                {
                    var xhttpDialog = new ContentDialog
                    {
                        Title = "Не поддерживается",
                        Content = "Транспорт WebSocket пока не поддерживается. " +
                                  "Если вам нужен обход белых списков, используйте сервера с TCP транспортом ",
                        CloseButtonText = "Отмена"
                    };

                    var choice = await xhttpDialog.ShowAsync();
                    if (choice != ContentDialogResult.Primary)
                    {
                        StatusText.Text = "Подключение отменено.";
                        return;
                    }
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
        private async Task<string> DecodeQrCodeFromStreamAsync(Windows.Storage.Streams.IRandomAccessStream stream)
        {
            try
            {
                var decoder = await Windows.Graphics.Imaging.BitmapDecoder.CreateAsync(stream);

                // Проход 1: Пробуем оригинальный размер (подходит для высокой детализации)
                using (var originalBmp = await decoder.GetSoftwareBitmapAsync(
                    Windows.Graphics.Imaging.BitmapPixelFormat.Bgra8,
                    Windows.Graphics.Imaging.BitmapAlphaMode.Premultiplied,
                    new Windows.Graphics.Imaging.BitmapTransform(),
                    Windows.Graphics.Imaging.ExifOrientationMode.RespectExifOrientation,
                    Windows.Graphics.Imaging.ColorManagementMode.ColorManageToSRgb))
                {
                    string res = DecodeWithBinarizers(originalBmp);
                    if (!string.IsNullOrEmpty(res)) return res;
                }

                // Масштабируем до различных целевых размеров для подавления шумов и смазов
                uint[] targets = new uint[] { 1200, 800, 600, 450 };
                uint origWidth = decoder.PixelWidth;
                uint origHeight = decoder.PixelHeight;

                foreach (uint targetSize in targets)
                {
                    if (origWidth <= targetSize && origHeight <= targetSize) continue;

                    var transform = new Windows.Graphics.Imaging.BitmapTransform();
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

                    using (var scaledBmp = await decoder.GetSoftwareBitmapAsync(
                        Windows.Graphics.Imaging.BitmapPixelFormat.Bgra8,
                        Windows.Graphics.Imaging.BitmapAlphaMode.Premultiplied,
                        transform,
                        Windows.Graphics.Imaging.ExifOrientationMode.RespectExifOrientation,
                        Windows.Graphics.Imaging.ColorManagementMode.ColorManageToSRgb))
                    {
                        string res = DecodeWithBinarizers(scaledBmp);
                        if (!string.IsNullOrEmpty(res)) return res;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[QR STREAM DECODE ERROR] {ex.Message}");
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
                        .Where(g => g.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                                     g.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    foreach (var subUrl in incomingSubscriptions)
                    {
                        _allProfiles.RemoveAll(p => string.Equals(p.SubscriptionGroup, subUrl, StringComparison.OrdinalIgnoreCase));
                    }

                    PopulateMetadata(newProfiles, text);
                    _allProfiles.AddRange(newProfiles);

                    UpdateGroupedUI();
                    await SaveProfilesAsync();
                    StatusText.Text = $"Импортировано {newProfiles.Count} серверов";
                }
                else
                {
                    StatusText.Text = "В импортированных данных не найдено профилей";
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

        private void PopulateMetadata(List<VlessProfile> profiles, string url)
        {
            foreach (var p in profiles)
            {
                p.LastUpdated = DateTime.Now;
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
            return $"vless://{p.Uuid}@{p.Address}:{p.Port}?type={p.Type}&security={p.Security}&sni={p.Sni}&pbk={p.PublicKey}&sid={p.ShortId}#{Uri.EscapeDataString(p.Name)}";
        }

        private string ReconstructJson(VlessProfile p)
        {
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
    }
}