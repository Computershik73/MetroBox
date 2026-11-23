using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.Core;
using Windows.Foundation;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.UI.Core;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Automation.Peers;
using Windows.UI.Xaml.Automation.Provider;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Imaging;

namespace VlessApp
{
    /// <summary>
    /// Autonomous Agent Remote Control Bridge for MetroBox.
    /// Enables AI agents and headless test runners to execute clicks/taps, select servers,
    /// toggle VPN connections, capture high-resolution screen images, and query runtime status.
    /// </summary>
    public class AgentControlBridge
    {
        private static AgentControlBridge _instance;
        private readonly MainPage _mainPage;
        private bool _isRunning;

        private const string CmdFileName = "control.json";
        private const string ResultFileName = "control_result.json";
        private const string ScreenshotFileName = "screenshot.png";

        public static void Start(MainPage mainPage)
        {
            if (_instance != null) return;
            _instance = new AgentControlBridge(mainPage);
            _instance.Run();
        }

        private AgentControlBridge(MainPage mainPage)
        {
            _mainPage = mainPage;
        }

        private async void Run()
        {
            _isRunning = true;
            AppLog.W("[AGENT BRIDGE] Remote Control Bridge started (listening for control.json).");

            var localFolder = ApplicationData.Current.LocalFolder;

            while (_isRunning)
            {
                try
                {
                    IStorageItem item = await localFolder.TryGetItemAsync(CmdFileName);
                    if (item is StorageFile file)
                    {
                        string content = null;
                        using (var stream = await file.OpenReadAsync())
                        using (var reader = new StreamReader(stream.AsStreamForRead(), Encoding.UTF8))
                        {
                            content = await reader.ReadToEndAsync();
                        }

                        if (!string.IsNullOrWhiteSpace(content))
                        {
                            AppLog.W($"[AGENT BRIDGE] Processing command: {content.Trim()}");
                            string responseJson = await ProcessCommandAsync(content);

                            // Write result file
                            var resFile = await localFolder.CreateFileAsync(ResultFileName, CreationCollisionOption.ReplaceExisting);
                            using (var outStream = await resFile.OpenAsync(FileAccessMode.ReadWrite))
                            using (var writer = new StreamWriter(outStream.AsStreamForWrite(), Encoding.UTF8))
                            {
                                await writer.WriteAsync(responseJson);
                                await writer.FlushAsync();
                            }

                            // Delete incoming command file
                            await file.DeleteAsync(StorageDeleteOption.PermanentDelete);
                            AppLog.W("[AGENT BRIDGE] Command finished, response saved.");
                        }
                    }
                }
                catch (Exception ex)
                {
                    AppLog.W($"[AGENT BRIDGE] Loop warning: {ex.Message}");
                }

                await Task.Delay(250);
            }
        }

        private async Task<string> ProcessCommandAsync(string json)
        {
            string cmdId = "";
            string action = "";
            int x = 0;
            int y = 0;
            string name = "";
            string address = "";
            int index = -1;

            try
            {
                cmdId = ExtractJsonString(json, "id");
                action = ExtractJsonString(json, "action").ToLowerInvariant();
                x = ExtractJsonInt(json, "x", 0);
                y = ExtractJsonInt(json, "y", 0);
                name = ExtractJsonString(json, "name");
                address = ExtractJsonString(json, "address");
                index = ExtractJsonInt(json, "index", -1);
            }
            catch (Exception ex)
            {
                return CreateResponseJson(cmdId, "error", $"JSON parse error: {ex.Message}");
            }

            var tcs = new TaskCompletionSource<string>();

            await _mainPage.Dispatcher.RunAsync(CoreDispatcherPriority.Normal, async () =>
            {
                try
                {
                    switch (action)
                    {
                        case "tap":
                        case "click":
                            string tapResult = await HandleTapAsync(x, y);
                            tcs.SetResult(tapResult);
                            break;

                        case "select_server":
                            string selectResult = HandleSelectServer(name, address, index);
                            tcs.SetResult(selectResult);
                            break;

                        case "connect":
                            _mainPage.TriggerConnect();
                            tcs.SetResult(CreateResponseJson(cmdId, "ok", "Connect triggered",
                                $"\"status\":\"{EscapeJson(_mainPage.GetCurrentStatus())}\",\"is_connected\":{(_mainPage.IsConnected() ? "true" : "false")}"));
                            break;

                        case "disconnect":
                            _mainPage.TriggerDisconnect();
                            tcs.SetResult(CreateResponseJson(cmdId, "ok", "Disconnect triggered",
                                $"\"status\":\"{EscapeJson(_mainPage.GetCurrentStatus())}\",\"is_connected\":{(_mainPage.IsConnected() ? "true" : "false")}"));
                            break;

                        case "screenshot":
                            string ssResult = await HandleScreenshotAsync(cmdId);
                            tcs.SetResult(ssResult);
                            break;

                        case "status":
                            var curProf = _mainPage.GetSelectedProfile();
                            string profName = curProf != null ? EscapeJson(curProf.Name) : "";
                            string profAddr = curProf != null ? EscapeJson(curProf.Address) : "";
                            int profPort = curProf != null ? curProf.Port : 0;
                            string extra = string.Format(
                                "\"selected_profile\":\"{0}\",\"selected_address\":\"{1}\",\"selected_port\":{2},\"vpn_status\":\"{3}\",\"is_connected\":{4},\"total_profiles\":{5}",
                                profName, profAddr, profPort, EscapeJson(_mainPage.GetCurrentStatus()), _mainPage.IsConnected() ? "true" : "false", _mainPage.GetAllProfiles().Count
                            );
                            tcs.SetResult(CreateResponseJson(cmdId, "ok", "Status report", extra));
                            break;

                        default:
                            tcs.SetResult(CreateResponseJson(cmdId, "error", $"Unknown action '{action}'"));
                            break;
                    }
                }
                catch (Exception ex)
                {
                    AppLog.W($"[AGENT BRIDGE] Action '{action}' exception: {ex}");
                    tcs.SetResult(CreateResponseJson(cmdId, "error", ex.Message));
                }
            });

            return await tcs.Task;
        }

        private async Task<string> HandleTapAsync(int x, int y)
        {
            var pt = new Point(x, y);
            var hitElements = VisualTreeHelper.FindElementsInHostCoordinates(pt, _mainPage).ToList();

            string hitInfo = "none";
            string invokedControl = "";

            if (hitElements.Count > 0)
            {
                var names = hitElements.Take(5).Select(e =>
                {
                    var fe = e as FrameworkElement;
                    return (fe != null && !string.IsNullOrEmpty(fe.Name)) ? $"{e.GetType().Name}#{fe.Name}" : e.GetType().Name;
                });
                hitInfo = string.Join(" > ", names);

                // Find first interactive control
                foreach (var elem in hitElements)
                {
                    if (elem is Button btn)
                    {
                        invokedControl = $"Button#{btn.Name}";
                        btn.Focus(FocusState.Programmatic);
                        var peer = new ButtonAutomationPeer(btn);
                        var invoke = peer.GetPattern(PatternInterface.Invoke) as IInvokeProvider;
                        if (invoke != null)
                        {
                            invoke.Invoke();
                        }
                        else
                        {
                            btn.Command?.Execute(btn.CommandParameter);
                        }
                        break;
                    }
                    if (elem is ToggleSwitch ts)
                    {
                        invokedControl = $"ToggleSwitch#{ts.Name}";
                        ts.IsOn = !ts.IsOn;
                        break;
                    }
                    if (elem is FrameworkElement fe && fe.DataContext is VlessProfile prof)
                    {
                        invokedControl = $"VlessProfile#{prof.Name}";
                        _mainPage.TriggerSelectProfile(prof);
                        break;
                    }
                    if (elem is ListViewItem lvi)
                    {
                        invokedControl = "ListViewItem";
                        lvi.IsSelected = true;
                        if (lvi.Content is VlessProfile p)
                        {
                            _mainPage.TriggerSelectProfile(p);
                        }
                        break;
                    }
                }
            }

            await Task.Yield();
            AppLog.W($"[AGENT BRIDGE] Tap ({x}, {y}) -> hit: {hitInfo}, invoked: {invokedControl}");

            string extra = string.Format("\"x\":{0},\"y\":{1},\"hit\":\"{2}\",\"invoked\":\"{3}\"",
                x, y, EscapeJson(hitInfo), EscapeJson(invokedControl));

            return CreateResponseJson("", "ok", "Tap executed", extra);
        }

        private string HandleSelectServer(string name, string address, int index)
        {
            var profiles = _mainPage.GetAllProfiles();
            if (profiles == null || profiles.Count == 0)
            {
                return CreateResponseJson("", "error", "No profiles loaded in application");
            }

            VlessProfile target = null;

            if (index >= 0 && index < profiles.Count)
            {
                target = profiles[index];
            }
            else if (!string.IsNullOrEmpty(address))
            {
                target = profiles.FirstOrDefault(p => string.Equals(p.Address, address, StringComparison.OrdinalIgnoreCase));
            }
            else if (!string.IsNullOrEmpty(name))
            {
                target = profiles.FirstOrDefault(p => p.Name != null && p.Name.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            if (target == null)
            {
                return CreateResponseJson("", "error", $"Server matching Name='{name}', Address='{address}', Index={index} not found");
            }

            _mainPage.TriggerSelectProfile(target);
            AppLog.W($"[AGENT BRIDGE] Server selected: {target.Name} ({target.Address}:{target.Port})");

            string extra = string.Format("\"selected_name\":\"{0}\",\"selected_address\":\"{1}\",\"selected_port\":{2}",
                EscapeJson(target.Name), EscapeJson(target.Address), target.Port);

            return CreateResponseJson("", "ok", "Server selected successfully", extra);
        }

        private async Task<string> HandleScreenshotAsync(string cmdId)
        {
            var rtb = new RenderTargetBitmap();
            await rtb.RenderAsync(_mainPage);

            var pixelBuffer = await rtb.GetPixelsAsync();
            byte[] pixels = new byte[pixelBuffer.Length];
            using (var reader = DataReader.FromBuffer(pixelBuffer))
            {
                reader.ReadBytes(pixels);
            }

            var localFolder = ApplicationData.Current.LocalFolder;
            var file = await localFolder.CreateFileAsync(ScreenshotFileName, CreationCollisionOption.ReplaceExisting);

            using (var stream = await file.OpenAsync(FileAccessMode.ReadWrite))
            {
                var encoder = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
                encoder.SetPixelData(
                    BitmapPixelFormat.Bgra8,
                    BitmapAlphaMode.Premultiplied,
                    (uint)rtb.PixelWidth,
                    (uint)rtb.PixelHeight,
                    96, 96,
                    pixels);
                await encoder.FlushAsync();
            }

            AppLog.W($"[AGENT BRIDGE] Screenshot saved: {rtb.PixelWidth}x{rtb.PixelHeight} ({pixels.Length} bytes)");

            string extra = string.Format("\"width\":{0},\"height\":{1},\"file\":\"{2}\"",
                rtb.PixelWidth, rtb.PixelHeight, ScreenshotFileName);

            return CreateResponseJson(cmdId, "ok", "Screenshot captured", extra);
        }

        private static string CreateResponseJson(string id, string status, string message, string extraFields = null)
        {
            var sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"id\":\"{0}\",", EscapeJson(id));
            sb.AppendFormat("\"status\":\"{0}\",", EscapeJson(status));
            sb.AppendFormat("\"message\":\"{0}\"", EscapeJson(message));
            if (!string.IsNullOrEmpty(extraFields))
            {
                sb.Append(",");
                sb.Append(extraFields);
            }
            sb.Append("}");
            return sb.ToString();
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", "\\n");
        }

        private static string ExtractJsonString(string json, string key)
        {
            string pattern = $"\"{key}\"\\s*:\\s*\"([^\"]*)\"";
            var m = System.Text.RegularExpressions.Regex.Match(json, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            return m.Success ? m.Groups[1].Value : "";
        }

        private static int ExtractJsonInt(string json, string key, int defaultValue)
        {
            string pattern = $"\"{key}\"\\s*:\\s*(-?\\d+)";
            var m = System.Text.RegularExpressions.Regex.Match(json, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success && int.TryParse(m.Groups[1].Value, out int val))
            {
                return val;
            }
            return defaultValue;
        }
    }
}
