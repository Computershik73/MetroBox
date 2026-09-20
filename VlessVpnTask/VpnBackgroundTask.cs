using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Windows.Networking.Vpn;

namespace VlessVpnTask
{
    public sealed class VpnBackgroundTask : IBackgroundTask
    {
        

        private static readonly VlessVpnPlugin _plugin = new VlessVpnPlugin();
        private static readonly object _gate = new object();
        private static bool _wired;
        private static volatile bool _exiting;
        private static BackgroundTaskDeferral _deferral;

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            FileLog.Init();

            // Deferral берём на КАЖДУЮ активацию. Завершаем его либо при чистом выходе
            // (TearDownAndExit), либо если событие обработалось синхронно с ошибкой.
            _deferral = taskInstance.GetDeferral();
            taskInstance.Canceled += OnCanceled;

            // Подписку на Disconnected делаем один раз на процесс.
            lock (_gate)
            {
                if (!_wired)
                {
                    _plugin.Disconnected += OnPluginDisconnected;

                    // Событие срабатывает не в момент сбоя, а когда сборщик мусора забирает
                    // задачу, чью ошибку никто не прочитал. В движке полно задач «запустили
                    // и забыли», и любой оборванный сервером поток рано или поздно всплывает
                    // здесь. Раньше на это гасился весь туннель вместе с процессом: связь
                    // внезапно умирала, и приходилось перезапускать приложение. Теперь
                    // исключение записывается целиком, а туннель продолжает работать.
                    System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, e) =>
                    {
                        try { e.SetObserved(); } catch { }
                        try
                        {
                            var ex = e.Exception?.GetBaseException();
                            FileLog.Important("[BG TASK] Непрочитанная ошибка фоновой задачи (туннель продолжает работу): "
                                              + (ex?.ToString() ?? "<нет объекта исключения>"));
                        }
                        catch { }
                    };

                    // Глобального перехвата для фоновой задачи в UWP нет: AppDomain здесь
                    // недоступен, а Application.UnhandledException живёт только в приложении.
                    // Настоящие сбои плагина ловятся в его собственных ветках ошибок.

                    _wired = true;
                }
            }

            Debug.WriteLine("[BG TASK] Активация фоновой задачи VPN.");

            try
            {
                // ProcessEventAsync здесь возвращает void: метод сам запускает цикл событий,
                // а процесс держится живым за счёт удержания deferral. Сессию завершают
                // OnPluginDisconnected (штатное/ошибочное отключение) и OnCanceled (Cancel).
                VpnChannel.ProcessEventAsync(_plugin, taskInstance.TriggerDetails);
            }
            catch (Exception ex)
            {
                FileLog.Important($"[BG TASK ERROR] ProcessEventAsync кинул исключение: {ex.Message}");
                TearDownAndExit();
            }
        }

        private void OnCanceled(IBackgroundTaskInstance sender, BackgroundTaskCancellationReason reason)
        {
            FileLog.Important($"[BG TASK] Отмена задачи системой, причина: {reason}");
            try { _plugin.Disconnect(null); } catch { }
            TearDownAndExit();
        }

        private void OnPluginDisconnected()
        {
            FileLog.Important("[BG TASK] Плагин сообщил об отключении — завершаем процесс.");
            TearDownAndExit();
        }

        // Единственная точка выхода. Гарантирует, что процесс умрёт чисто и
        // освободит ResourceGroup 'tunnel' + loopback-транспорт, чтобы СЛЕДУЮЩЕЕ
        // подключение поднялось без ошибки 691.
        private static void TearDownAndExit()
        {
            if (_exiting) return;
            _exiting = true;

            try { FileLog.Important("[BG TASK] TearDown: гашу плагин."); } catch { }

            // 1) синхронно освобождаем ресурсы плагина (сокеты, движок, loopback)
            try { _plugin.Disconnect(null); } catch { }

            // 2) завершаем deferral — штатный сигнал "задача закончена"
            try { _deferral?.Complete(); } catch { }
            _deferral = null;

            // дать асинхронному логу дописать хвост и сокетам закрыться
            try { System.Threading.Tasks.Task.Delay(1250).Wait(); } catch { }

            try { Windows.ApplicationModel.Core.CoreApplication.Exit(); }
            
            catch (Exception ex)
            {
                try { FileLog.Important($"[BG TASK] CoreApplication.Exit не удался: {ex.Message}"); } catch { }
            }
        }
    }
}