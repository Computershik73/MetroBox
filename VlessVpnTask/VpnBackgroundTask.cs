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
        [DllImport("api-ms-win-core-processthreads-l1-1-0.dll")]
        private static extern uint GetCurrentProcessId();

        [DllImport("api-ms-win-core-processthreads-l1-1-0.dll")]
        private static extern void ExitProcess(uint uExitCode);

        private static readonly VlessVpnPlugin _plugin = new VlessVpnPlugin();
        private static readonly object _gate = new object();
        private static bool _wired;
        private static volatile bool _exiting;
        private static BackgroundTaskDeferral _deferral;

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            _exiting = false;
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
                FileLog.Important($"[BG TASK] Активация фоновой задачи VPN (PID {GetCurrentProcessId()}).");
            }
            catch { }

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

        // Единственная точка выхода.
        // 1) Синхронно гасит плагин (_channel.Stop() и сокеты).
        // 2) Завершение deferral выполняет асинхронно с задержкой 1250 мс вне RPC-потока RasMan,
        //    чтобы вызов Disconnect(channel) успел штатно вернуть S_OK в систему и служба
        //    RasMan чисто закрыла порт до сброса отсрочки UWP.
        // 3) Сброс _exiting = false позволяет повторному подключению подняться в том же процессе.
        private static void TearDownAndExit()
        {
            if (_exiting) return;
            _exiting = true;

            try { FileLog.Important("[BG TASK] TearDown: синхронно освобождаю ресурсы плагина..."); } catch { }

            int generation = System.Threading.Volatile.Read(ref VlessVpnPlugin.ConnectGeneration);
            var deferral = _deferral;
            _deferral = null;

            try { _plugin.Disconnect(null); } catch { }

            System.Threading.Tasks.Task.Run(async () =>
            {
                try { await System.Threading.Tasks.Task.Delay(1250); } catch { }

                // Если за время ожидания успело прийти новое подключение — отменяем завершение
                if (System.Threading.Volatile.Read(ref VlessVpnPlugin.ConnectGeneration) != generation || _plugin.IsConnected)
                {
                    try { FileLog.Important("[BG TASK] TearDown отменен: пришло новое подключение."); } catch { }
                    _exiting = false;
                    return;
                }

                try
                {
                    FileLog.Important($"[BG TASK] TearDown: завершаю deferral фоновой задачи (PID {GetCurrentProcessId()}).");
                }
                catch { }
                try { FileLog.Flush(); } catch { }

                try { deferral?.Complete(); } catch { }

                // Завершаем процесс фоновой задачи (ResourceGroup="tunnel"), чтобы он не остался
                // висеть в памяти в состоянии Suspend на W10M. Вызов ExitProcess(0)
                // гарантирует, что при следующем подключении служба RasMan запустит чистый хост
                // без 15-секундного таймаута и ошибки RAS 691.
                try
                {
                    FileLog.Important($"[BG TASK] TearDown: завершаю процесс через ExitProcess (PID {GetCurrentProcessId()}).");
                    FileLog.Flush();
                    ExitProcess(0);
                }
                catch (Exception ex)
                {
                    try { FileLog.Important($"[BG TASK] ExitProcess не удался: {ex.Message}"); } catch { }
                }
                _exiting = false;
            });
        }
    }
}