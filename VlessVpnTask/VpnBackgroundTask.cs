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

            // Запоминаем, какое подключение гасим и чья это отсрочка: если за время
            // ожидания придёт новое подключение, выходить будет нельзя.
            int generation = System.Threading.Volatile.Read(ref VlessVpnPlugin.ConnectGeneration);
            var deferral = _deferral;

            // 1) синхронно освобождаем ресурсы плагина (сокеты, движок, loopback)
            try { _plugin.Disconnect(null); } catch { }

            // 2) выход уводим в сторону от потока, на котором система вызвала Disconnect:
            //    пока мы на нём спим, платформа ждёт возврата из собственного вызова.
            //
            //    И deferral завершаем ПОСЛЕДНИМ. Complete() — это разрешение системе убить
            //    процесс, а до него нужно успеть закрыть сокеты и дописать журнал. Прежний
            //    порядок (сначала Complete, потом ожидание) процесс переживал не всегда: в
            //    журнале телефона видно, как запись обрывается на середине Disconnect, и
            //    следующее подключение падало с ошибкой 691 — ресурсы туннеля остались за
            //    убитым процессом.
            System.Threading.Tasks.Task.Run(async () =>
            {
                try { await System.Threading.Tasks.Task.Delay(1250); } catch { }

                // Пока процесс дозакрывался, система пришла с новым подключением — в тот
                // же процесс. Выход сейчас убил бы свежий туннель на середине подъёма.
                // Туннель закрыли приложением и сразу открыли снова — ровно так и бывает.
                if (System.Threading.Volatile.Read(ref VlessVpnPlugin.ConnectGeneration) != generation)
                {
                    try { FileLog.Important("[BG TASK] TearDown отменён: пока процесс закрывался, пришло новое подключение."); } catch { }

                    // Свою отсрочку закрываем, только если она уже не нужна новому сеансу.
                    if (!ReferenceEquals(deferral, _deferral)) { try { deferral?.Complete(); } catch { } }
                    _exiting = false;
                    return;
                }

                try { FileLog.Important("[BG TASK] TearDown: отпускаю задачу и выхожу."); } catch { }

                try { deferral?.Complete(); } catch { }
                if (ReferenceEquals(deferral, _deferral)) _deferral = null;

                try { Windows.ApplicationModel.Core.CoreApplication.Exit(); }
                catch (Exception ex)
                {
                    try { FileLog.Important($"[BG TASK] CoreApplication.Exit не удался: {ex.Message}"); } catch { }
                }
            });
        }
    }
}