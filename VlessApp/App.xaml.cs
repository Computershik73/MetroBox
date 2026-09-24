using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks; // Добавлено для работы с Task
using Windows.ApplicationModel;
using Windows.Storage;
using Windows.ApplicationModel.Activation;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

namespace VlessApp
{
    sealed partial class App : Application
    {
        public App()
        {
            this.InitializeComponent();
            this.Suspending += OnSuspending;

            // Падение приложения иначе видно только в системном журнале ошибок, и то
            // одним кодом 0x80131500 без текста. Записываем исключение к себе, чтобы
            // пользователь мог прислать его вместе с остальным журналом.
            this.UnhandledException += (s, e) =>
            {
                try
                {
                    AppLog.W("──── НЕОБРАБОТАННОЕ ИСКЛЮЧЕНИЕ ────");
                    AppLog.W("  " + e.Message);
                    AppLog.W("  " + (e.Exception == null ? "<нет объекта исключения>" : e.Exception.ToString()));
                }
                catch { }
            };

            TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                try
                {
                    AppLog.W("──── ИСКЛЮЧЕНИЕ В ФОНОВОЙ ЗАДАЧЕ ────");
                    AppLog.W("  " + e.Exception);
                }
                catch { }
                e.SetObserved();
            };
        }

        // Туннель живёт в отдельном процессе и о закрытии приложения ничего не знает:
        // на телефоне закрытие крестиком в переключателе задач не приносит приложению
        // никакого события — к этому моменту оно уже приостановлено, и система его
        // просто убивает. Поэтому приложение всю свою жизнь держит этот файл открытым
        // монопольно, а туннель время от времени проверяет, не освободился ли он.
        // Освобождается файл только со смертью процесса — это и есть сигнал.
        internal const string AliveLockName = "app.alive";
        private static FileStream _aliveLock;

        private static async void HoldAliveLock()
        {
            if (_aliveLock != null) return;
            string path = Path.Combine(ApplicationData.Current.LocalFolder.Path, AliveLockName);

            // Туннель может как раз в этот миг проверять файл — тогда повторяем.
            for (int i = 0; i < 10 && _aliveLock == null; i++)
            {
                try { _aliveLock = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
                catch { await Task.Delay(200); }
            }
            if (_aliveLock == null)
                AppLog.W("[ЖИЗНЬ] Не удалось занять app.alive — туннель не узнает о закрытии приложения.");
        }

        protected override void OnLaunched(LaunchActivatedEventArgs e)
        {
            // Журнал начинается заново на каждый запуск: его отправляют целиком,
            // и разбирать склейку за все прошлые сессии невозможно.
            if (Window.Current.Content == null) AppLog.Reset();
            HoldAliveLock();

            Frame rootFrame = Window.Current.Content as Frame;

            if (rootFrame == null)
            {
                rootFrame = new Frame();
                rootFrame.NavigationFailed += OnNavigationFailed;

                if (e.PreviousExecutionState == ApplicationExecutionState.Terminated)
                {
                    //TODO: Загрузить состояние из ранее приостановленного приложения
                }

                Window.Current.Content = rootFrame;
            }

            if (e.PrelaunchActivated == false)
            {
                if (rootFrame.Content == null)
                {
                    rootFrame.Navigate(typeof(MainPage), e.Arguments);
                }
                Window.Current.Activate();
            }
        }

        void OnNavigationFailed(object sender, NavigationFailedEventArgs e)
        {
            throw new Exception("Failed to load Page " + e.SourcePageType.FullName);
        }

        // ПРИНУДИТЕЛЬНОЕ ОТКЛЮЧЕНИЕ VPN ПРИ ВЫХОДЕ ПОЛЬЗОВАТЕЛЯ ИЗ ПРИЛОЖЕНИЯ
        private void OnSuspending(object sender, SuspendingEventArgs e)
        {
            var deferral = e.SuspendingOperation.GetDeferral();
            // Позволяем VPN-клиенту продолжать работу в фоне при сворачивании приложения
            deferral.Complete();
        }
    }
}