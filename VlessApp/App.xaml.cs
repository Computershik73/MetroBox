using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks; // Добавлено для работы с Task
using Windows.ApplicationModel;
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

        protected override void OnLaunched(LaunchActivatedEventArgs e)
        {
            // Журнал начинается заново на каждый запуск: его отправляют целиком,
            // и разбирать склейку за все прошлые сессии невозможно.
            if (Window.Current.Content == null) AppLog.Reset();

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