using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using Windows.Storage;

namespace VlessVpnTask
{
    internal static class FileLog
    {
        public static bool Verbose;
        public static bool HexDump;

        private static BlockingCollection<string> _queue;
        private static System.Threading.Tasks.Task _worker;
        private static string _path;
        private static volatile bool _started;
        private static readonly object _initLock = new object();

        public static void Init()
        {
            lock (_initLock)
            {
                if (_started) return;

                try
                {
                    // System.IO по пути LocalFolder работает в UWP и быстрее WinRT-API.
                    _path = Path.Combine(ApplicationData.Current.LocalFolder.Path, "vpnlog.txt");
                }
                catch { _path = null; }

                // Читаем флаг подробного лога (как раньше).
                try
                {
                    var s = ApplicationData.Current.LocalSettings.Values;
                    if (s.TryGetValue("v_DebugLog", out object v) && v is bool b) Verbose = b;
                    if (s.TryGetValue("v_HexDump", out object h) && h is bool hb) HexDump = hb;
                }
                catch { }

                // Большая ёмкость + DropOldest-семантика вручную: писать в лог никогда
                // не должно блокировать VPN, даже если диск не успевает.
                _queue = new BlockingCollection<string>(new ConcurrentQueue<string>(), 20000);

                _worker = System.Threading.Tasks.Task.Factory.StartNew(
    WorkerLoop,
    System.Threading.CancellationToken.None,
    System.Threading.Tasks.TaskCreationOptions.LongRunning,
    System.Threading.Tasks.TaskScheduler.Default);

                _started = true;
            }
        }

        // НЕ блокирует: только кладёт строку в очередь и возвращается.
        public static void W(string msg)
        {
            if (!_started) { try { Init(); } catch { } }
            Enqueue(msg);
        }

        // Важные строки логируем всегда (даже при выключенном Verbose).
        public static void Important(string msg)
        {
            if (!_started) { try { Init(); } catch { } }
            Enqueue(msg);
        }

        private static void Enqueue(string msg)
        {
            var q = _queue;
            if (q == null) return;

            string line = DateTime.Now.ToString("HH:mm:ss.fff") + "  " + msg;

            // TryAdd с нулевым таймаутом — если очередь переполнена, СБРАСЫВАЕМ строку,
            // но НИКОГДА не ждём. Лог — диагностика, он не должен тормозить трафик.
            if (!q.TryAdd(line))
            {
                // выкидываем самые старые, освобождаем место, пробуем ещё раз (без блокировки)
                try { string _; for (int i = 0; i < 64 && q.TryTake(out _); i++) { } } catch { }
                q.TryAdd(line);
            }
        }

        private static void WorkerLoop()
        {
            var sb = new StringBuilder(8192);
            try
            {
                foreach (string first in _queue.GetConsumingEnumerable())
                {
                    sb.Clear();
                    sb.Append(first).Append("\r\n");

                    // Сгребаем всё, что уже накопилось, и пишем одной пачкой —
                    // меньше системных вызовов, выше пропускная способность.
                    string more;
                    int batch = 0;
                    while (batch < 500 && _queue.TryTake(out more))
                    {
                        sb.Append(more).Append("\r\n");
                        batch++;
                    }

                    FlushToDisk(sb.ToString());
                }
            }
            catch { /* поток-демон, тихо выходим при завершении процесса */ }
        }

        private static void FlushToDisk(string text)
        {
            if (_path == null || text.Length == 0) return;
            try
            {
                // Открываем-дописываем-закрываем: устойчиво к внезапному завершению процесса
                // (важно для фикса 691 — лог не теряется при ExitProcess).
                using (var fs = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite, 8192))
                using (var w = new StreamWriter(fs, new UTF8Encoding(false)))
                {
                    w.Write(text);
                    w.Flush();
                }
            }
            catch { /* диск занят/недоступен — пропускаем, трафик важнее лога */ }
        }
    }
}