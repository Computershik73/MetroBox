using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    // Движок AmneziaWG. В отличие от VLESS-пути здесь НЕ нужен пользовательский TCP-стек:
    // WireGuard работает на уровне IP, поэтому пакет от ОС просто шифруется и уходит в UDP,
    // а расшифрованный пакет отдаётся обратно в ОС. Наружу выставлен тот же набор методов,
    // что и у NatEngine, чтобы плагин мог работать с любым из движков единообразно.
    internal sealed class AwgEngine
    {
        // WireGuard: инициатор переустанавливает ключи через 120 с после установки сессии.
        private static readonly TimeSpan RekeyAfter = TimeSpan.FromSeconds(120);
        // WireGuard считает сессию мёртвой через 180 с; после этого сервер её уже забыл,
        // и перевыпускать ключи поверх неё бесполезно — нужен новый сокет и новый хендшейк.
        private static readonly TimeSpan DeadAfter = TimeSpan.FromSeconds(150);
        private const int HandshakeTimeoutMs = 5000;
        private const int HandshakeAttempts = 3;
        // 4096 пакетов — это больше секунды буфера и ~6 МБ памяти, чего фоновой задаче
        // на телефоне никто не даст. 1024 хватает с запасом.
        private const int MaxOsRxQueue = 1024;

        private readonly AwgConfig _cfg;
        private AwgTunnel _tunnel;
        private AwgTunnel _prevTunnel;   // предыдущая сессия — переживает перевыпуск ключей

        private DatagramSocket _socket;

        // Отправка. Строгая очередь с одним насосом оказалась МЕДЛЕННЕЕ (5 Мбит/с против
        // 10): каждая датаграмма получала лишний переход «очередь → сигнал → насос», а
        // выигрыша от сохранения порядка нет — окно защиты от повторов в WireGuard 64
        // пакета, и умеренная перестановка там штатная. Поэтому вернулись к прямой
        // отправке под замком, но с ограничением числа пакетов «в полёте», чтобы очередь
        // задач не росла бесконечно и не съедала память фоновой задачи.
        private int _txInFlight;
        private const int MaxTxInFlight = 256;

        private TaskCompletionSource<byte[]> _handshakeWaiter;
        private readonly object _waiterLock = new object();

        private Timer _rekeyTimer;
        private Timer _keepaliveTimer;
        private volatile bool _stopped;
        private int _rekeyBusy;

        private Timer _drainTimer;
        private Timer _statsTimer;
        private DateTime _lastRxUtc = DateTime.UtcNow;
        private string _serverIp;
        private string _serverCanonical;   // адрес сервера в том же виде, что даёт HostName
        private int _foreignLogged;

        private int _osRxCount;
        private int _triggerPending;
        private long _txPackets, _rxPackets, _txBytes, _rxBytes;

        // Счётчики для диагностики: без них причину падения скорости приходится угадывать.
        private long _sendTicks, _sendCalls;
        private int _txDropped, _rxDropped;
        private long _prevTxBytes, _prevRxBytes, _prevSendTicks, _prevSendCalls;

        public ConcurrentQueue<byte[]> OsRxQueue { get; } = new ConcurrentQueue<byte[]>();
        public Action TriggerDecapsulate { get; set; }
        public VpnChannel Channel { get; set; }

        public bool Established { get { var t = _tunnel; return t != null && t.Established; } }

        public AwgEngine(AwgConfig cfg) { _cfg = cfg; }

        // ===================== подъём туннеля =====================

        public async Task<bool> StartAsync(string serverIp)
        {
            try
            {
                _serverIp = serverIp;
                _lastRxUtc = DateTime.UtcNow;
                _socket = new DatagramSocket();
                _socket.MessageReceived += OnDatagram;

                var remote = new HostName(serverIp);
                string port = _cfg.EndpointPort.ToString();
                // Канонизируем через тот же HostName, что и входящий адрес, — иначе
                // сравнение строк могло бы разойтись на форматировании.
                _serverCanonical = remote.CanonicalName;
                Volatile.Write(ref _foreignLogged, 0);

                if (!await SetupSocketAsync(remote, port))
                    return false;

                if (!await DoHandshakeAsync()) return false;

                // Страховка приёма. Триггер Decapsulate одноразовый: пока ОС не позвала нас,
                // повторно мы его не шлём. Если он потеряется — а он теряется — принятые
                // пакеты навсегда зависают в очереди, туннель «отваливается», а память
                // фоновой задачи забивается до сноса процесса. У NatEngine такой таймер
                // есть с самого начала, у AWG его не было.
                _drainTimer = new Timer(_ =>
                {
                    if (!_stopped && Volatile.Read(ref _osRxCount) > 0)
                    {
                        try { TriggerDecapsulate?.Invoke(); } catch { }
                    }
                }, null, 100, 100);

                _statsTimer = new Timer(_ => LogRates(), null, 10000, 10000);

                _rekeyTimer = new Timer(_ => { var _ignore = RekeyIfNeededAsync(); }, null, 15000, 15000);
                if (_cfg.PersistentKeepalive > 0)
                {
                    int ms = _cfg.PersistentKeepalive * 1000;
                    _keepaliveTimer = new Timer(_ => { var _ignore = SendKeepaliveAsync(); }, null, ms, ms);
                }
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[AWG ERROR] Старт: {ex.Message}");
                return false;
            }
        }

        // ПРОВЕРЕНО НА УСТРОЙСТВЕ И ОТКАЗАЛИСЬ: четыре потока вывода через
        // GetOutputStreamAsync давали каждому свой ИСХОДНЫЙ ПОРТ. Хендшейк (он идёт по
        // нулевому потоку) проходил, а дальше сервер видел пакеты с новых портов, считал,
        // что пир переехал, и переносил его endpoint — ответы уходили в никуда. Трафик
        // вставал полностью. WireGuard требует ровно один исходный порт на пир, поэтому
        // отправка здесь принципиально последовательная.
        //
        // Задержку вместо этого срезаем иначе: пишем прямо в поток вывода сокета, без
        // DataWriter — он добавляет ещё одну буферизацию и ещё один асинхронный слой.
        private IOutputStream _out;
        private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);
        private readonly bool _connectedMode = true;

        private async Task<bool> SetupSocketAsync(HostName remote, string port)
        {
            try
            {
                // Привязка к физическому адаптеру обязательна: иначе сокет уйдёт
                // в наш же туннель.
                if (VlessVpnPlugin.PhysicalIp != null)
                    await _socket.ConnectAsync(new EndpointPair(VlessVpnPlugin.PhysicalIp, "", remote, port));
                else
                    await _socket.ConnectAsync(remote, port);

                _out = _socket.OutputStream;
                FileLog.Important($"[AWG] UDP к {remote.RawName}:{port} открыт " +
                                  $"(через {VlessVpnPlugin.PhysicalIp?.RawName ?? "<без привязки>"}).");
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[AWG ERROR] Не удалось открыть UDP: {ex.Message}");
                return false;
            }
        }

        private async Task<bool> DoHandshakeAsync()
        {
            for (int attempt = 1; attempt <= HandshakeAttempts && !_stopped; attempt++)
            {
                var tunnel = new AwgTunnel(_cfg);

                var waiter = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
                lock (_waiterLock) _handshakeWaiter = waiter;

                try
                {
                    // Сначала «подписные» датаграммы I1..I5 (если заданы), затем мусорные Jc —
                    // тот же порядок, что и в senko. Это и есть маскировка Amnezia:
                    // наблюдателю начало сессии не похоже на WireGuard.
                    byte[][] sigs = tunnel.BuildSignaturePackets();
                    if (sigs.Length > 0)
                    {
                        foreach (var s in sigs) await SendRawAsync(s, 0);
                        FileLog.Important($"[AWG] Отправлено подписных пакетов I1..I5: {sigs.Length}.");
                    }

                    byte[][] junk = tunnel.BuildJunkPackets();
                    if (junk.Length > 0)
                    {
                        foreach (var j in junk) await SendRawAsync(j, 0);
                        FileLog.Important($"[AWG] Отправлено мусорных пакетов: {junk.Length} ({_cfg.Jmin}..{_cfg.Jmax} байт).");
                    }

                    byte[] init = tunnel.BuildInitiation();
                    await SendRawAsync(init, 0);
                    FileLog.Important($"[AWG] Инициация отправлена ({init.Length} байт), попытка {attempt}/{HandshakeAttempts}. Жду ответ...");

                    var done = await Task.WhenAny(waiter.Task, Task.Delay(HandshakeTimeoutMs));
                    if (done != waiter.Task)
                    {
                        FileLog.Important($"[AWG] Таймаут ответа на инициацию ({HandshakeTimeoutMs} мс).");
                        continue;
                    }

                    byte[] resp = await waiter.Task;
                    if (resp != null && tunnel.ConsumeResponse(resp, resp.Length))
                    {
                        _prevTunnel = _tunnel;
                        _tunnel = tunnel;
                        FileLog.Important("[AWG] === ТУННЕЛЬ AMNEZIAWG ПОДНЯТ ===");
                        return true;
                    }
                    FileLog.Important("[AWG] Ответ не прошёл проверку (ключи/PresharedKey/обфускация?).");
                }
                catch (Exception ex)
                {
                    FileLog.Important($"[AWG ERROR] Хендшейк, попытка {attempt}: {ex.Message}");
                }
                finally
                {
                    lock (_waiterLock) _handshakeWaiter = null;
                }
            }
            return false;
        }

        // Перевыпуск ключей: WireGuard требует нового хендшейка примерно раз в 2 минуты.
        // Здесь же сторожевой контроль: если от сервера давно ничего нет, перевыпускать
        // ключи бессмысленно — сессии на той стороне уже нет, нужен полный пересбор.
        private async Task RekeyIfNeededAsync()
        {
            if (_stopped) return;
            var t = _tunnel;
            if (t == null || !t.Established) return;
            if (Interlocked.Exchange(ref _rekeyBusy, 1) == 1) return;

            try
            {
                var now = DateTime.UtcNow;
                if (now - _lastRxUtc > DeadAfter)
                {
                    FileLog.Important($"[AWG] Тишина от сервера {(int)(now - _lastRxUtc).TotalSeconds} с — пересобираю туннель целиком.");
                    string ip = _serverIp;
                    if (!string.IsNullOrEmpty(ip))
                    {
                        if (await RestartAsync(ip)) FileLog.Important("[AWG] Туннель пересобран.");
                        else FileLog.Important("[AWG] Пересобрать не удалось, попробую снова.");
                    }
                    return;
                }

                if (now - t.EstablishedAtUtc < RekeyAfter) return;

                FileLog.Important("[AWG] Плановый перевыпуск ключей...");
                // Старый туннель продолжает работать, пока новый не поднимется, — разрыва нет.
                if (!await DoHandshakeAsync())
                    FileLog.Important("[AWG] Перевыпуск не удался, продолжаю на старых ключах.");
            }
            catch (Exception ex) { FileLog.Important($"[AWG ERROR] Перевыпуск: {ex.Message}"); }
            finally { Volatile.Write(ref _rekeyBusy, 0); }
        }

        private async Task SendKeepaliveAsync()
        {
            var t = _tunnel;
            if (_stopped || t == null || !t.Established) return;
            try
            {
                byte[] ka = t.Seal(new byte[0], 0);   // пустой пакет = keepalive
                if (ka != null) await SendRawAsync(ka);
            }
            catch { }
        }

        // ===================== ввод-вывод =====================

        // Отправка «в фоне» для пакетов с данными: ждать здесь нельзя, Encapsulate зовёт ОС.
        private void Enqueue(byte[] data)
        {
            if (data == null || data.Length == 0 || _stopped) return;
            if (Interlocked.Increment(ref _txInFlight) > MaxTxInFlight)
            {
                // Канал не успевает — отбрасываем, как это делает любой роутер.
                Interlocked.Decrement(ref _txInFlight);
                Interlocked.Increment(ref _txDropped);
                return;
            }
            var _ignore = SendAndReleaseAsync(data);
        }

        private async Task SendAndReleaseAsync(byte[] data)
        {
            try { await SendRawAsync(data); }
            finally { Interlocked.Decrement(ref _txInFlight); }
        }

        // Параметр lane остался от эксперимента с параллельными потоками и больше ничего
        // не значит: отправка последовательная, иначе сервер теряет пира (см. выше).
        private async Task SendRawAsync(byte[] data, int lane = -1)
        {
            if (data == null || data.Length == 0 || _stopped) return;

            await _writeLock.WaitAsync();
            try
            {
                var os = _out;
                if (os == null) return;
                long t0 = Stopwatch.GetTimestamp();
                await os.WriteAsync(data.AsBuffer());
                Interlocked.Add(ref _sendTicks, Stopwatch.GetTimestamp() - t0);
                Interlocked.Increment(ref _sendCalls);
            }
            catch (Exception ex) { FileLog.W($"[AWG] Ошибка отправки: {ex.Message}"); }
            finally { _writeLock.Release(); }
        }

        private void OnDatagram(DatagramSocket sender, DatagramSocketMessageReceivedEventArgs args)
        {
            if (_stopped) return;
            try
            {
                // Сокет теперь просто привязан, а не подключён, поэтому чужие датаграммы
                // отсеиваем сами: обрабатываем только то, что пришло от нашего сервера.
                if (!_connectedMode && _serverCanonical != null)
                {
                    var from = args.RemoteAddress;
                    if (from == null || !string.Equals(from.CanonicalName, _serverCanonical, StringComparison.OrdinalIgnoreCase))
                    {
                        // Один раз пишем в лог: если вдруг адреса форматируются по-разному,
                        // молчаливо отброшенный трафик было бы невозможно объяснить.
                        if (Interlocked.Exchange(ref _foreignLogged, 1) == 0)
                            FileLog.Important($"[AWG] Датаграмма не от сервера: {from?.CanonicalName ?? "<нет адреса>"} (ждём {_serverCanonical}).");
                        return;
                    }
                }

                byte[] data;
                using (var reader = args.GetDataReader())
                {
                    uint len = reader.UnconsumedBufferLength;
                    if (len == 0) return;
                    data = new byte[len];
                    reader.ReadBytes(data);
                }
                _lastRxUtc = DateTime.UtcNow;

                // Ответ на инициацию узнаём строго: точная длина и номер типа из H2.
                // Иначе при перевыпуске ключей обычный пакет с данными «съедался»
                // ожидающим хендшейком — и данные пропадали, и перевыпуск падал.
                if (AwgTunnel.IsHandshakeResponse(_cfg, data, data.Length))
                {
                    TaskCompletionSource<byte[]> waiter;
                    lock (_waiterLock) waiter = _handshakeWaiter;
                    if (waiter != null && waiter.TrySetResult(data)) return;
                }

                var t = _tunnel;
                if (t == null || !t.Established) return;

                byte[] plain = t.Open(data, data.Length);
                if (plain == null)
                {
                    // Сразу после перевыпуска сервер какое-то время шлёт на старых ключах.
                    var prev = _prevTunnel;
                    if (prev == null || !prev.Established) return;
                    plain = prev.Open(data, data.Length);
                    if (plain == null) return;          // чужое/повтор/подделка
                }
                if (plain.Length == 0) return;          // keepalive

                if (Volatile.Read(ref _osRxCount) >= MaxOsRxQueue)
                {
                    Interlocked.Increment(ref _rxDropped);
                    return;
                }
                OsRxQueue.Enqueue(plain);
                Interlocked.Increment(ref _osRxCount);
                Interlocked.Increment(ref _rxPackets);
                Interlocked.Add(ref _rxBytes, plain.Length);

                if (Interlocked.Exchange(ref _triggerPending, 1) == 0) KickDecapsulate();
            }
            catch (Exception ex) { FileLog.W($"[AWG] Ошибка приёма: {ex.Message}"); }
        }

        // ===================== интерфейс для плагина =====================

        [ThreadStatic] private static byte[] _osTxScratch;

        public bool ProcessPacketFromOs(VpnPacketBuffer vpnBuffer)
        {
            var t = _tunnel;
            if (t == null || !t.Established) return false;
            try
            {
                // Буфер на поток вместо ToArray() на каждый пакет: ОС зовёт Encapsulate
                // сотни раз в секунду, и лишняя аллокация там дорого обходится.
                byte[] buf = _osTxScratch ?? (_osTxScratch = new byte[2048]);
                int len = (int)vpnBuffer.Buffer.Length;
                if (len < 20 || len > buf.Length) return false;
                WindowsRuntimeBufferExtensions.CopyTo(vpnBuffer.Buffer, 0, buf, 0, len);

                byte[] sealed_ = t.Seal(buf, len);
                if (sealed_ == null) return false;

                Interlocked.Increment(ref _txPackets);
                Interlocked.Add(ref _txBytes, len);
                Enqueue(sealed_);
                return true;
            }
            catch (Exception ex) { FileLog.W($"[AWG] Ошибка обработки пакета ОС: {ex.Message}"); return false; }
        }

        public void ResetTriggerPending() { Interlocked.Exchange(ref _triggerPending, 0); }
        public bool HasPendingOsRx() { return Volatile.Read(ref _osRxCount) > 0; }
        public void KickDecapsulate() { try { TriggerDecapsulate?.Invoke(); } catch { } }

        public bool TryDequeueOsRx(out byte[] packet)
        {
            if (OsRxQueue.TryDequeue(out packet))
            {
                Interlocked.Decrement(ref _osRxCount);
                return true;
            }
            return false;
        }

        // Раз в 10 с — где именно теряется скорость. Без этих цифр причину замедления
        // приходится угадывать, а угадывать по логу без счётчиков нельзя.
        private void LogRates()
        {
            if (_stopped) return;
            try
            {
                long txB = Volatile.Read(ref _txBytes), rxB = Volatile.Read(ref _rxBytes);
                long calls = Volatile.Read(ref _sendCalls), ticks = Volatile.Read(ref _sendTicks);

                double txMbit = (txB - _prevTxBytes) * 8.0 / 10.0 / 1e6;
                double rxMbit = (rxB - _prevRxBytes) * 8.0 / 10.0 / 1e6;
                long dCalls = calls - _prevSendCalls;
                double usPerSend = dCalls > 0
                    ? (ticks - _prevSendTicks) * 1e6 / Stopwatch.Frequency / dCalls
                    : 0;

                _prevTxBytes = txB; _prevRxBytes = rxB;
                _prevSendCalls = calls; _prevSendTicks = ticks;

                FileLog.Important(
                    $"[AWG СКОРОСТЬ] отдача={txMbit:F1} Мбит/с приём={rxMbit:F1} Мбит/с | " +
                    $"отправка={usPerSend:F0} мкс/пакет ({dCalls} шт за 10 с) | " +
                    $"в полёте={Volatile.Read(ref _txInFlight)} очередь_приёма={Volatile.Read(ref _osRxCount)} | " +
                    $"потеряно: отдача={Volatile.Read(ref _txDropped)} приём={Volatile.Read(ref _rxDropped)}");
            }
            catch { }
        }

        public void LogStats()
        {
            FileLog.Important($"[AWG] tx={Volatile.Read(ref _txPackets)}пак/{Volatile.Read(ref _txBytes)}б " +
                              $"rx={Volatile.Read(ref _rxPackets)}пак/{Volatile.Read(ref _rxBytes)}б " +
                              $"очередь={Volatile.Read(ref _osRxCount)}");
        }

        // Полный пересбор туннеля после смены сети: старый сокет привязан к исчезнувшему
        // интерфейсу, поэтому его надо закрыть и подняться заново.
        public async Task<bool> RestartAsync(string serverIp)
        {
            CloseSocket();
            _tunnel = null;
            _prevTunnel = null;
            while (OsRxQueue.TryDequeue(out _)) { }
            Volatile.Write(ref _osRxCount, 0);
            return await StartAsync(serverIp);
        }

        private void CloseSocket()
        {
            try { _rekeyTimer?.Dispose(); } catch { } _rekeyTimer = null;
            try { _keepaliveTimer?.Dispose(); } catch { } _keepaliveTimer = null;
            try { _drainTimer?.Dispose(); } catch { } _drainTimer = null;
            try { _statsTimer?.Dispose(); } catch { } _statsTimer = null;
            Volatile.Write(ref _txInFlight, 0);
            _out = null;
            try { if (_socket != null) _socket.MessageReceived -= OnDatagram; } catch { }
            try { _socket?.Dispose(); } catch { } _socket = null;
        }

        public void SignalStop()
        {
            _stopped = true;
            CloseSocket();
            _tunnel = null;
            _prevTunnel = null;
            while (OsRxQueue.TryDequeue(out _)) { }
            Volatile.Write(ref _osRxCount, 0);
        }
    }
}
