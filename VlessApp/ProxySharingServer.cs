using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.ExtendedExecution;
using Windows.Networking;
using Windows.Networking.Connectivity;
using Windows.Networking.Sockets;

namespace VlessApp
{
    /// <summary>
    /// Локальный гибридный прокси-сервер (HTTP CONNECT + SOCKS5) для раздачи VPN-трафика
    /// другим устройствам по Wi-Fi / Мобильному хот-споту Windows 10 Mobile.
    /// </summary>
    public static class ProxySharingServer
    {
        public const int DefaultPort = 10808;

        private static StreamSocketListener _listener;
        private static ExtendedExecutionSession _extSession;
        private static int _activeConnections = 0;
        private static long _totalBytesRelayed = 0;

        public static bool IsRunning => _listener != null;
        public static int CurrentPort { get; private set; } = DefaultPort;
        public static int ActiveConnections => _activeConnections;
        public static long TotalBytesRelayed => _totalBytesRelayed;

        public static event Action<bool> StateChanged;

        public static async Task<bool> StartAsync(int port = DefaultPort)
        {
            if (IsRunning)
            {
                if (CurrentPort == port) return true;
                await StopAsync();
            }

            try
            {
                CurrentPort = port > 0 && port < 65536 ? port : DefaultPort;

                _listener = new StreamSocketListener();
                _listener.Control.KeepAlive = true;
                _listener.Control.NoDelay = true;
                _listener.ConnectionReceived += OnConnectionReceived;

                await _listener.BindServiceNameAsync(CurrentPort.ToString());
                AppLog.W($"[PROXY] Сервер раздачи VPN запущен на порту {CurrentPort} (HTTP CONNECT + SOCKS5)");

                await StartExtendedExecutionAsync();

                StateChanged?.Invoke(true);
                return true;
            }
            catch (Exception ex)
            {
                AppLog.W($"[PROXY] Ошибка запуска сервера на порту {port}: {ex.Message}");
                await StopAsync();
                return false;
            }
        }

        public static async Task StopAsync()
        {
            if (_listener != null)
            {
                try
                {
                    _listener.ConnectionReceived -= OnConnectionReceived;
                    _listener.Dispose();
                }
                catch { }
                _listener = null;
                AppLog.W("[PROXY] Сервер раздачи VPN остановлен");
            }

            StopExtendedExecution();
            StateChanged?.Invoke(false);
            await Task.CompletedTask;
        }

        private static async void OnConnectionReceived(StreamSocketListener sender, StreamSocketListenerConnectionReceivedEventArgs args)
        {
            var clientSocket = args.Socket;
            Interlocked.Increment(ref _activeConnections);

            await Task.Run(async () =>
            {
                try
                {
                    using (clientSocket)
                    using (var clientIn = clientSocket.InputStream.AsStreamForRead())
                    using (var clientOut = clientSocket.OutputStream.AsStreamForWrite())
                    {
                        await HandleClientAsync(clientSocket, clientIn, clientOut);
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[PROXY CLIENT ERR] {ex.Message}");
                }
                finally
                {
                    Interlocked.Decrement(ref _activeConnections);
                }
            });
        }

        private static async Task HandleClientAsync(StreamSocket clientSocket, Stream clientIn, Stream clientOut)
        {
            int b0 = clientIn.ReadByte();
            if (b0 == -1) return;

            string clientIp = clientSocket.Information.RemoteAddress?.DisplayName ?? "client";

            if (b0 == 0x05)
            {
                // SOCKS5 (RFC 1928)
                await HandleSocks5Async(clientIp, (byte)b0, clientIn, clientOut);
            }
            else
            {
                // HTTP / HTTPS CONNECT
                await HandleHttpAsync(clientIp, (byte)b0, clientIn, clientOut);
            }
        }

        #region SOCKS5 Protocol Handler

        private static async Task HandleSocks5Async(string clientIp, byte ver, Stream clientIn, Stream clientOut)
        {
            // 1. Читаем методы аутентификации от клиента
            int nmethods = clientIn.ReadByte();
            if (nmethods <= 0) return;

            byte[] methods = new byte[nmethods];
            if (!await ReadExactAsync(clientIn, methods, 0, nmethods)) return;

            // Ответ сервера: VER=5, METHOD=0 (No Authentication Required)
            await clientOut.WriteAsync(new byte[] { 0x05, 0x00 }, 0, 2);
            await clientOut.FlushAsync();

            // 2. Читаем запрос на соединение
            byte[] reqHeader = new byte[4];
            if (!await ReadExactAsync(clientIn, reqHeader, 0, 4)) return;

            byte cmd = reqHeader[1];
            byte atyp = reqHeader[3];

            if (cmd != 0x01) // 0x01 = CONNECT
            {
                // Команда не поддерживается (REP=0x07)
                await clientOut.WriteAsync(new byte[] { 0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);
                await clientOut.FlushAsync();
                return;
            }

            string destHost = null;
            if (atyp == 0x01) // IPv4 (4 байта)
            {
                byte[] ipBytes = new byte[4];
                if (!await ReadExactAsync(clientIn, ipBytes, 0, 4)) return;
                destHost = $"{ipBytes[0]}.{ipBytes[1]}.{ipBytes[2]}.{ipBytes[3]}";
            }
            else if (atyp == 0x03) // Доменное имя (1 байт длины + ASCII)
            {
                int domainLen = clientIn.ReadByte();
                if (domainLen <= 0) return;
                byte[] domainBytes = new byte[domainLen];
                if (!await ReadExactAsync(clientIn, domainBytes, 0, domainLen)) return;
                destHost = Encoding.ASCII.GetString(domainBytes);
            }
            else if (atyp == 0x04) // IPv6 (16 байт)
            {
                byte[] ip6Bytes = new byte[16];
                if (!await ReadExactAsync(clientIn, ip6Bytes, 0, 16)) return;
                destHost = new System.Net.IPAddress(ip6Bytes).ToString();
            }
            else
            {
                // Неподдерживаемый тип адреса (REP=0x08)
                await clientOut.WriteAsync(new byte[] { 0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);
                await clientOut.FlushAsync();
                return;
            }

            byte[] portBytes = new byte[2];
            if (!await ReadExactAsync(clientIn, portBytes, 0, 2)) return;
            int destPort = (portBytes[0] << 8) | portBytes[1];

            // Подключение к целевому узлу через системный стек (направляется в VPN-туннель)
            StreamSocket targetSocket = new StreamSocket();
            targetSocket.Control.NoDelay = true;
            try
            {
                await targetSocket.ConnectAsync(new HostName(destHost), destPort.ToString(), SocketProtectionLevel.PlainSocket);
            }
            catch (Exception ex)
            {
                AppLog.W($"[PROXY SOCKS5] {clientIp} -> {destHost}:{destPort} отказ: {ex.Message}");
                // Ошибка подключения (REP=0x04 Host unreachable / 0x05 Connection refused)
                try
                {
                    await clientOut.WriteAsync(new byte[] { 0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);
                    await clientOut.FlushAsync();
                }
                catch { }
                targetSocket.Dispose();
                return;
            }

            // Успешный ответ: VER=5, REP=0 (Success), RSV=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
            await clientOut.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10);
            await clientOut.FlushAsync();

            await PipeSocketsAsync(clientIn, clientOut, targetSocket);
        }

        #endregion

        #region HTTP / HTTPS CONNECT Protocol Handler

        private static async Task HandleHttpAsync(string clientIp, byte firstByte, Stream clientIn, Stream clientOut)
        {
            // Считываем первую строку запроса (Method URL HTTP/Version)
            var ms = new MemoryStream();
            ms.WriteByte(firstByte);
            int prev = firstByte;
            while (true)
            {
                int b = clientIn.ReadByte();
                if (b == -1) return;
                ms.WriteByte((byte)b);
                if (prev == '\r' && b == '\n') break;
                prev = b;
                if (ms.Length > 8192) return; // Защита от переполнения
            }

            string firstLine = Encoding.ASCII.GetString(ms.ToArray()).Trim();
            var parts = firstLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return;

            string method = parts[0].ToUpperInvariant();
            string targetUri = parts[1];

            if (method == "CONNECT")
            {
                // HTTPS CONNECT Tunneling (RFC 7231 Section 4.3.6)
                string host = targetUri;
                int port = 443;
                int colonIdx = targetUri.LastIndexOf(':');
                if (colonIdx > 0 && int.TryParse(targetUri.Substring(colonIdx + 1), out int p))
                {
                    host = targetUri.Substring(0, colonIdx);
                    port = p;
                }

                // Пропускаем оставшиеся HTTP-заголовки клиента до \r\n\r\n
                await SkipRemainingHttpHeadersAsync(clientIn);

                // Подключаемся к целевому серверу
                var targetSocket = new StreamSocket();
                targetSocket.Control.NoDelay = true;
                try
                {
                    await targetSocket.ConnectAsync(new HostName(host), port.ToString(), SocketProtectionLevel.PlainSocket);
                }
                catch (Exception ex)
                {
                    AppLog.W($"[PROXY HTTPS] {clientIp} -> {host}:{port} отказ: {ex.Message}");
                    byte[] err = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                    try { await clientOut.WriteAsync(err, 0, err.Length); await clientOut.FlushAsync(); } catch { }
                    targetSocket.Dispose();
                    return;
                }

                // Отвечаем клиенту: 200 Connection Established
                byte[] ok = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\nProxy-Agent: MetroBox\r\n\r\n");
                await clientOut.WriteAsync(ok, 0, ok.Length);
                await clientOut.FlushAsync();

                await PipeSocketsAsync(clientIn, clientOut, targetSocket);
            }
            else
            {
                // Обычный HTTP прокси (GET http://host:port/path HTTP/1.1)
                string host = null;
                int port = 80;
                string relativePath = "/";

                if (targetUri.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                {
                    string stripped = targetUri.Substring(7);
                    int slashIdx = stripped.IndexOf('/');
                    string hostPort = slashIdx >= 0 ? stripped.Substring(0, slashIdx) : stripped;
                    relativePath = slashIdx >= 0 ? stripped.Substring(slashIdx) : "/";

                    int colonIdx = hostPort.LastIndexOf(':');
                    if (colonIdx > 0 && int.TryParse(hostPort.Substring(colonIdx + 1), out int p))
                    {
                        host = hostPort.Substring(0, colonIdx);
                        port = p;
                    }
                    else
                    {
                        host = hostPort;
                    }
                }

                if (string.IsNullOrEmpty(host)) return;

                var targetSocket = new StreamSocket();
                targetSocket.Control.NoDelay = true;
                try
                {
                    await targetSocket.ConnectAsync(new HostName(host), port.ToString(), SocketProtectionLevel.PlainSocket);
                }
                catch (Exception ex)
                {
                    AppLog.W($"[PROXY HTTP] {clientIp} -> {host}:{port} отказ: {ex.Message}");
                    byte[] err = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\n\r\n");
                    try { await clientOut.WriteAsync(err, 0, err.Length); await clientOut.FlushAsync(); } catch { }
                    targetSocket.Dispose();
                    return;
                }

                using (targetSocket)
                using (var targetIn = targetSocket.InputStream.AsStreamForRead())
                using (var targetOut = targetSocket.OutputStream.AsStreamForWrite())
                {
                    string httpVer = parts.Length > 2 ? parts[2] : "HTTP/1.1";
                    string rewrittenLine = $"{method} {relativePath} {httpVer}\r\n";
                    byte[] lineBytes = Encoding.ASCII.GetBytes(rewrittenLine);
                    await targetOut.WriteAsync(lineBytes, 0, lineBytes.Length);
                    await targetOut.FlushAsync();

                    var t1 = RelayStreamAsync(clientIn, targetOut);
                    var t2 = RelayStreamAsync(targetIn, clientOut);
                    await Task.WhenAny(t1, t2);
                }
            }
        }

        private static async Task SkipRemainingHttpHeadersAsync(Stream stream)
        {
            // Автомат поиска двойного CRLF: \r\n\r\n (состояния 0 -> 1 -> 2 -> 3 -> 4)
            byte[] buf = new byte[1];
            int state = 0;
            while (state < 4)
            {
                int r = await stream.ReadAsync(buf, 0, 1);
                if (r <= 0) break;
                char c = (char)buf[0];
                if (state == 0 && c == '\r') state = 1;
                else if (state == 1 && c == '\n') state = 2;
                else if (state == 2 && c == '\r') state = 3;
                else if (state == 3 && c == '\n') state = 4;
                else if (c == '\r') state = 1;
                else state = 0;
            }
        }

        #endregion

        #region Stream Piping & Utilities

        private static async Task PipeSocketsAsync(Stream clientIn, Stream clientOut, StreamSocket targetSocket)
        {
            using (targetSocket)
            using (var targetIn = targetSocket.InputStream.AsStreamForRead())
            using (var targetOut = targetSocket.OutputStream.AsStreamForWrite())
            {
                var t1 = RelayStreamAsync(clientIn, targetOut);
                var t2 = RelayStreamAsync(targetIn, clientOut);
                await Task.WhenAny(t1, t2);
            }
        }

        private static async Task RelayStreamAsync(Stream source, Stream destination)
        {
            byte[] buffer = new byte[32768];
            try
            {
                int bytesRead;
                while ((bytesRead = await source.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await destination.WriteAsync(buffer, 0, bytesRead);
                    await destination.FlushAsync();
                    Interlocked.Add(ref _totalBytesRelayed, bytesRead);
                }
            }
            catch { }
        }

        private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, int offset, int count)
        {
            int total = 0;
            while (total < count)
            {
                int read = await stream.ReadAsync(buffer, offset + total, count - total);
                if (read <= 0) return false;
                total += read;
            }
            return true;
        }

        public static List<string> GetLocalIpAddresses()
        {
            var ips = new List<string>();
            try
            {
                var hostnames = NetworkInformation.GetHostNames();
                foreach (var hn in hostnames)
                {
                    if (hn.Type == HostNameType.Ipv4)
                    {
                        string s = hn.CanonicalName;
                        if (!s.StartsWith("127.") && !s.StartsWith("169.254."))
                        {
                            ips.Add(s);
                        }
                    }
                }
            }
            catch { }
            return ips;
        }

        private static async Task StartExtendedExecutionAsync()
        {
            try
            {
                if (_extSession == null)
                {
                    _extSession = new ExtendedExecutionSession
                    {
                        Reason = ExtendedExecutionReason.Unspecified,
                        Description = "MetroBox VPN Proxy Sharing"
                    };
                    _extSession.Revoked += (s, e) =>
                    {
                        AppLog.W("[PROXY] Фоновая сессия ExtendedExecution отозвана системой");
                        _extSession?.Dispose();
                        _extSession = null;
                    };
                    var result = await _extSession.RequestExtensionAsync();
                    AppLog.W($"[PROXY] Запрос ExtendedExecution: {result}");
                }
            }
            catch (Exception ex)
            {
                AppLog.W($"[PROXY] Исключение ExtendedExecution: {ex.Message}");
            }
        }

        private static void StopExtendedExecution()
        {
            try
            {
                _extSession?.Dispose();
                _extSession = null;
            }
            catch { }
        }

        #endregion
    }
}
