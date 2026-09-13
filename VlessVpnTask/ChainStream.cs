using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    // Уже поднятое VLESS-соединение, поданное наружу как обычный поток.
    //
    // Зачем: подписки Amnezia Premium отдают цепочку из двух узлов — реле умеет
    // доводить только до парного выходного узла, что подтверждено опытом (запрос
    // к выходному IP через реле вернул живой HTTP 400 от его сайта прикрытия,
    // тогда как доменные назначения реле молча закрывает).
    //
    // Второе звено — это ещё одно рукопожатие REALITY и ещё один VLESS-запрос,
    // но уже поверх первого туннеля, а не поверх TCP. Переписывать ради этого
    // VlessConnection нельзя: через него работают все остальные профили.
    // Вместо этого весь стек REALITY/vision переиспользуется как есть —
    // EstablishHandshakeAsync принимает DataWriter/DataReader, а те строятся
    // над любым IInputStream/IOutputStream. Достаточно выдать первое звено
    // в виде такой пары потоков.
    internal sealed class ChainInputStream : IInputStream
    {
        private readonly IDirectConn _inner;
        private readonly Queue<byte[]> _pending = new Queue<byte[]>();
        private byte[] _current;
        private int _offset;
        private bool _eof;

        public ChainInputStream(IDirectConn inner) { _inner = inner; }

        public IAsyncOperationWithProgress<IBuffer, uint> ReadAsync(
            IBuffer buffer, uint count, InputStreamOptions options)
        {
            return AsyncInfo.Run<IBuffer, uint>(async (token, progress) =>
            {
                // Отдаём столько, сколько уже есть: DataReader работает
                // с частичным чтением, а копить до полного count значило бы
                // ждать данных, которых сервер может и не прислать.
                while (!_eof && !HasBytes())
                {
                    byte[] chunk;
                    try
                    {
                        chunk = await _inner.ReadPayloadAsync();
                    }
                    catch (Exception ex)
                    {
                        // Первое звено умерло. Для второго это конец потока, а не сбой:
                        // без этого исключение всплывало наружу и в логе выглядело как
                        // NullReferenceException второго звена, пряча настоящую причину —
                        // отказ первого.
                        FileLog.Important("[CHAIN] Первое звено оборвалось при чтении: " + ex.Message);
                        _eof = true;
                        break;
                    }
                    if (chunk == null) { _eof = true; break; }
                    if (chunk.Length > 0) _pending.Enqueue(chunk);
                }

                if (!HasBytes()) return CryptographicBufferEmpty();

                int want = (int)count;
                var outBytes = new List<byte>(Math.Min(want, 16384));
                while (want > 0 && HasBytes())
                {
                    if (_current == null || _offset >= _current.Length)
                    {
                        _current = _pending.Dequeue();
                        _offset = 0;
                    }
                    int take = Math.Min(want, _current.Length - _offset);
                    for (int i = 0; i < take; i++) outBytes.Add(_current[_offset + i]);
                    _offset += take;
                    want -= take;
                }

                return Windows.Security.Cryptography.CryptographicBuffer
                    .CreateFromByteArray(outBytes.ToArray());
            });
        }

        private bool HasBytes()
        {
            if (_current != null && _offset < _current.Length) return true;
            return _pending.Count > 0;
        }

        private static IBuffer CryptographicBufferEmpty()
        {
            return Windows.Security.Cryptography.CryptographicBuffer
                .CreateFromByteArray(new byte[0]);
        }

        public void Dispose() { }
    }

    internal sealed class ChainOutputStream : IOutputStream
    {
        private readonly IDirectConn _inner;

        public ChainOutputStream(IDirectConn inner) { _inner = inner; }

        public IAsyncOperationWithProgress<uint, uint> WriteAsync(IBuffer buffer)
        {
            return AsyncInfo.Run<uint, uint>(async (token, progress) =>
            {
                byte[] data;
                Windows.Security.Cryptography.CryptographicBuffer.CopyToByteArray(buffer, out data);
                if (data != null && data.Length > 0)
                    await _inner.WriteUnderlyingAsync(data);
                return (uint)(data == null ? 0 : data.Length);
            });
        }

        public IAsyncOperation<bool> FlushAsync()
        {
            // Первое звено пишет в сокет само, отдельного сброса ему не нужно.
            return AsyncInfo.Run(token => Task.FromResult(true));
        }

        public void Dispose() { }
    }
}
