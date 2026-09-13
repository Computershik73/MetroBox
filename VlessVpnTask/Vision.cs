using System;
using System.IO;

namespace VlessVpnTask
{
    // Порт senko/daemon/core/vision.c — xtls-rprx-vision padding-обёртка.
    // Проволочно совместим с xray-core: первый блок несёт 16-байтовый UUID,
    // далее команда(1) + content_len(2) + padding_len(2) + content + padding.
    // Команды: 0=CONTINUE, 1=END, 2=DIRECT. После END/DIRECT паддинг выключается
    // и поток идёт «сырым» passthrough.
    internal static class VisionConst
    {
        public const byte CmdContinue = 0;
        public const byte CmdEnd = 1;
        public const byte CmdDirect = 2;

        public const int DefaultPadPackets = 8;
        public const int LongPadThreshold = 900;
        public const int LongPadRandom = 500;
        public const int LongPadBase = 900;
        public const int ShortPadRandom = 256;
    }

    // Порт TrafficState + XtlsFilterTls из xray-core (proxy/proxy.go).
    // Состояние общее на соединение: ServerHello приходит в нисходящем потоке,
    // а решение о команде принимается в восходящем, поэтому VisionWrap и
    // VisionUnpad обязаны смотреть в один и тот же объект.
    //
    // Смысл всей этой машинерии один: xtls-rprx-vision «отпускает» поток в raw
    // (команда DIRECT) ТОЛЬКО если сайт согласовал TLS 1.3 с подходящим шифром.
    // На TLS 1.2 обёртка закрывается командой END, а splice не включается —
    // именно этого различия у нас не было, и все TLS 1.2-соединения (в частности
    // возобновлённые сессии speedtest.net) получали DIRECT там, где эталон шлёт END.
    internal sealed class VisionTrafficState
    {
        public bool IsTLS;
        public bool IsTLS12orAbove;
        public bool EnableXtls;
        public ushort Cipher;
        public int RemainingServerHello = -1;
        public int NumberOfPacketToFilter = 8;

        private bool _verdictLogged;

        // supported_versions = TLS 1.3, в том виде, в каком оно лежит в ServerHello.
        private static readonly byte[] Tls13SupportedVersions = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };

        private static bool Contains(byte[] hay, int hayLen, byte[] needle)
        {
            int last = hayLen - needle.Length;
            for (int i = 0; i <= last; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return true;
            }
            return false;
        }

        // Шифры TLS 1.3. xray включает xtls, если шифр найден в этом наборе и не
        // равен TLS_AES_128_CCM_8_SHA256 (0x1305). Если ServerHello оказался короче
        // 79 байт, шифр не разбирается вовсе и остаётся 0 — тогда xtls не включится.
        private static bool CipherAllowsXtls(ushort c)
        {
            return c == 0x1301 || c == 0x1302 || c == 0x1303 || c == 0x1304;
        }

        public void FilterTls(byte[] b, int len)
        {
            NumberOfPacketToFilter--;
            if (len >= 6)
            {
                if (b[0] == 0x16 && b[1] == 0x03 && b[2] == 0x03 && b[5] == 0x02)
                {
                    RemainingServerHello = ((b[3] << 8) | b[4]) + 5;
                    IsTLS12orAbove = true;
                    IsTLS = true;
                    if (len >= 79 && RemainingServerHello >= 79)
                    {
                        int sessionIdLen = b[43];
                        if (43 + sessionIdLen + 3 <= len)
                            Cipher = (ushort)((b[43 + sessionIdLen + 1] << 8) | b[43 + sessionIdLen + 2]);
                    }
                    else
                    {
                        FileLog.Important($"[VISION TLS] Короткий ServerHello: буфер {len}б, " +
                                          $"запись {RemainingServerHello}б — шифр не разбираем (TLS 1.2 или старее).");
                    }
                }
                else if (b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01)
                {
                    IsTLS = true;
                }
            }

            if (RemainingServerHello > 0)
            {
                int end = RemainingServerHello;
                if (end > len) end = len;
                RemainingServerHello -= len;
                if (Contains(b, end, Tls13SupportedVersions))
                {
                    if (CipherAllowsXtls(Cipher)) EnableXtls = true;
                    Verdict("TLS 1.3");
                    NumberOfPacketToFilter = 0;
                    return;
                }
                if (RemainingServerHello <= 0)
                {
                    Verdict("TLS 1.2");
                    NumberOfPacketToFilter = 0;
                }
            }
        }

        private void Verdict(string version)
        {
            if (_verdictLogged) return;
            _verdictLogged = true;
            FileLog.Important($"[VISION TLS] Сайт согласовал {version}, шифр 0x{Cipher:x4} → " +
                              $"обёртка закроется командой {(EnableXtls ? "DIRECT (xtls включён)" : "END (xtls выключен)")}.");
        }
    }

    internal sealed class VisionWrap
    {
        private readonly byte[] _uuid = new byte[16];
        private readonly VisionTrafficState _state;
        private bool _uuidSent;
        private bool _paddingActive;
        private bool _bootstrapSent;
        public bool DirectSent { get; private set; }
        // Команда последнего собранного блока — нужна только логу: по ней видно,
        // в каком режиме ушёл первый запрос (0=CONTINUE, 1=END, 2=DIRECT).
        public byte LastCommand { get; private set; }
        private uint _prng;
        private int _blocksSent;
        private long _bytesSent;

        public VisionWrap(byte[] uuid16, VisionTrafficState state)
        {
            Buffer.BlockCopy(uuid16, 0, _uuid, 0, 16);
            _state = state;
            _paddingActive = true;
            uint seed = SeedNow();
            _prng = seed ^ ((uint)_uuid[0] << 24) ^ ((uint)_uuid[15] << 8);
        }

        private static uint SeedNow()
        {
            // эквивалент tv_sec ^ (tv_usec<<11) ^ 0xa5a5c3
            long ticks = DateTime.UtcNow.Ticks;
            uint sec = (uint)(ticks / TimeSpan.TicksPerSecond);
            uint usec = (uint)((ticks / 10) % 1000000);
            return sec ^ (usec << 11) ^ 0xa5a5c3u;
        }

        private ushort PrngMod(ushort mod)
        {
            if (mod == 0) return 0;
            uint x = _prng != 0 ? _prng : 0x13579bdfu;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            _prng = x;
            return (ushort)(x % mod);
        }

        private ushort PaddingLen(int contentLen, bool longPadding)
        {
            if (longPadding && contentLen < VisionConst.LongPadThreshold)
            {
                ushort extra = PrngMod((ushort)VisionConst.LongPadRandom);
                int want = VisionConst.LongPadBase + extra;
                if (want > contentLen) want -= contentLen;
                else want = 0;
                if (want > 0xffff) want = 0xffff;
                return (ushort)want;
            }
            return PrngMod((ushort)VisionConst.ShortPadRandom);
        }

        private void FillPadding(byte[] outBuf, int offset, int n)
        {
            for (int i = 0; i < n; i++)
                outBuf[offset + i] = (byte)PrngMod(256);
        }

        // Порт IsCompleteRecord из xray-core: буфер целиком состоит из полных
        // application-data записей (0x17 0x03 0x03 + длина). Именно это, а не
        // подсчёт записей, служит эталону признаком «хендшейк к сайту закончился».
        private static bool IsCompleteRecord(byte[] b, int totalLen)
        {
            int headerLen = 5;
            int recordLen = 0;
            int i = 0;
            while (i < totalLen)
            {
                if (headerLen > 0)
                {
                    byte data = b[i];
                    i++;
                    switch (headerLen)
                    {
                        case 5: if (data != 0x17) return false; break;
                        case 4: if (data != 0x03) return false; break;
                        case 3: if (data != 0x03) return false; break;
                        case 2: recordLen = data << 8; break;
                        case 1: recordLen |= data; break;
                    }
                    headerLen--;
                }
                else if (recordLen > 0)
                {
                    int remaining = totalLen - i;
                    if (remaining < recordLen) return false;
                    i += recordLen;
                    recordLen = 0;
                    headerLen = 5;
                }
                else return false;
            }
            return headerLen == 5 && recordLen == 0;
        }

        private byte[] BuildBlock(byte cmd, byte[] input, int inLen, bool longPadding)
        {
            if (inLen > 0xffff) inLen = 0xffff;
            ushort pad = PaddingLen(inLen, longPadding);
            int prefix = _uuidSent ? 0 : 16;
            int total = prefix + 5 + inLen + pad;

            byte[] outBuf = new byte[total];
            LastCommand = cmd;
            int o = 0;
            if (!_uuidSent)
            {
                Buffer.BlockCopy(_uuid, 0, outBuf, 0, 16);
                o = 16;
                _uuidSent = true;
            }
            outBuf[o++] = cmd;
            outBuf[o++] = (byte)(inLen >> 8);
            outBuf[o++] = (byte)(inLen & 0xff);
            outBuf[o++] = (byte)(pad >> 8);
            outBuf[o++] = (byte)(pad & 0xff);
            if (inLen > 0) { Buffer.BlockCopy(input, 0, outBuf, o, inLen); o += inLen; }
            if (pad > 0) { FillPadding(outBuf, o, pad); o += pad; }
            return outBuf;
        }

        // Пустой bootstrap-блок (CONTINUE + длинный паддинг) — отправляется,
        // когда клиентских данных ещё нет, чтобы vision-сервер не сбросил соединение.
        public byte[] Bootstrap()
        {
            if (!_paddingActive || _bootstrapSent) return null;
            _bootstrapSent = true;
            return BuildBlock(VisionConst.CmdContinue, null, 0, true);
        }

        // Обернуть исходящий блок клиентских данных. После выключения паддинга
        // возвращает данные без изменений (raw passthrough).
        public byte[] Wrap(byte[] input, int inLen)
        {
            if (inLen == 0) return null;

            // В xray фильтр висит на writer'е и срабатывает до решения о паддинге,
            // поэтому ClientHello к сайту успевает выставить IsTLS на своём же буфере.
            if (_state.NumberOfPacketToFilter > 0) _state.FilterTls(input, inLen);

            if (!_paddingActive)
            {
                if (inLen == input.Length) return input;
                byte[] raw = new byte[inLen];
                Buffer.BlockCopy(input, 0, raw, 0, inLen);
                return raw;
            }

            if (inLen > 0xffff) inLen = 0xffff;

            // Правило xray (VisionWriter.WriteMultiBuffer): обёртка закрывается на
            // первом буфере, который целиком состоит из application-data записей.
            // Команда при этом зависит от версии TLS у САЙТА: DIRECT только когда
            // включён xtls (TLS 1.3), иначе END. Мы раньше считали app-записи и
            // всегда слали DIRECT — на TLS 1.2 это расходилось с сервером и по
            // моменту (мы переключались буфером позже), и по команде.
            byte cmd;
            bool longPadding = _state.IsTLS;
            bool switchRecord = _state.IsTLS && inLen >= 6 &&
                                input[0] == 0x17 && input[1] == 0x03 && input[2] == 0x03 &&
                                IsCompleteRecord(input, inLen);
            if (switchRecord)
            {
                cmd = _state.EnableXtls ? VisionConst.CmdDirect : VisionConst.CmdEnd;
                longPadding = true;
            }
            else if (!_state.IsTLS12orAbove && _state.NumberOfPacketToFilter <= 1)
            {
                // Не-TLS поток: эталон добивает паддинг за пакет до конца окна фильтра.
                cmd = VisionConst.CmdEnd;
            }
            else
            {
                cmd = VisionConst.CmdContinue;
            }

            byte[] block = BuildBlock(cmd, input, inLen, longPadding);
            _blocksSent++;
            _bytesSent += inLen;
            if (cmd != VisionConst.CmdContinue)
            {
                _paddingActive = false;
                // Переключение в raw на исходящем потоке. Обёртка и распаковка решают
                // это независимо, и если границы разъедутся, наружу уйдёт мусор — сайт
                // ответит alert'ом. Пишем, на каком блоке и после скольких байт это
                // случилось, чтобы сверить с моментом переключения downstream.
                FileLog.Important($"[VISION SW TX] Уход в raw: cmd={cmd} " +
                                  $"({(cmd == VisionConst.CmdDirect ? "DIRECT" : "END")}), " +
                                  $"блок #{_blocksSent}, в нём {inLen}б, всего отправлено {_bytesSent}б, " +
                                  $"по записи={(switchRecord ? "да" : "нет")}, " +
                                  $"IsTLS={_state.IsTLS}, xtls={_state.EnableXtls}.");
            }
            if (cmd == VisionConst.CmdDirect) DirectSent = true;
            return block;
        }
    }

    internal sealed class VisionUnpad
    {
        private readonly byte[] _uuid = new byte[16];
        private int _remainingCommand = -1;
        private int _remainingContent = -1;
        private int _remainingPadding = -1;
        private int _currentCommand;
        private bool _direct;
        private readonly byte[] _stash = new byte[24];
        private int _stashLen;
        private long _bytesOut;
        private int _blocksSeen;
        private int _lastCmdSeen = -1;

        private readonly VisionTrafficState _state;

        public bool IsDirect => _direct;

        // Узел перестал заворачивать поток во внешний REALITY. Поднимается только
        // командой DIRECT; при уходе в raw «по кадру без UUID» остаётся false —
        // там причина неизвестна, и снимать TLS вслепую опаснее, чем оставить.
        public bool RawSplice { get; private set; }

        // После END поток идёт сырым, но версия сайта могла ещё не определиться:
        // в xray reader продолжает фильтровать, пока NumberOfPacketToFilter > 0.
        public bool NeedsProcessing => !_direct || _state.NumberOfPacketToFilter > 0;

        public VisionUnpad(byte[] uuid16, VisionTrafficState state)
        {
            Buffer.BlockCopy(uuid16, 0, _uuid, 0, 16);
            _state = state;
        }

        // Снять vision-обёртку и скормить результат фильтру TLS. Порядок как в
        // xray (VisionReader.ReadMultiBuffer): сначала XtlsUnpadding, потом
        // XtlsFilterTls по УЖЕ распакованным байтам — иначе на нулевом смещении
        // окажется vision-заголовок, а не запись ServerHello, и версия сайта
        // никогда не определится.
        public byte[] Unpad(byte[] input, int inLen, out bool switchedDirect)
        {
            byte[] outBuf = UnpadCore(input, inLen, out switchedDirect);
            if (_state.NumberOfPacketToFilter > 0 && outBuf.Length > 0)
                _state.FilterTls(outBuf, outBuf.Length);
            return outBuf;
        }

        // Возвращает распакованные application-данные. switchedDirect=true в момент
        // перехода в passthrough. Устойчиво к серверам, которые downstream не паддят:
        // первые 16 байт не совпадут с UUID и поток сразу пойдёт как direct.
        private byte[] UnpadCore(byte[] input, int inLen, out bool switchedDirect)
        {
            switchedDirect = false;
            var outMs = new MemoryStream();

            if (_direct)
            {
                if (inLen > 0) outMs.Write(input, 0, inLen);
                return outMs.ToArray();
            }

            int i = 0;
            while (i < inLen || _stashLen > 0)
            {
                if (_remainingCommand == -1)
                {
                    while (_stashLen < 16 && i < inLen) _stash[_stashLen++] = input[i++];
                    if (_stashLen < 16) break; // нужно больше данных

                    if (!Equals16(_stash, _uuid))
                    {
                        // Не vision-фрейм → direct passthrough: отдаём stash + остаток.
                        // Сюда попадаем и штатно (сервер не паддит downstream), и после END,
                        // когда мы зря ждём UUID. Отличать важно: во втором случае решение
                        // принимается по 16 байтам сырых данных сайта, и если их в этом
                        // чтении меньше, кусок задержится в stash.
                        FileLog.Important($"[VISION SW RX] Кадр без UUID на {_bytesOut}-м байте " +
                                          $"(до этого блоков {_blocksSeen}, последняя команда " +
                                          $"{_lastCmdSeen}) — ухожу в raw, отдаю {_stashLen}б из stash " +
                                          $"+ {inLen - i}б остатка.");
                        outMs.Write(_stash, 0, _stashLen);
                        if (inLen - i > 0) outMs.Write(input, i, inLen - i);
                        _bytesOut += _stashLen + (inLen - i);
                        _stashLen = 0;
                        _direct = true;
                        switchedDirect = true;
                        return outMs.ToArray();
                    }
                    _stashLen = 0;
                    _remainingCommand = 5;
                    _remainingContent = 0;
                    _remainingPadding = 0;
                }

                while (_remainingCommand > 0)
                {
                    if (i >= inLen) return outMs.ToArray(); // заголовок разорван между чтениями
                    byte b = input[i++];
                    switch (_remainingCommand)
                    {
                        case 5: _currentCommand = b; break;
                        case 4: _remainingContent = ((int)b) << 8; break;
                        case 3: _remainingContent |= b; break;
                        case 2: _remainingPadding = ((int)b) << 8; break;
                        case 1: _remainingPadding |= b; break;
                    }
                    _remainingCommand--;
                }

                if (_remainingContent > 0)
                {
                    int take = inLen - i;
                    if (take > _remainingContent) take = _remainingContent;
                    if (take > 0) { outMs.Write(input, i, take); i += take; _bytesOut += take; }
                    _remainingContent -= take;
                    if (_remainingContent > 0) return outMs.ToArray();
                }

                if (_remainingContent == 0 && _remainingPadding > 0)
                {
                    int skip = inLen - i;
                    if (skip > _remainingPadding) skip = _remainingPadding;
                    i += skip;
                    _remainingPadding -= skip;
                    if (_remainingPadding > 0) return outMs.ToArray();
                }

                if (_remainingCommand <= 0 && _remainingContent <= 0 && _remainingPadding <= 0)
                {
                    if (_currentCommand == VisionConst.CmdContinue)
                    {
                        _blocksSeen++;
                        _lastCmdSeen = _currentCommand;
                        _remainingCommand = 5; // следующий блок без uuid
                        _remainingContent = 0;
                        _remainingPadding = 0;
                    }
                    else
                    {
                        _blocksSeen++;
                        _lastCmdSeen = _currentCommand;
                        FileLog.Important($"[VISION SW RX] Команда {_currentCommand} " +
                                          $"({(_currentCommand == VisionConst.CmdDirect ? "DIRECT" : "END")}) " +
                                          $"в блоке #{_blocksSeen}, всего распаковано {_bytesOut}б, " +
                                          $"хвостом отдаю {inLen - i}б.");
                        // И DIRECT, и END означают одно: обёртка кончилась, дальше сырой поток.
                        // Раньше на END мы возвращались к ожиданию uuid, и решение «это уже не
                        // vision-кадр» принималось только по 16 накопленным байтам данных сайта.
                        // Пока их не набиралось, начало ответа лежало в stash — в логе такие
                        // задержки доходили до 734 мс, а если соединение закрывалось раньше,
                        // хвост терялся совсем.
                        _direct = true;
                        // Обёртка кончается на обеих командах, но внешний TLS —
                        // только на DIRECT: это и есть сплайс XTLS, дальше узел
                        // перестаёт шифровать, потому что данные уже защищены
                        // внутренним TLS сайта. END означает лишь конец паддинга
                        // (xtls выключен, сайт на TLS 1.2), и REALITY продолжается.
                        // Смешивать их нельзя: на END сырое чтение отдавало наружу
                        // шифротекст, браузер получал мусор и рвал соединение.
                        if (_currentCommand == VisionConst.CmdDirect) RawSplice = true;
                        switchedDirect = true;
                        int rest = inLen - i;
                        if (rest > 0) { outMs.Write(input, i, rest); i = inLen; _bytesOut += rest; }
                        _remainingCommand = -1;
                        _remainingContent = -1;
                        _remainingPadding = -1;
                    }
                }
            }

            return outMs.ToArray();
        }

        private static bool Equals16(byte[] a, byte[] b)
        {
            for (int i = 0; i < 16; i++) if (a[i] != b[i]) return false;
            return true;
        }
    }
}
