using System;
using System.Collections.Concurrent;

namespace VlessVpnTask
{
    /// <summary>
    /// YtFlow-style FakeDNS: при A-запросе клиенту возвращается синтетический IP
    /// из подсети 11.17.0.0/16 вместо реального. При SYN на этот fake-IP
    /// NatEngine резолвит mapping и открывает VLESS-соединение по доменному имени.
    ///
    /// Зачем: на WP10 после перезагрузки приложения (Edge, YouTube) получают
    /// корректный DNS-ответ с реальным IP, но AppContainer-WFP-фильтр не маршрутизирует
    /// исходящий TCP в TUN. Если же IP принадлежит подсети, явно прописанной в маршрутах
    /// TUN-интерфейса, ОС гарантированно отправляет SYN в Encapsulate.
    /// </summary>
    internal static class FakeDns
    {
        // 11.17.0.0/16. Узлы: 11.17.0.1 .. 11.17.255.254
        // 11.17.0.0 и 11.17.255.255 зарезервированы как network/broadcast.
        private const uint Base   = 0x0B110000u; // 11.17.0.0
        private const uint Mask   = 0xFFFF0000u; // /16
        private const int  MaxHosts = 65533;

        public sealed class Target
        {
            public byte[] RealIp;    // 4 байта, реальный A-ответ от upstream DNS
            public string Domain;    // оригинальный запрошенный домен
        }

        private static readonly ConcurrentDictionary<uint, Target> _fakeToTarget
            = new ConcurrentDictionary<uint, Target>();
        private static readonly ConcurrentDictionary<string, uint> _nameToFake
            = new ConcurrentDictionary<string, uint>(StringComparer.OrdinalIgnoreCase);

        public static bool IsFakeIp(byte[] ip4)
        {
            if (ip4 == null || ip4.Length != 4) return false;
            uint u = ((uint)ip4[0] << 24) | ((uint)ip4[1] << 16) | ((uint)ip4[2] << 8) | ip4[3];
            return (u & Mask) == Base;
        }

        public static bool TryResolve(byte[] fakeIp4, out byte[] realIp, out string domain)
        {
            realIp = null;
            domain = null;
            if (!IsFakeIp(fakeIp4)) return false;
            uint key = ((uint)fakeIp4[0] << 24) | ((uint)fakeIp4[1] << 16) | ((uint)fakeIp4[2] << 8) | fakeIp4[3];
            if (!_fakeToTarget.TryGetValue(key, out var t) || t == null) return false;
            realIp = t.RealIp;
            domain = t.Domain;
            return true;
        }

        /// <summary>
        /// Аллоцирует стабильный fake-IP для (domain). Если для этого имени
        /// уже выделен fake-IP - переиспользует его, но обновляет realIp.
        /// </summary>
        public static byte[] RegisterStable(string domain, byte[] realIp4)
        {
            if (string.IsNullOrEmpty(domain) || realIp4 == null || realIp4.Length != 4)
                return null;

            string key = domain.ToLowerInvariant();
            uint fake;
            if (_nameToFake.TryGetValue(key, out fake))
            {
                _fakeToTarget[fake] = new Target { RealIp = realIp4, Domain = key };
            }
            else
            {
                fake = AllocateStable(key);
                _nameToFake[key] = fake;
                _fakeToTarget[fake] = new Target { RealIp = realIp4, Domain = key };
            }
            return new byte[] {
                (byte)(fake >> 24),
                (byte)(fake >> 16),
                (byte)(fake >> 8),
                (byte)fake
            };
        }

        // FNV-1a 32-bit над именем -> host в [1..MaxHosts]
        private static uint AllocateStable(string lowerKey)
        {
            uint h = 2166136261u;
            for (int i = 0; i < lowerKey.Length; i++)
            {
                h ^= (byte)lowerKey[i];
                h *= 16777619u;
            }
            uint host = (h % (uint)MaxHosts) + 1u;
            return Base | host;
        }
    }
}
