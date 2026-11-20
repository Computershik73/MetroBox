using System;
using System.Text;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.System.Profile;

namespace VlessApp
{
    public class HwidLimitReachedException : Exception
    {
        public HwidLimitReachedException(string message = "Лимит устройств по подписке исчерпан. Пожалуйста, отвяжите неиспользуемое устройство в личном кабинете или боте провайдера.")
            : base(message)
        {
        }
    }

    internal static class DeviceHardwareId
    {
        public static string GetHwid()
        {
            try
            {
                // UWP HardwareToken: уникальный для связки приложения и устройства
                HardwareToken token = HardwareIdentification.GetPackageSpecificToken(null);
                IBuffer hardwareId = token.Id;

                // Хэшируем token.Id в SHA-256 с выводом 64-символьной hex-строки в нижнем регистре
                var hashProvider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
                IBuffer hashBuf = hashProvider.HashData(hardwareId);
                CryptographicBuffer.CopyToByteArray(hashBuf, out byte[] hashBytes);

                var sb = new StringBuilder(hashBytes.Length * 2);
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
            catch (Exception ex)
            {
                AppLog.W($"[HWID] Ошибка получения токена железа: {ex.Message}. Используем fallback GUID.");

                // Fallback: постоянный GUID в ApplicationData.Current.LocalSettings, если вызов API вернул исключение
                var localSettings = ApplicationData.Current.LocalSettings;
                if (!localSettings.Values.ContainsKey("PersistentDeviceHwid"))
                {
                    localSettings.Values["PersistentDeviceHwid"] = Guid.NewGuid().ToString("N");
                }
                return localSettings.Values["PersistentDeviceHwid"].ToString();
            }
        }
    }
}
