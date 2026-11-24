# Руководство: Настройка легковесного сборочного окружения для MetroBox

Данное руководство описывает полный цикл подготовки минималистичной виртуальной машины под управлением Windows для компиляции и сборки UWP-пакетов **MetroBox** под **Windows 10 Mobile** (архитектура **ARM32**, целевая система Creators Update `10.0.15063.0` / минимальная `10.0.14393.0`, устройство Nokia Lumia 630).

---

## 1. Архитектурные требования к сборочной среде

Для сборки нативного клиента MetroBox требуется специализированный инструментарий:
- **XAML-компилятор UWP** (`Microsoft.Windows.UI.Xaml.CSharp.targets`);
- **Цепочка .NET Native** (`ilc.exe`, `nutc_driver.exe`), выполняющая AOT-компиляцию C# кода в машинный ARM-код под процессор Qualcomm Snapdragon 400;
- **Пакетный инструментарий Windows AppModel** (`MakeAppx.exe`, `SignTool.exe`).

> [!IMPORTANT]
> **Почему сборка невозможна в WSL / Linux:**  
> Все компоненты `.NET Native`, компиляторы UAP и утилиты формирования `.appx`/`.appxbundle` существуют исключительно в виде нативных Win32/PE-бинарников под Windows.
>
> **Почему не подходят модифицированные «SuperLite» сборки (Tiny10, Ghost Spectre, ReviOS):**  
> В неофициальных сборках часто урезаются службы **AppModel**, сервис развёртывания **AppX Deployment Service (`AppXSvc`)**, криптографические подсистемы подписи и системные COM-классы компилятора разметки. Это приводит к критическим ошибкам на этапе сборки (`REGDB_E_CLASSNOTREG`, `0x80073CF9`).

---

## 2. Выбор базового дистрибутива ОС

Рекомендуемый образ: **Windows 10 IoT Enterprise LTSC 2021 (English) x64**  
- **Источник:** [Windows 10 IoT Enterprise LTSC 2021 (English) x64 : Microsoft : Internet Archive](https://archive.org/details/en-us_windows_10_iot_enterprise_ltsc_2021_x64_dvd_257ad90f_202301) (`en-us_windows_10_iot_enterprise_ltsc_2021_x64_dvd_257ad90f_202301.iso`).
- **Преимущества:**
  - Официальный чистый образ Microsoft с жизненным циклом поддержки до 2031 года;
  - Полное отсутствие предустановленного потребительского ПО (Cortana, рекламные плитки, игры, фоновые трекеры);
  - Потребление оперативной памяти: всего **~700–800 МБ** в простое;
  - Непрерывность и целостность стека AppModel / UWP / MSIX.

---

## 3. Рекомендуемые параметры виртуальной машины (VMware Workstation / Player)

| Параметр | Значение | Описание |
| :--- | :--- | :--- |
| **Гостевая ОС** | Windows 10 x64 | Совместимость с 64-битными SDK-инструментами |
| **Виртуальный диск (VMDK)** | 25–30 ГБ | **Обязательно Thin Provisioning** («Allocate disk space on demand»). Фактически на хосте образ займет **10–12 ГБ**. |
| **Оперативная память (RAM)** | 2048 – 3072 МБ | Достаточно для работы компилятора `.NET Native`, потребляющего до 1.5 ГБ в пике |
| **Процессоры (vCPU)** | 2 ядра | Оптимально для фоновой компиляции без перегрузки хоста |
| **Сеть (Network)** | NAT | Доступ к репозиториям NuGet и интернету |
| **Общие папки (Shared Folders)** | Каталог репозитория | Проброс `D:\_\geek\wp-reborn-metrobox` для сборки без дублирования исходного кода |

---

## 4. Оптимизация гостевой системы (Ультра-лёгкий профиль)

Сразу после завершения установки ОС запустите консоль **PowerShell от имени Администратора** и выполните базовую оптимизацию диска и фоновых служб:

```powershell
# 1. Сжатие системных файлов ОС прозрачным алгоритмом CompactOS (экономит ~3.5 ГБ)
compact.exe /compactos:always

# 2. Отключение файла гибернации (освобождает объем, равный размеру RAM)
powercfg -h off

# 3. Отключение фонового индексатора поиска
Set-Service -Name WSearch -StartupType Disabled
Stop-Service WSearch

# 4. Настройка компактного статического файла подкачки (2048 МБ)
$cs = Get-WmiObject Win32_ComputerSystem
$cs.AutomaticManagedPagefile = $false
$cs.Put()
$pagefile = Get-WmiObject -Class Win32_PageFileSetting
if ($pagefile) {
    $pagefile.InitialSize = 2048
    $pagefile.MaximumSize = 2048
    $pagefile.Put()
}
```

---

## 5. Установка минимального набора сборочных инструментов (Headless CLI)

Не устанавливайте полную среду Visual Studio IDE (занимающую от 25 ГБ). Для компиляции достаточно консольного пакета **Visual Studio Build Tools**.

1. Скачайте официальный загрузчик [vs_BuildTools.exe](https://aka.ms/vs/17/release/vs_buildtools.exe).
2. Запустите установку изолированного набора UWP компонентов из командной строки:

```cmd
vs_BuildTools.exe --quiet --wait --norestart --nocache ^
  --add Microsoft.VisualStudio.Workload.UniversalBuildTools ^
  --add Microsoft.VisualStudio.ComponentGroup.UWP.NetNative ^
  --add Microsoft.VisualStudio.ComponentGroup.UWP.VC.ARM ^
  --add Microsoft.VisualStudio.Component.Windows10SDK.15063.UWP
```

> [!NOTE]
> Если в используемой редакции Build Tools отсутствует SDK `10.0.15063.0`, выберите доступный SDK `10.0.16299.0` или `10.0.17763.0`. Они полностью поддерживают сборку для платформ с `TargetPlatformMinVersion=10.0.14393.0` (Lumia 630).

---

## 6. Сборка пакета приложения (MSBuild)

Запустите **Developer Command Prompt for VS** (или откройте PowerShell с загруженным окружением VS) и перейдите в корень репозитория:

```powershell
# Сборка пакета MetroBox под ARMv7 (Windows 10 Mobile)
msbuild VlessApp.sln `
  /p:Configuration=Release `
  /p:Platform=ARM `
  /p:AppxBundle=Never `
  /p:UapAppxPackageBuildMode=SideloadOnly `
  /p:TargetPlatformVersion=10.0.15063.0 `
  /p:TargetPlatformMinVersion=10.0.14393.0
```

Результат сборки формируется в каталоге:
`VlessApp\AppPackages\VlessApp_<версия>_ARM_Test\`
- `VlessApp_<версия>_ARM.appx` — основной пакет приложения;
- `VlessApp.cer` — сертификат подписи;
- `Dependencies\ARM\` — нативные рантайм-пакеты (`Microsoft.NET.Native.Framework`, `Microsoft.NET.Native.Runtime`, `Microsoft.VCLibs`).

---

## 7. Развёртывание на устройство (Nokia Lumia 630)

### Способ 1: Автоматическая установка через скрипт `deploy_appx.ps1`
При активном соединении через USB (служба `IpOverUsbSvc` / Device Portal `http://127.0.0.1:10080`):
```powershell
.\scripts\deploy_appx.ps1 `
  -PackagePath "VlessApp\AppPackages\VlessApp_1.4.1.0_ARM_Test\VlessApp_1.4.1.0_ARM.appx" `
  -CertificatePath "VlessApp\AppPackages\VlessApp_1.4.1.0_ARM_Test\VlessApp.cer" `
  -DependencyPaths @(
      "VlessApp\AppPackages\VlessApp_1.4.1.0_ARM_Test\Dependencies\ARM\Microsoft.NET.Native.Framework.1.7.appx",
      "VlessApp\AppPackages\VlessApp_1.4.1.0_ARM_Test\Dependencies\ARM\Microsoft.NET.Native.Runtime.1.7.appx",
      "VlessApp\AppPackages\VlessApp_1.4.1.0_ARM_Test\Dependencies\ARM\Microsoft.VCLibs.ARM.14.00.appx"
  )
```

### Способ 2: Браузерный веб-интерфейс Windows Device Portal
1. Откройте в браузере `http://127.0.0.1:10080` (или IP телефона по Wi-Fi).
2. Перейдите во вкладку **Apps** $\to$ **Deploy apps**.
3. Выберите файл `.appx`, добавьте сертификат `.cer` и зависимости из папки `Dependencies\ARM\`.
4. Нажмите **Deploy** и дождитесь завершения установки.
