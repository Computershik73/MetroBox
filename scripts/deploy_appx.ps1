# deploy_appx.ps1 - Deploy UWP / APPX / APPXBUNDLE with dependencies and certificates via Device Portal REST API
param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [string[]]$DependencyPaths = @(),

    [string]$CertificatePath = $null,

    [string]$DeviceAddress = "127.0.0.1:10080"
)

$protocol = if ($DeviceAddress -match ":10080$|:80$") { "http" } else { "https" }
$baseUrl = "$($protocol)://$DeviceAddress"

$cookieFile = Join-Path $env:TEMP "wp_dp_cookie.txt"
if (Test-Path $cookieFile) { Remove-Item $cookieFile -Force }

Write-Host "Connecting to Device Portal at $baseUrl..."
$null = curl.exe -k -s -c $cookieFile "$baseUrl/api/app/packagemanager/packages"
if (-not (Test-Path $cookieFile)) {
    Write-Error "Failed to obtain session cookies from Device Portal!"
    exit 1
}

$csrfToken = ""
Get-Content $cookieFile | ForEach-Object {
    if ($_ -match "CSRF-Token`t(.*)$") {
        $csrfToken = $matches[1].Trim()
    }
}

if (-not $csrfToken) {
    Write-Warning "CSRF-Token not found in cookies; proceeding without X-CSRF-Token header."
} else {
    Write-Host "Obtained CSRF-Token: $csrfToken"
}

$pkgName = [System.IO.Path]::GetFileName($PackagePath)
$encodedPkgName = [System.Uri]::EscapeDataString($pkgName)
$url = "$baseUrl/api/app/packagemanager/package?package=$encodedPkgName"

$curlArgs = @("-k", "-s", "-b", $cookieFile, "-X", "POST")
if ($csrfToken) {
    $curlArgs += @("-H", "X-CSRF-Token: $csrfToken")
}
$curlArgs += @("-F", "$pkgName=@`"$PackagePath`"")

foreach ($dep in $DependencyPaths) {
    if (Test-Path $dep) {
        $depName = [System.IO.Path]::GetFileName($dep)
        Write-Host "Adding dependency: $depName"
        $curlArgs += @("-F", "$depName=@`"$dep`"")
    }
}

if ($CertificatePath -and (Test-Path $CertificatePath)) {
    $certName = [System.IO.Path]::GetFileName($CertificatePath)
    Write-Host "Adding certificate: $certName"
    $curlArgs += @("-F", "$certName=@`"$CertificatePath`"")
}

Write-Host "Uploading package $pkgName..."
$resp = & curl.exe @curlArgs -w "`nHTTP_STATUS:%{http_code}" $url
$respText = ($resp -join "`n")
Write-Host "Post response: $respText"

if ($respText -notmatch "HTTP_STATUS:(200|202)") {
    Write-Error "Deployment request failed or was rejected by Device Portal!"
    exit 1
}

Write-Host "Waiting for deployment to complete..."
$deadline = (Get-Date).AddMinutes(15)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 3
    $stateRaw = curl.exe -k -s -b $cookieFile -w "`nHTTP_STATUS:%{http_code}" "$baseUrl/api/app/packagemanager/state"
    $lines = $stateRaw -split "`n"
    $httpCode = $lines[-1].Replace("HTTP_STATUS:", "").Trim()
    $json = ($lines[0..($lines.Length - 2)] -join "`n").Trim()

    if ($httpCode -eq "204") {
        Write-Host -NoNewline "."
        continue
    }

    Write-Host "`nDeployment completed with status ${httpCode}:"
    Write-Host $json
    break
}

Remove-Item $cookieFile -Force -ErrorAction SilentlyContinue
