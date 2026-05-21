# Скачать fluent-bit + osquery .deb через Docker
# Результат кладётся в agents/deploy/files/
#
# Использование:
#   .\fetch.ps1                                             # версии по умолчанию
#   .\fetch.ps1 -FluentBitVersion 5.0.5 -OsqueryVersion 5.23.0
#
# Требования: Docker Desktop запущен

param(
    [string]$FluentBitVersion = "5.0.5",
    [string]$OsqueryVersion   = "5.23.0"
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding        = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

$FetchDir  = $PSScriptRoot
$FilesDir  = Join-Path (Split-Path $FetchDir -Parent) "files"
$ImageName = "ueba-pkg-fetch"

if (-not (Test-Path $FilesDir)) {
    New-Item -ItemType Directory -Force $FilesDir | Out-Null
}

Write-Host "[1/3] Building image (FLUENT_BIT_VERSION=$FluentBitVersion OSQUERY_VERSION=$OsqueryVersion)..."
docker build `
    --build-arg "FLUENT_BIT_VERSION=$FluentBitVersion" `
    --build-arg "OSQUERY_VERSION=$OsqueryVersion" `
    -t $ImageName $FetchDir
if ($LASTEXITCODE -ne 0) { throw "docker build failed (exit $LASTEXITCODE)" }

Write-Host "[2/3] Extracting .deb files to: $FilesDir"
$ContainerId = (docker create $ImageName).Trim()
if ($LASTEXITCODE -ne 0) { throw "docker create failed (exit $LASTEXITCODE)" }
Write-Host "      container: $ContainerId"

try {
    docker cp "${ContainerId}:/packages/." $FilesDir
    if ($LASTEXITCODE -ne 0) { throw "docker cp failed (exit $LASTEXITCODE)" }
} finally {
    docker rm  $ContainerId | Out-Null
    docker rmi $ImageName   | Out-Null
}

Write-Host "[3/3] Done. Files in agents/deploy/files/:"
$Debs = Get-ChildItem "$FilesDir\*.deb" -ErrorAction SilentlyContinue
if (-not $Debs) {
    Write-Warning "No .deb files found in $FilesDir - check docker build output above"
    exit 1
}
$Debs | Format-Table Name, @{Label="MB"; Expression={ [math]::Round($_.Length/1MB, 1) }}

Write-Host ""
Write-Host "Пропишите в agents/deploy/group_vars/all.yml:"
Write-Host "  use_local_packages: true"
Write-Host "  fluent_bit_version: `"$FluentBitVersion`""
Write-Host "  osquery_version: `"$OsqueryVersion`""
