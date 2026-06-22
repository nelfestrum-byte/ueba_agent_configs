# Скачать fluent-bit + osquery .deb через Docker для нескольких дистрибутивов.
# Результат кладётся в agents/deploy/roles/common/files/packages/<distro>/
#
# Использование:
#   .\fetch.ps1                                              # все дистрибутивы, версии по умолчанию
#   .\fetch.ps1 -Distros bullseye,trixie                    # конкретные дистрибутивы
#   .\fetch.ps1 -FluentBitVersion 5.0.5 -OsqueryVersion 5.23.0
#
# Поддерживаемые дистрибутивы: bullseye (Debian 11), bookworm (Debian 12), trixie (Debian 13)
# Требования: Docker Desktop запущен

param(
    [string]$FluentBitVersion = "5.0.5",
    [string]$OsqueryVersion   = "5.23.0",
    [string[]]$Distros        = @("bullseye", "trixie")
)

# Таблица соответствий кодовых имён → базовые образы Debian
$DistroImages = @{
    "bullseye" = "debian:bullseye-slim"
    "bookworm" = "debian:bookworm-slim"
    "trixie"   = "debian:trixie-slim"
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding        = [System.Text.Encoding]::UTF8
$ErrorActionPreference = "Stop"

$FetchDir   = $PSScriptRoot
$PackagesDir = Join-Path (Split-Path (Split-Path $FetchDir -Parent) -Parent) "roles\common\files\packages"

foreach ($Distro in $Distros) {
    if (-not $DistroImages.ContainsKey($Distro)) {
        Write-Warning "Неподдерживаемый дистрибутив: $Distro. Пропускаем."
        continue
    }

    $BaseImage  = $DistroImages[$Distro]
    $TargetDir  = Join-Path $PackagesDir $Distro
    $ImageName  = "ueba-pkg-fetch-$Distro"

    Write-Host ""
    Write-Host "=== $Distro ($BaseImage) ==="

    if (-not (Test-Path $TargetDir)) {
        New-Item -ItemType Directory -Force $TargetDir | Out-Null
    }

    Write-Host "[1/3] Building image..."
    docker build `
        --build-arg "BASE_IMAGE=$BaseImage" `
        --build-arg "FLUENT_BIT_VERSION=$FluentBitVersion" `
        --build-arg "OSQUERY_VERSION=$OsqueryVersion" `
        -t $ImageName $FetchDir
    if ($LASTEXITCODE -ne 0) { throw "docker build failed for $Distro (exit $LASTEXITCODE)" }

    Write-Host "[2/3] Extracting .deb files to: $TargetDir"
    $ContainerId = (docker create $ImageName).Trim()
    if ($LASTEXITCODE -ne 0) { throw "docker create failed (exit $LASTEXITCODE)" }

    try {
        docker cp "${ContainerId}:/packages/." $TargetDir
        if ($LASTEXITCODE -ne 0) { throw "docker cp failed (exit $LASTEXITCODE)" }
    } finally {
        docker rm  $ContainerId | Out-Null
        docker rmi $ImageName   | Out-Null
    }

    Write-Host "[3/3] Files in $TargetDir :"
    $Debs = Get-ChildItem "$TargetDir\*.deb" -ErrorAction SilentlyContinue
    if (-not $Debs) {
        Write-Warning "Нет .deb файлов в $TargetDir - проверьте вывод docker build"
    } else {
        $Debs | Format-Table Name, @{Label="MB"; Expression={ [math]::Round($_.Length/1MB, 1) }}
    }
}

Write-Host ""
Write-Host "Готово. Пропишите в agents/deploy/group_vars/all.yml:"
Write-Host "  use_local_packages: true"
Write-Host "  fluent_bit_version: `"$FluentBitVersion`""
Write-Host "  osquery_version: `"$OsqueryVersion`""
