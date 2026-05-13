# Fetch osquery + fluent-bit .deb via Docker, place into agents/deploy/files/
#
# Usage:
#   .\fetch.ps1                    # Debian trixie (default)
#   .\fetch.ps1 -FbDist bookworm   # fluent-bit from bookworm if trixie unavailable
#
# Requirements: Docker Desktop running

param(
    [string]$FbDist = "trixie"
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

Write-Host "[1/3] Building image (FB_DIST=$FbDist)..."
docker build --build-arg "FB_DIST=$FbDist" -t $ImageName $FetchDir
if ($LASTEXITCODE -ne 0) { throw "docker build failed (exit $LASTEXITCODE)" }

Write-Host "[2/3] Extracting .deb files to: $FilesDir"
$ContainerId = (docker create $ImageName).Trim()
if ($LASTEXITCODE -ne 0) { throw "docker create failed (exit $LASTEXITCODE)" }
Write-Host "      container: $ContainerId"

try {
    # /packages/. copies directory CONTENTS (not the dir itself)
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

Write-Host "Set in agents/deploy/group_vars/all.yml:"
Write-Host "  use_local_packages: true"
foreach ($f in $Debs) {
    if ($f.Name -like "osquery*")    { Write-Host "  osquery_local_deb: `"$($f.Name)`"" }
    if ($f.Name -like "fluent-bit*") { Write-Host "  fluent_bit_local_deb: `"$($f.Name)`"" }
}
