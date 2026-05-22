#!/usr/bin/env pwsh
# Creates an anonymized client distribution archive from the current git HEAD.
# Excluded via .gitattributes export-ignore: HARDENING/, CLAUDE.md, README_FOR_AI.md,
# CONTAINER_BEHAVIOR_PLAN.md, dev_stand/, tests/, .claude/

$date   = Get-Date -Format "yyyy-MM-dd"
$outDir = Join-Path $PSScriptRoot "dist"
$outFile = Join-Path $outDir "ueba-stand-$date.zip"

if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir | Out-Null
}

$ref = git rev-parse --short HEAD 2>$null
if (-not $?) {
    Write-Error "Not a git repository or git not found."
    exit 1
}

git archive HEAD --format=zip -o $outFile
if (-not $?) {
    Write-Error "git archive failed."
    exit 1
}

$size = [math]::Round((Get-Item $outFile).Length / 1KB, 1)
Write-Host "Built: $outFile  ($size KB, ref $ref)"
