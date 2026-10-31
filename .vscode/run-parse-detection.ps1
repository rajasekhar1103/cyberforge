$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$temp = Join-Path $env:TEMP "cyberforge-live"
New-Item -ItemType Directory -Force -Path $temp | Out-Null

$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$sourceLog = Join-Path $root "firex-10G.log"
$parsed = Join-Path $temp "firex-10G-$runId.parquet"
$detections = Join-Path $temp "firex-10G-$runId-detections.parquet"
$rules = Join-Path $root "detection-engine\rules\detections.yaml"
Write-Host "Input: $sourceLog"
Write-Host "Parsed output: $parsed"
Write-Host "Parser workers: 2"
Write-Host "Building optimized release parser..."
Push-Location (Join-Path $root "cyberforge-parser")
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

$parser = Join-Path $root "cyberforge-parser\target\release\cyberforge-parser.exe"
Write-Host "Starting parse..."
$clock = [Diagnostics.Stopwatch]::StartNew()
& $parser --input $sourceLog --output $parsed --batch-size 5000 --threads 2
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host ("Parse completed in {0:N2} seconds. Starting detection..." -f $clock.Elapsed.TotalSeconds)
$clock.Restart()
Push-Location (Join-Path $root "detection-engine")
try {
    python -u engine.py --input $parsed --rules $rules --output $detections --batch-size 5000
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

Write-Host ("Detection completed in {0:N2} seconds." -f $clock.Elapsed.TotalSeconds)
Write-Host "Detection output: $detections"
Write-Host "Parse and detection completed successfully."
