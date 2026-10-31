$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$parserDirectory = Join-Path $root "cyberforge-parser"
$sourceLog = Join-Path $root "firex-10G.log"
$temp = Join-Path $env:TEMP "cyberforge-parser-thread-benchmark"
New-Item -ItemType Directory -Force -Path $temp | Out-Null

$sample = Join-Path $temp "firex-100MiB.log"
$sequentialOutput = Join-Path $temp "threads-1.parquet"
$parallelOutput = Join-Path $temp "threads-2.parquet"

Write-Host "Building optimized release parser..."
Push-Location $parserDirectory
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}
finally {
    Pop-Location
}

$parser = Join-Path $parserDirectory "target\release\cyberforge-parser.exe"
if (-not (Test-Path -LiteralPath $parser)) {
    throw "Release parser was not created: $parser"
}

Write-Host "Creating a 100 MiB prefix sample, ending on a complete record..."
$reader = [System.IO.File]::OpenRead($sourceLog)
$writer = [System.IO.File]::Create($sample)
try {
    $buffer = [byte[]]::new(1MB)
    $targetBytes = 100MB
    $copied = 0
    while ($copied -lt $targetBytes) {
        $read = $reader.Read($buffer, 0, [Math]::Min($buffer.Length, $targetBytes - $copied))
        if ($read -eq 0) {
            break
        }
        $writer.Write($buffer, 0, $read)
        $copied += $read
    }

    while ($copied -lt $reader.Length) {
        $next = $reader.ReadByte()
        if ($next -lt 0) {
            break
        }
        $writer.WriteByte([byte]$next)
        $copied++
        if ($next -eq 10) {
            break
        }
    }
}
finally {
    $writer.Dispose()
    $reader.Dispose()
}

$results = @()
foreach ($threads in @(1, 2)) {
    $output = if ($threads -eq 1) { $sequentialOutput } else { $parallelOutput }
    Write-Host "Parsing sample with --threads $threads..."
    $clock = [Diagnostics.Stopwatch]::StartNew()
    & $parser --input $sample --output $output --batch-size 5000 --threads $threads
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    $clock.Stop()
    $results += [pscustomobject]@{
        Threads = $threads
        Seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 2)
        OutputBytes = (Get-Item -LiteralPath $output).Length
        OutputPath = $output
    }
}

Write-Host "Comparing every Parquet field and row in order..."
python -c 'import pyarrow.parquet as pq,sys; a=pq.read_table(sys.argv[1]); b=pq.read_table(sys.argv[2]); assert a.equals(b), "sequential and parallel output differ"; print(f"Equivalent rows: {a.num_rows}; columns: {a.num_columns}")' $sequentialOutput $parallelOutput
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$results | Format-Table -AutoSize
Write-Host "Benchmark outputs: $temp"
