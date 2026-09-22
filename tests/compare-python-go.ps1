<#
.SYNOPSIS
    Runs the same CLI cases through scan_and_get.py and the Go port, then compares
    exit codes and CSV output.

.DESCRIPTION
    Every case is executed twice with identical arguments: once against
    scan_and_get.py and once against the binary built from cmd/scan-and-get. A case
    passes when both implementations return the same exit code and produce matching
    CSV output.

    Debug error text (error, redfish_error, xml_parse_error) is produced by the Go
    standard library rather than requests/ElementTree, so cases that exercise those
    columns compare headers only.

.PARAMETER Cidr
    Target used by the discovery cases. Must stay local; defaults to 127.0.0.1/32.

.PARAMETER Live
    Also run cases against tests/mock_bmc_server.py, which binds 127.0.0.1:80 and
    returns iLO XML plus Redfish JSON. This compares real extracted field values.

.EXAMPLE
    pwsh tests/compare-python-go.ps1

.EXAMPLE
    pwsh tests/compare-python-go.ps1 -Live
#>
[CmdletBinding()]
param(
    [string]$Cidr = '127.0.0.1/32',
    [string]$Python,
    [switch]$Live,
    [switch]$SkipBuild,
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
$goExe = Join-Path $repo 'scan_and_get.exe'
$pyScript = Join-Path $repo 'scan_and_get.py'

if (-not $Python) {
    $venvPython = Join-Path $repo '.venv\Scripts\python.exe'
    $Python = if (Test-Path $venvPython) { $venvPython } else { 'python' }
}

Push-Location $repo
try {
    if (-not $SkipBuild) {
        Write-Host 'Building cmd/scan-and-get...'
        & go build -o $goExe ./cmd/scan-and-get
        if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
    }
    if (-not (Test-Path $goExe)) { throw "missing $goExe (run without -SkipBuild)" }

    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("scan-and-get-parity-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null

    # Fixtures for the settings validation cases.
    $badJson = Join-Path $work 'bad.json'
    $noXml = Join-Path $work 'noxml.json'
    $noRedfish = Join-Path $work 'noredfish.json'
    $emptyArgs = Join-Path $work 'empty.args.txt'
    $missingSettings = Join-Path $work 'missing.json'
    $missingNmap = Join-Path $work 'missing-nmap.exe'

    '{ not valid json' | Set-Content -Encoding utf8 $badJson
    '{}' | Set-Content -Encoding utf8 $noXml
    ((Get-Content (Join-Path $repo 'settings.json') -Raw) -replace '"redfish"\s*:', '"redfish_disabled":') |
        Set-Content -Encoding utf8 $noRedfish
    Set-Content -Encoding utf8 -Path $emptyArgs -Value ''

    $localArgs = '-sn -n'
    $rangeCidr = ($Cidr -replace '/\d+$', '/30')

    $cases = @(
        @{ n = 'no-args'; a = @() }
        @{ n = 'help'; a = @('--help') }
        @{ n = 'unknown-flag'; a = @('--cidr', $Cidr, '--bogus') }
        @{ n = 'bad-scheme'; a = @('--cidr', $Cidr, '--scheme', 'ftp') }
        @{ n = 'missing-settings'; a = @('--cidr', $Cidr, '--settings', $missingSettings) }
        @{ n = 'bad-json-settings'; a = @('--cidr', $Cidr, '--settings', $badJson) }
        @{ n = 'no-xml-fields'; a = @('--cidr', $Cidr, '--settings', $noXml) }
        @{ n = 'redfishonly-and-noredfish'; a = @('--cidr', $Cidr, '--redfish-only', '--no-redfish') }
        @{ n = 'redfishonly-without-fields'; a = @('--cidr', $Cidr, '--settings', $noRedfish, '--nmap-args', $localArgs, '--redfish-only') }
        @{ n = 'empty-args-file'; a = @('--cidr', $Cidr, '--nmap-args-file', $emptyArgs, '--dry-run') }
        @{ n = 'unlaunchable-nmap-32'; a = @('--cidr', $Cidr, '--nmap-path', $missingNmap, '--nmap-args', $localArgs, '--dry-run'); csv = 'full' }
        @{ n = 'unlaunchable-nmap-range'; a = @('--cidr', $rangeCidr, '--nmap-path', $missingNmap, '--nmap-args', $localArgs, '--dry-run') }
        @{ n = 'pn-safety-refusal'; a = @('--cidr', $Cidr, '--nmap-args', '-Pn -n -sn', '--dry-run') }
        @{ n = 'no-hosts-up'; a = @('--cidr', '192.0.2.1/32', '--nmap-args', '-sn -n --host-timeout 2s', '--dry-run') }
        @{ n = 'dry-run'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--dry-run'); csv = 'full' }
        @{ n = 'dry-run-args-file'; a = @('--cidr', $Cidr, '--nmap-args-file', 'nmap-ilo443.args.txt', '--dry-run'); csv = 'full' }
        @{ n = 'dry-run-path-scheme'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--path', 'custom?x=1', '--dry-run'); csv = 'full' }
        @{ n = 'max-targets-cap'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--max-targets', '0') }
        @{ n = 'unreachable-host'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '2'); csv = 'full' }
        @{ n = 'unreachable-host-debug'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '2', '--debug'); csv = 'header' }
        @{ n = 'no-redfish'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '2', '--no-redfish'); csv = 'full' }
        @{ n = 'redfish-only'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '2', '--redfish-only'); csv = 'full' }
        @{ n = 'redfish-only-debug'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '2', '--redfish-only', '--debug'); csv = 'header' }
        @{ n = 'workers-and-progress'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '2', '--workers', '4', '--progress-every', '1'); csv = 'full' }
    )

    $server = $null
    if ($Live) {
        $serverScript = Join-Path $PSScriptRoot 'mock_bmc_server.py'
        Write-Host 'Starting mock BMC server on 127.0.0.1:80...'
        $server = Start-Process -FilePath $Python -ArgumentList $serverScript -PassThru -WindowStyle Hidden

        $ready = $false
        foreach ($attempt in 1..25) {
            try {
                $client = [System.Net.Sockets.TcpClient]::new()
                $client.Connect('127.0.0.1', 80)
                $client.Close()
                $ready = $true
                break
            }
            catch {
                Start-Sleep -Milliseconds 200
            }
        }
        if (-not $ready) { throw 'mock BMC server did not start (is 127.0.0.1:80 already in use?)' }

        $cases += @(
            @{ n = 'live-xml-and-redfish'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '5'); csv = 'full' }
            @{ n = 'live-debug-columns'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '5', '--debug'); csv = 'full' }
            @{ n = 'live-redfish-only'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '5', '--redfish-only'); csv = 'full' }
            @{ n = 'live-no-redfish'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '5', '--no-redfish'); csv = 'full' }
            @{ n = 'live-non-xml-body'; a = @('--cidr', $Cidr, '--nmap-args', $localArgs, '--scheme', 'http', '--timeout', '5', '--path', '/redfish/v1', '--debug'); csv = 'header' }
        )
    }

    $report = @()
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'

    foreach ($case in $cases) {
        $goCsv = Join-Path $work "$($case.n).go.csv"
        $pyCsv = Join-Path $work "$($case.n).py.csv"

        $goArgs = @($case.a)
        $pyArgs = @($case.a)
        if ($case.csv) {
            $goArgs += @('--csv-output', $goCsv)
            $pyArgs += @('--csv-output', $pyCsv)
        }

        $goOut = (& $goExe @goArgs 2>&1 | Out-String)
        $goExit = $LASTEXITCODE
        $null = (& $Python $pyScript @pyArgs 2>&1 | Out-String)
        $pyExit = $LASTEXITCODE

        $csvStatus = 'n/a'
        if ($case.csv) {
            $goExists = Test-Path $goCsv
            $pyExists = Test-Path $pyCsv
            if ($goExists -and $pyExists) {
                $goLines = @(Get-Content $goCsv)
                $pyLines = @(Get-Content $pyCsv)
                if ($case.csv -eq 'header') {
                    $csvStatus = if ($goLines[0] -eq $pyLines[0]) { 'header-match' } else { 'HEADER-DIFF' }
                }
                else {
                    $csvStatus = if ($null -eq (Compare-Object $goLines $pyLines)) { 'match' } else { 'DIFF' }
                }
            }
            elseif (-not $goExists -and -not $pyExists) {
                $csvStatus = 'none-written'
            }
            else {
                $csvStatus = 'ONE-SIDED'
            }
        }

        $firstLine = (($goOut -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
        if ($firstLine -and $firstLine.Length -gt 70) { $firstLine = $firstLine.Substring(0, 70) + '...' }

        $report += [pscustomobject]@{
            Case    = $case.n
            GoExit  = $goExit
            PyExit  = $pyExit
            Exit    = if ($goExit -eq $pyExit) { 'ok' } else { 'MISMATCH' }
            Csv     = $csvStatus
            GoFirst = $firstLine
        }
    }

    $ErrorActionPreference = $previousPreference

    if ($server -and -not $server.HasExited) { Stop-Process -Id $server.Id -Force }

    $report | Format-Table -AutoSize -Wrap

    $failures = @($report | Where-Object { $_.Exit -ne 'ok' -or $_.Csv -like '*DIFF*' -or $_.Csv -eq 'ONE-SIDED' })
    Write-Host ''
    Write-Host ("Cases: {0}   Failures: {1}" -f $report.Count, $failures.Count)

    if ($KeepArtifacts) {
        Write-Host "Artifacts kept in $work"
    }
    else {
        Remove-Item -Recurse -Force $work
    }

    if ($failures.Count -gt 0) {
        $failures | ForEach-Object { Write-Host ("FAILED: {0}" -f $_.Case) -ForegroundColor Red }
        exit 1
    }

    Write-Host 'All cases matched.' -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
