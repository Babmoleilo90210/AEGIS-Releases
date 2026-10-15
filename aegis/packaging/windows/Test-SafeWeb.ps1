[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Executable,
      [string]$Report = '.\safeweb-native-result.json')
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$results = [System.Collections.Generic.List[object]]::new()
function Add-Result([string]$Name,[bool]$Passed,[string]$Detail) {
    $script:results.Add([ordered]@{test=$Name;status=$(if($Passed){'PASS'}else{'FAIL'});detail=$Detail})
}
# The self-test creates an actual Windows AppContainer process. The process
# proves its token identity, reads/writes its own sentinel, fails to open an
# outside sentinel, verifies clipboard job policy and connects two same-SID
# contained processes through loopback. It does not assert Tor Browser works.
try {
    $output = & $Executable '--self-test' 2>$null
    $code = $LASTEXITCODE
    $rows = @($output | ForEach-Object { $_ | ConvertFrom-Json })
    Add-Result 'AppContainer token, filesystem, two-process loopback and job policy' `
        ($code -eq 0 -and @($rows | Where-Object {$_.state -eq 'SELFTEST_PASS'}).Count -eq 1) `
        ('helper exit code: ' + $code)
} catch { Add-Result 'AppContainer native self-test' $false 'Helper did not produce valid bounded status records' }
foreach($url in @('file:///C:/Windows/System32/cmd.exe','https://localhost/',
    'https://127.0.0.1/','https://[::1]/','http://example.org/',
    'https://name:secret@example.org/','https://example.org:65536/',
    'https://example.org/" -profile C:\Users\other','https://x.invalid/ --command')) {
    $null = & $Executable '--bundle' 'C:\NotAnAegisBundle' '--url' $url 2>$null
    Add-Result ('URL rejection ' + $results.Count) ($LASTEXITCODE -eq 2) 'Invalid URL rejected before filesystem access'
}
$reportData=[ordered]@{
    schema=1
    os=[Environment]::OSVersion.VersionString
    processArchitecture=$env:PROCESSOR_ARCHITECTURE
    helperSha256=(Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash.ToLowerInvariant()
    tests=$results
    torBrowser='NOT_RUN'
    windows11Acceptance='NOT_RUN'
    productionReady=$false
}
$reportData | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Report -Encoding UTF8
if(@($results | Where-Object {$_.status -eq 'FAIL'}).Count) {exit 1}
exit 0
