# Explicit optional user action. No administrator privileges, network, services or firewall changes.
$ErrorActionPreference = 'Stop'
$AegisFolder = Split-Path -Parent $MyInvocation.MyCommand.Path
$Executable = Join-Path $AegisFolder 'AEGIS.exe'
if (!(Test-Path -LiteralPath $Executable)) { throw 'AEGIS.exe not found. Extract the entire ZIP first.' }
$Shell = New-Object -ComObject WScript.Shell
$Targets = @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('Desktop'))
foreach ($Target in $Targets) {
    $Link = $Shell.CreateShortcut((Join-Path $Target 'AEGIS.lnk'))
    $Link.TargetPath = $Executable
    $Link.WorkingDirectory = $AegisFolder
    $Link.IconLocation = "$Executable,0"
    $Link.Save()
}
