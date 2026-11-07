$scriptName  = "sveto4"
$sourceFile  = ".\$scriptName.ps1"
$targetExe   = ".\$scriptName.exe"

Set-Location $PSScriptRoot

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Running as administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

$wasRunning = $false
$runningProcess = Get-Process -Name $scriptName -ErrorAction SilentlyContinue

if ($runningProcess) {
    Write-Host "Found running process $scriptName.exe. Terminating..." -ForegroundColor Cyan
    $wasRunning = $true
    Stop-Process -Name $scriptName -Force
    Start-Sleep -Seconds 2
}

if (Test-Path $targetExe) {
    try {
        Write-Host "Removing old executable $targetExe..." -ForegroundColor Gray
        Remove-Item $targetExe -Force -ErrorAction Stop
    } catch {
        Write-Error "Failed to remove $targetExe. File might be locked. Exiting."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Exit
    }
}

Write-Host "Starting compilation to EXE..." -ForegroundColor Green
Invoke-PS2EXE $sourceFile $targetExe -RequireAdmin -noConsole

if (Test-Path $targetExe) {
    Write-Host "Compilation successful!" -ForegroundColor Green
    
    if ($wasRunning) {
        Write-Host "Restarting updated $scriptName.exe..." -ForegroundColor Yellow
        Start-Process $targetExe
    } else {
        Write-Host "$scriptName.exe was not running initially. No restart needed." -ForegroundColor Gray
    }
} else {
    Write-Error "Error: $targetExe was not created."
}

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
