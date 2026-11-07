# Builds sveto4.exe (Release) and copies it to .\dist.
# If sveto4.exe from .\dist is running, it is stopped and restarted after the build.
# Requires .NET SDK 8+ (only for building; the app itself runs on built-in .NET Framework 4.8).

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$project = 'src\Sveto4\Sveto4.csproj'
$output  = 'src\Sveto4\bin\Release\net48\sveto4.exe'
$dist    = Join-Path $PSScriptRoot 'dist'
$target  = Join-Path $dist 'sveto4.exe'

dotnet build $project -c Release -nologo
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }

$running = Get-Process -Name sveto4 -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $target }
if ($running) {
    Write-Host 'Stopping running sveto4.exe...' -ForegroundColor Yellow
    $running | Stop-Process -Force
    Start-Sleep -Seconds 1
}

New-Item -ItemType Directory -Force $dist | Out-Null
Copy-Item $output $target -Force
Write-Host "Built: $target" -ForegroundColor Green

if ($running) {
    Write-Host 'Restarting sveto4.exe...' -ForegroundColor Yellow
    Start-Process $target
}
