# Builds the Windows desktop app and installer:
#   powershell -ExecutionPolicy Bypass -File desktop\build_desktop.ps1
# Needs Python 3.10-3.12 (64-bit) on PATH. Optional: Inno Setup 6 for the setup .exe.
# Output: dist\AISOCPlatform\AISOCPlatform.exe, dist\AISOCPlatform-portable.zip,
#         dist\AISOCPlatform-Setup-2.0.0.exe (with Inno Setup)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Run($exe, [string[]]$argv) { & $exe @argv; if ($LASTEXITCODE -ne 0) { throw "Failed ($LASTEXITCODE): $exe $($argv -join ' ')" } }

Step "Python build environment (.venv-desktop)"
if (-not (Test-Path ".venv-desktop\Scripts\python.exe")) { Run "python" @("-m", "venv", ".venv-desktop") }
$Py = Join-Path $Root ".venv-desktop\Scripts\python.exe"
Run $Py @("-m", "pip", "install", "--upgrade", "pip")
Run $Py @("-m", "pip", "install", "-r", "requirements.txt", "-r", "desktop\requirements-desktop.txt")

Step "Tests"
Run $Py @("-m", "pip", "install", "pytest", "pytest-asyncio", "httpx")
Run $Py @("-m", "pytest", "-q")

Step "Icon"
Run $Py @("desktop\make_icon.py")

Step "PyInstaller"
Run $Py @("-m", "PyInstaller", "desktop\ai_soc.spec", "--noconfirm", "--clean")

Step "Portable zip"
$Zip = "dist\AISOCPlatform-portable.zip"
if (Test-Path $Zip) { Remove-Item $Zip }
Compress-Archive -Path "dist\AISOCPlatform" -DestinationPath $Zip

Step "Installer (Inno Setup)"
$Iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($Iscc) { Run $Iscc @("desktop\installer.iss"); Write-Host "Installer: dist\AISOCPlatform-Setup-2.0.0.exe" -ForegroundColor Green }
else { Write-Host "Inno Setup 6 not found - skipped the installer (https://jrsoftware.org/isdl.php)" -ForegroundColor Yellow }
Write-Host "`nPortable app: dist\AISOCPlatform\AISOCPlatform.exe" -ForegroundColor Green
