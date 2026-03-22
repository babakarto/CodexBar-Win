<# Build CodexBar.exe - Standalone Windows executable #>

Write-Host "[*] Building CodexBar.exe..." -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Ensure PyInstaller
pip install pyinstaller --quiet

# Build
pyinstaller --onefile `
    --noconsole `
    --name "CodexBar" `
    --icon "assets/codexbar.ico" `
    --add-data "assets;assets" `
    --hidden-import pystray._win32 `
    codexbar.py

Write-Host ""
Write-Host "[OK] Built: dist/CodexBar.exe" -ForegroundColor Green
Write-Host "     Copy it anywhere and run!" -ForegroundColor DarkGray
