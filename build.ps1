<# Build CodexBar.exe - Standalone Windows executable #>

Write-Host "[*] Building CodexBar.exe..." -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Ensure PyInstaller
pip install pyinstaller --quiet

# Generate multi-resolution icon from Claude logo
Write-Host "[*] Generating icon..." -ForegroundColor Cyan
python -c @"
from PIL import Image
img = Image.open('assets/claude-logo.png').convert('RGBA')
img.save('assets/codexbar.ico', format='ICO',
         sizes=[(16,16),(32,32),(48,48),(64,64),(128,128),(256,256)])
print('    Icon generated: 16/32/48/64/128/256px')
"@

# Build
Write-Host "[*] Running PyInstaller..." -ForegroundColor Cyan
pyinstaller --onefile `
    --noconsole `
    --name "CodexBar" `
    --icon "assets/codexbar.ico" `
    --add-data "assets;assets" `
    --hidden-import pystray._win32 `
    --hidden-import customtkinter `
    --collect-data customtkinter `
    --hidden-import winpty `
    --collect-binaries pywinpty `
    codexbar.py

if (Test-Path "dist/CodexBar.exe") {
    $size = [math]::Round((Get-Item "dist/CodexBar.exe").Length / 1MB, 1)
    Write-Host ""
    Write-Host "[OK] Built: dist/CodexBar.exe ($size MB)" -ForegroundColor Green
    Write-Host "     Copy it anywhere and run!" -ForegroundColor DarkGray
} else {
    Write-Host "[FAIL] Build failed - CodexBar.exe not found" -ForegroundColor Red
    exit 1
}
