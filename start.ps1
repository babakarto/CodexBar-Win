<# CodexBar for Windows - Quick Setup & Launch #>

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║      CodexBar for Windows v1.0.0      ║" -ForegroundColor Magenta
Write-Host "  ║   Claude Code Usage Monitor            ║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Check Python
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Host "[!] Python not found. Install Python 3.10+ from python.org" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Python found: $($python.Source)" -ForegroundColor Green

# Install dependencies
Write-Host "[*] Installing dependencies..." -ForegroundColor Cyan
pip install -r requirements.txt --quiet --break-system-packages 2>$null
if (-not $?) {
    pip install -r requirements.txt --quiet
}

Write-Host "[*] Dependencies installed." -ForegroundColor Green

# Create config directory
$configDir = "$env:USERPROFILE\.codexbar"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    Write-Host "[*] Config directory created: $configDir" -ForegroundColor Green
}

# Launch
Write-Host ""
Write-Host "[*] Launching CodexBar..." -ForegroundColor Yellow
Write-Host "    Right-click the tray icon to open menu" -ForegroundColor DarkGray
Write-Host "    Double-click to open the usage panel" -ForegroundColor DarkGray
Write-Host ""

python codexbar.py
