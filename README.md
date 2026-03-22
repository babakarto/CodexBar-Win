# CodexBar for Windows

> System tray app that shows your **real Claude Code & OpenAI Codex usage** — session limits, weekly limits, reset times, and API costs — right from the Windows taskbar.

Windows port of [steipete/CodexBar](https://github.com/steipete/CodexBar) for macOS.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Windows 10/11](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)
![License MIT](https://img.shields.io/badge/license-MIT-green)

<p align="center">
  <img src="docs/claude.png?v=5" alt="CodexBar — Claude tab" width="370">
  <img src="docs/codex.png?v=5" alt="CodexBar — Codex tab" width="370">
</p>

## Download

### Standalone .exe (no Python needed)

1. Go to [**Releases**](https://github.com/babakarto/CodexBar-Win/releases/latest)
2. Download `CodexBar.exe` or `CodexBar-Win.zip`
3. Run `CodexBar.exe` — it appears in your system tray

### Run from source

```bash
git clone https://github.com/babakarto/CodexBar-Win.git
cd CodexBar-Win
pip install -r requirements.txt
python codexbar.py
```

Or double-click `CodexBar.bat` — it installs dependencies and launches.

## Requirements

- **Windows 10 or 11**
- **Claude Code CLI** installed and logged in (`claude` in PATH)
- Python 3.10+ (only if running from source)

## Features

- **Dual provider** — Claude Code + OpenAI Codex tabs with smooth animated transitions
- **Live usage bars** — session and weekly limits with color-coded percentages
- **Reset countdowns** — know exactly when your limits refresh
- **Cost tracking** — today's spend and 30-day totals from local logs
- **Native popup** — customtkinter window with rounded corners, slide-up animation
- **Provider branding** — Claude orange palette + OpenAI dark/green theme, tray icon switches per tab
- **Auto-refresh** — updates every 5 minutes
- **Zero config** — reads everything Claude Code already stores locally

## How It Gets Data

CodexBar tries multiple methods in order, using the first that succeeds:

| Priority | Method | What it does |
|----------|--------|-------------|
| 1 | **CLI (PTY)** | Spawns interactive `claude` via pseudo-terminal, sends `/usage`, parses output |
| 2 | **OAuth token** | Reads `~/.claude/.credentials.json`, calls Claude.ai API |
| 3 | **Browser cookies** | Reads `sessionKey` from Chrome/Edge/Brave, decrypts with DPAPI + AES-GCM |
| 4 | **JSONL logs** | Scans `~/.claude/projects/` for conversation logs (always runs for cost data) |

## macOS vs Windows

| | [CodexBar](https://github.com/steipete/CodexBar) (macOS) | CodexBar-Win (Windows) |
|---|---|---|
| **UI** | SwiftUI menu bar popup | customtkinter system tray popup |
| **Language** | Swift | Python |
| **Providers** | 16+ (Claude, Cursor, Copilot, Gemini...) | Claude Code + OpenAI Codex |
| **Data source** | CLI PTY | CLI PTY → OAuth → Cookies → JSONL |
| **Install** | `brew install --cask steipete/tap/codexbar` | Download .exe or `pip install` |
| **Auto-update** | Sparkle framework | GitHub Releases |
| **Cookie decrypt** | macOS Keychain | Windows DPAPI + AES-GCM via ctypes |
| **Size** | ~5 MB (native) | ~30 MB (bundled Python runtime) |
| **License** | MIT | MIT |

## Build Standalone .exe

```powershell
.\build.ps1
# Output: dist/CodexBar.exe (~30 MB)
```

Requires PyInstaller (`pip install pyinstaller`). The script handles icon generation and all hidden imports.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| No usage data shown | Make sure `claude` is in PATH and you're logged in |
| "winpty not found" | `pip install pywinpty` |
| Antivirus flags .exe | PyInstaller executables are commonly false-positived. Add an exception or run from source |
| Popup doesn't appear | Check the system tray overflow area (click ^ arrow near clock) |
| CLI shows 0% | Another Claude Code session may be running — CodexBar spawns its own PTY |

## Credits

Windows port inspired by [steipete/CodexBar](https://github.com/steipete/CodexBar) (MIT) by [Peter Steinberger](https://steipete.me) — the original macOS menu bar app.

## License

MIT
