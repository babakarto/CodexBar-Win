# CodexBar for Windows

System tray app that shows your **real Claude Code usage** — session limits, weekly limits, reset times, and API costs — right from the taskbar.

Windows port of [steipete/CodexBar](https://github.com/steipete/CodexBar) for macOS.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Windows 10/11](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)
![License MIT](https://img.shields.io/badge/license-MIT-green)

## Features

- **System tray icon** with the Claude logo
- **Native popup** — borderless customtkinter window with rounded corners, slide-up animation, and frosted glass transparency
- **Live usage data** from Claude Code CLI via PTY (same method as the macOS version)
- **Fallback chain**: CLI (PTY) &rarr; OAuth token &rarr; Browser cookies &rarr; JSONL logs
- **Session & weekly usage bars** with percentage and reset countdowns
- **Cost tracking** — scans local JSONL logs for today and 30-day spend
- **Auto-refresh** every 5 minutes

## Quick Start

```
git clone https://github.com/AlessandroAlessandrini/CodexBar-Win.git
cd CodexBar-Win
pip install -r requirements.txt
python codexbar.py
```

Or double-click `CodexBar.bat`.

## Requirements

- **Python 3.10+**
- **Windows 10/11**
- **Claude Code CLI** installed and logged in (`claude` in PATH)

Dependencies (auto-installed):
```
pystray>=0.19.5
Pillow>=10.0
customtkinter>=5.2
pywinpty>=2.0
```

## How It Gets Data

CodexBar tries multiple methods in order, using the first that succeeds:

| Method | What it does |
|--------|-------------|
| **CLI (PTY)** | Spawns an interactive `claude` session via pseudo-terminal, sends `/usage`, parses the output. This is the primary and most reliable method. |
| **OAuth token** | Reads `~/.claude/.credentials.json`, calls the Claude.ai API with the stored access token. |
| **Browser cookies** | Reads `sessionKey` from Chrome/Edge/Brave cookie databases, decrypts with DPAPI + AES-GCM, calls the Claude.ai API. |
| **JSONL logs** | Scans `~/.claude/projects/` for conversation logs, calculates token costs. Always runs for cost data regardless of which method provides usage. |

## Build Standalone .exe

```powershell
.\build.ps1
# Output: dist/CodexBar.exe
```

## Credits

Inspired by [steipete/CodexBar](https://github.com/steipete/CodexBar) (MIT) — the original macOS menu bar app.

## License

MIT
