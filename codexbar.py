"""
CodexBar for Windows v1.0.0
============================
System tray app that shows your REAL Claude usage.
Native customtkinter popup — no browser hack needed.

Requirements: pip install pystray Pillow customtkinter
Usage: python codexbar.py
"""

import os
import sys
import json
import time
import re
import sqlite3
import shutil
import subprocess
import threading
import ctypes
import ctypes.wintypes
import base64
import tempfile
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("ERRORE: Pillow mancante. Lancia: python -m pip install Pillow")
    sys.exit(1)

try:
    import pystray
    from pystray import MenuItem, Menu
except ImportError:
    print("ERRORE: pystray mancante. Lancia: python -m pip install pystray")
    sys.exit(1)

try:
    import customtkinter as ctk
except ImportError:
    print("ERRORE: customtkinter mancante. Lancia: python -m pip install customtkinter")
    sys.exit(1)

try:
    from winpty import PtyProcess
except ImportError:
    PtyProcess = None
    print("[CodexBar] winpty not found (pip install pywinpty). CLI /usage disabled.")


def _resource_path(relative_path):
    """Get absolute path to resource — works for dev and PyInstaller .exe."""
    if getattr(sys, 'frozen', False):
        base = Path(sys._MEIPASS)
    else:
        base = Path(__file__).parent
    return base / relative_path


# ─────────────────────────────────────────────
# Chromium cookie decryptor  (DPAPI + AES-GCM)
# ─────────────────────────────────────────────

class _CookieDecryptor:
    """Read and decrypt the sessionKey cookie from Chrome, Edge, or Brave.

    Chromium v80-126 encrypts cookies with AES-256-GCM (``v10`` prefix).
    Chromium 127+ uses App-Bound Encryption (``v20`` prefix).

    v10: The AES key lives in ``Local State``, encrypted with Windows DPAPI.
    v20: Requires Chrome's elevation-service COM object — attempted here,
         falls back gracefully if the service is unavailable.

    All crypto is pure ctypes (DPAPI via crypt32, AES-GCM via bcrypt.dll).
    """

    _LOCAL = os.environ.get("LOCALAPPDATA", "")
    BROWSERS = [
        ("Chrome", Path(_LOCAL) / "Google"         / "Chrome"        / "User Data"),
        ("Edge",   Path(_LOCAL) / "Microsoft"      / "Edge"          / "User Data"),
        ("Brave",  Path(_LOCAL) / "BraveSoftware"  / "Brave-Browser" / "User Data"),
    ]

    # ── public entry point ──────────────────────

    @classmethod
    def get_session_key(cls):
        """Return ``(cookie_value, browser_name)`` or ``(None, None)``."""
        for name, user_data in cls.BROWSERS:
            cookie_db   = user_data / "Default" / "Network" / "Cookies"
            local_state = user_data / "Local State"
            if not cookie_db.exists() or not local_state.exists():
                continue
            try:
                master_key = cls._master_key(local_state)
                if master_key is None:
                    print(f"    {name}: could not decrypt master key")
                    continue
                value = cls._read_cookie(cookie_db, master_key)
                if value:
                    return value, name
            except Exception as e:
                print(f"    {name} cookie err: {e}")
        return None, None

    # ── DPAPI via ctypes ────────────────────────

    class _BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    @classmethod
    def _dpapi_decrypt(cls, data: bytes) -> bytes | None:
        blob_in = cls._BLOB(len(data),
                            ctypes.create_string_buffer(data, len(data)))
        blob_out = cls._BLOB()
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0,
            ctypes.byref(blob_out),
        )
        if not ok:
            return None
        raw = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return raw

    # ── AES-256-GCM via Windows BCrypt ──────────

    class _BCRYPT_AUTH_INFO(ctypes.Structure):
        _fields_ = [
            ("cbSize",       ctypes.c_ulong),
            ("dwInfoVersion",ctypes.c_ulong),
            ("pbNonce",      ctypes.c_void_p),
            ("cbNonce",      ctypes.c_ulong),
            ("pbAuthData",   ctypes.c_void_p),
            ("cbAuthData",   ctypes.c_ulong),
            ("pbTag",        ctypes.c_void_p),
            ("cbTag",        ctypes.c_ulong),
            ("pbMacContext", ctypes.c_void_p),
            ("cbMacContext", ctypes.c_ulong),
            ("cbAAD",        ctypes.c_ulong),
            ("cbData",       ctypes.c_ulonglong),
            ("dwFlags",      ctypes.c_ulong),
        ]

    @classmethod
    def _aes_gcm_decrypt(cls, key: bytes, nonce: bytes,
                         ciphertext: bytes, tag: bytes) -> bytes:
        _b = ctypes.windll.bcrypt

        # open AES provider
        hAlg = ctypes.c_void_p()
        st = _b.BCryptOpenAlgorithmProvider(
            ctypes.byref(hAlg), ctypes.c_wchar_p("AES"), None,
            ctypes.c_ulong(0))
        if st != 0:
            raise OSError(f"BCryptOpenAlgorithmProvider 0x{st & 0xFFFFFFFF:08x}")

        try:
            # set GCM chaining mode — property value is raw UTF-16LE bytes
            mode_bytes = "ChainingModeGCM\0".encode("utf-16-le")
            mode_buf = (ctypes.c_ubyte * len(mode_bytes))(*mode_bytes)
            st = _b.BCryptSetProperty(
                hAlg, ctypes.c_wchar_p("ChainingMode"),
                mode_buf, ctypes.c_ulong(len(mode_bytes)),
                ctypes.c_ulong(0))
            if st != 0:
                raise OSError(f"BCryptSetProperty 0x{st & 0xFFFFFFFF:08x}")

            # import symmetric key
            hKey = ctypes.c_void_p()
            key_buf = (ctypes.c_ubyte * len(key))(*key)
            st = _b.BCryptGenerateSymmetricKey(
                hAlg, ctypes.byref(hKey), None, ctypes.c_ulong(0),
                key_buf, ctypes.c_ulong(len(key)), ctypes.c_ulong(0))
            if st != 0:
                raise OSError(f"BCryptGenerateSymmetricKey 0x{st & 0xFFFFFFFF:08x}")

            try:
                # build auth-info struct
                ai = cls._BCRYPT_AUTH_INFO()
                ai.cbSize        = ctypes.sizeof(ai)
                ai.dwInfoVersion = 1
                nonce_buf = (ctypes.c_ubyte * len(nonce))(*nonce)
                ai.pbNonce  = ctypes.cast(nonce_buf, ctypes.c_void_p)
                ai.cbNonce  = len(nonce)
                tag_buf = (ctypes.c_ubyte * len(tag))(*tag)
                ai.pbTag    = ctypes.cast(tag_buf, ctypes.c_void_p)
                ai.cbTag    = len(tag)

                # decrypt
                ct_buf   = (ctypes.c_ubyte * len(ciphertext))(*ciphertext)
                pt_buf   = (ctypes.c_ubyte * len(ciphertext))()
                cb_out   = ctypes.c_ulong()
                st = _b.BCryptDecrypt(
                    hKey,
                    ct_buf, ctypes.c_ulong(len(ciphertext)),
                    ctypes.byref(ai),
                    None, ctypes.c_ulong(0),
                    pt_buf, ctypes.c_ulong(len(ciphertext)),
                    ctypes.byref(cb_out), ctypes.c_ulong(0))
                if st != 0:
                    raise OSError(f"BCryptDecrypt 0x{st & 0xFFFFFFFF:08x}")
                return bytes(pt_buf[:cb_out.value])
            finally:
                _b.BCryptDestroyKey(hKey)
        finally:
            _b.BCryptCloseAlgorithmProvider(hAlg, ctypes.c_ulong(0))

    # ── master key from Local State ─────────────

    @classmethod
    def _master_key(cls, local_state_path: Path) -> bytes | None:
        with open(local_state_path, "r", encoding="utf-8") as f:
            js = json.load(f)
        b64 = js.get("os_crypt", {}).get("encrypted_key")
        if not b64:
            return None
        raw = base64.b64decode(b64)
        if raw[:5] != b"DPAPI":
            return None
        return cls._dpapi_decrypt(raw[5:])

    # ── read cookie from (possibly locked) DB ───

    @classmethod
    def _copy_locked_file(cls, src: Path, dst: str):
        """Copy a file that another process holds open (e.g. browser DB).

        Uses CreateFileW with full sharing flags to bypass the lock that
        ``shutil.copy2`` trips on.
        """
        _k = ctypes.windll.kernel32
        _k.CreateFileW.restype = ctypes.wintypes.HANDLE
        INVALID = ctypes.wintypes.HANDLE(-1).value

        hFile = _k.CreateFileW(
            str(src),
            0x80000000,         # GENERIC_READ
            0x7,                # FILE_SHARE_READ | WRITE | DELETE
            None,
            3,                  # OPEN_EXISTING
            0, None)
        if hFile == INVALID:
            err = ctypes.GetLastError()
            if err == 32:
                raise OSError("DB locked by browser (close it to read cookies)")
            raise OSError(f"CreateFileW error {err}")

        try:
            size = _k.GetFileSize(hFile, None)
            if size == 0xFFFFFFFF or size == 0:
                raise OSError("GetFileSize failed")
            buf = (ctypes.c_ubyte * size)()
            read = ctypes.wintypes.DWORD()
            _k.ReadFile(hFile, buf, size, ctypes.byref(read), None)
            with open(dst, "wb") as f:
                f.write(bytes(buf[:read.value]))
        finally:
            _k.CloseHandle(hFile)

    @classmethod
    def _read_cookie(cls, cookie_db: Path, master_key: bytes) -> str | None:
        """Query the Cookies SQLite DB and decrypt the sessionKey value."""
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.close()
        try:
            # try shutil first, fall back to CreateFileW for locked DBs
            try:
                shutil.copy2(cookie_db, tmp.name)
            except (PermissionError, OSError):
                cls._copy_locked_file(cookie_db, tmp.name)

            conn = sqlite3.connect(tmp.name)
            conn.text_factory = bytes
            rows = conn.execute(
                "SELECT encrypted_value, value "
                "FROM cookies "
                "WHERE host_key IN ('.claude.ai','claude.ai') "
                "  AND name = 'sessionKey' "
                "ORDER BY last_access_utc DESC LIMIT 1"
            ).fetchall()
            conn.close()
            if not rows:
                return None
            enc_val, plain_val = rows[0]
            # some Chromium builds store the value in plaintext
            if plain_val and plain_val != b"":
                return plain_val.decode("utf-8", errors="replace")
            if not enc_val or len(enc_val) < 4:
                return None
            return cls._decrypt_value(enc_val, master_key)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    @classmethod
    def _decrypt_value(cls, enc: bytes, key: bytes) -> str | None:
        prefix = enc[:3]
        # v10: standard AES-256-GCM with DPAPI-decrypted key
        if prefix == b"v10":
            nonce      = enc[3:15]
            ct_and_tag = enc[15:]
            if len(ct_and_tag) < 16:
                return None
            ciphertext = ct_and_tag[:-16]
            tag        = ct_and_tag[-16:]
            plain = cls._aes_gcm_decrypt(key, nonce, ciphertext, tag)
            return plain.decode("utf-8", errors="replace")
        # v20: App-Bound Encryption (Chrome 127+) — needs elevation service
        if prefix == b"v20":
            print("      cookie is v20 (App-Bound Encryption)")
            print("      v20 requires Chrome's elevation service; skipping")
            return None
        # Legacy: raw DPAPI blob (very old Chromium)
        plain = cls._dpapi_decrypt(enc)
        if plain:
            return plain.decode("utf-8", errors="replace")
        return None


# ─────────────────────────────────────────────
# Data fetcher
# ─────────────────────────────────────────────

class ClaudeDataFetcher:
    def __init__(self):
        self.data = self._empty()

    def _empty(self):
        return {
            "provider": "Claude", "plan": "Unknown", "updated": "Never",
            "session_used_pct": 0, "session_reset": "unknown",
            "weekly_used_pct": 0, "weekly_reset": "unknown",
            "opus_used_pct": 0,
            "cost_today": 0.0, "cost_today_tokens": "0",
            "cost_30d": 0.0, "cost_30d_tokens": "0",
            "source": "none", "error": None,
        }

    def fetch_all(self):
        print("[CodexBar] Fetching real usage data...")
        got_usage = False

        # 1) Try CLI
        cli = self._fetch_cli()
        if cli and cli.get("source") == "cli":
            self.data = cli
            got_usage = True
            print(f"  OK CLI: session {cli['session_used_pct']}%, weekly {cli['weekly_used_pct']}%")
        else:
            print("  -- CLI: not available")

        # 2) Try OAuth token from ~/.claude/.credentials.json
        if not got_usage:
            api = self._fetch_oauth_api()
            if api and api.get("source") == "api":
                self.data = api
                got_usage = True
                print(f"  OK OAuth: session {api['session_used_pct']}%, weekly {api['weekly_used_pct']}%")
            else:
                print("  -- OAuth: not available")

        # 3) Try browser cookie → Claude API
        if not got_usage:
            api = self._fetch_cookie_api()
            if api and api.get("source") == "api":
                self.data = api
                got_usage = True
                print(f"  OK Cookie: session {api['session_used_pct']}%, weekly {api['weekly_used_pct']}%")
            else:
                print("  -- Cookie: not available")

        # 4) Always try JSONL for cost data
        cost = self._fetch_jsonl()
        if cost:
            self.data["cost_today"] = cost["cost_today"]
            self.data["cost_today_tokens"] = cost["cost_today_tokens"]
            self.data["cost_30d"] = cost["cost_30d"]
            self.data["cost_30d_tokens"] = cost["cost_30d_tokens"]
            if self.data["source"] == "none":
                self.data["source"] = "logs"
            print(f"  OK Logs: today ${cost['cost_today']:.2f}, 30d ${cost['cost_30d']:.2f}")
        else:
            print("  -- Logs: no JSONL found")

        self.data["updated"] = datetime.now().strftime("Updated %H:%M")
        return self.data

    def _fetch_cli(self):
        """Spawn an interactive Claude session via PTY, send /usage, parse."""
        if PtyProcess is None:
            return None
        cmd = self._find_claude()
        if not cmd:
            return None
        try:
            raw = self._pty_usage(cmd)
            if raw and "%" in raw and ("session" in raw.lower() or "week" in raw.lower()):
                return self._parse_usage(raw)
        except Exception as e:
            print(f"    CLI err: {e}")
        return None

    @staticmethod
    def _pty_usage(cmd, startup_wait=5, trust_wait=3, cmd_wait=8):
        """Open claude in a PTY, send /usage, collect output, send /exit."""
        # Use home dir as cwd to avoid "Pty is closed" conflict when another
        # Claude Code session is active in the current working directory.
        neutral_cwd = str(Path.home())
        # Use simple 'cmd.exe /c claude' to avoid quoting issues with paths.
        proc = PtyProcess.spawn(
            "cmd.exe /c claude",
            dimensions=(40, 120),
            cwd=neutral_cwd,
        )
        chunks = []
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                try:
                    d = proc.read(8192)
                    if d:
                        chunks.append(d)
                except EOFError:
                    break
                except Exception:
                    time.sleep(0.1)

        t = threading.Thread(target=reader, daemon=True)
        t.start()

        try:
            time.sleep(startup_wait)       # wait for welcome / trust prompt
            # Accept the workspace trust prompt if shown ("Yes, I trust…")
            proc.write("\r")
            time.sleep(trust_wait)         # wait for welcome screen after trust
            proc.write("/usage\r")         # select from autocomplete + execute
            time.sleep(cmd_wait)           # wait for usage data to render
        finally:
            stop.set()
            try:
                proc.write("/exit\r")
            except Exception:
                pass
            time.sleep(1)
            try:
                proc.close(force=True)
            except Exception:
                pass
            t.join(timeout=3)

        return "".join(chunks)

    def _find_claude(self):
        places = [
            Path(os.environ.get("APPDATA", "")) / "npm" / "claude.cmd",
            Path(os.environ.get("APPDATA", "")) / "npm" / "claude",
            Path.home() / ".claude" / "local" / "claude.exe",
            Path.home() / "scoop" / "shims" / "claude.cmd",
        ]
        for p in places:
            if p.exists():
                print(f"    Found claude: {p}")
                return str(p)
        r = shutil.which("claude") or shutil.which("claude.cmd")
        if r:
            print(f"    Found claude in PATH: {r}")
        return r

    def _parse_usage(self, raw):
        """Parse the /usage output from the interactive Claude CLI.

        After ANSI stripping, the PTY output has this line structure
        (one piece of data per line, section header on its own line):

            L0: Current session
            L1: ███                 6%used
            L2: Reses4pm (Europe/Malta)        ← "Resets" mangled
            L3: Current week (all models)
            L4: ███▌                7%used
            L5: Resets Mar 27, 9:59am (Europe/Malta)
        """
        # strip VT100 / ANSI / OSC / control chars
        clean = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', raw)
        clean = re.sub(r'\x1b\][^\x07\x1b]*[\x07]', '', clean)
        clean = re.sub(r'\x1b[()>][0-9A-Z]', '', clean)
        clean = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', clean)

        d = self._empty()
        d["source"] = "cli"

        # After ANSI stripping the Windows PTY often puts all fields on
        # one line.  Insert newlines before known section headers and
        # before "Resets" / "%used" so the line-by-line parser works.
        clean = re.sub(r'(Current\s+session)', r'\n\1', clean, flags=re.I)
        clean = re.sub(r'(Current\s+week)', r'\n\1', clean, flags=re.I)
        clean = re.sub(r'(\d+\s*%\s*used)', r'\n\1', clean, flags=re.I)
        clean = re.sub(r'([Rr]es(?:et)?s?\s+\w)', r'\n\1', clean)

        lines = clean.split("\n")

        section = None        # "session" | "weekly" | "sonnet"
        for line in lines:
            lo = line.lower().strip()

            # ── section headers ──
            # Don't 'continue' — the header and data can land on the
            # same line after ANSI stripping in the Windows PTY.
            if "current session" in lo:
                section = "session"
            elif "current week" in lo and "sonnet" not in lo:
                section = "weekly"
            elif "sonnet" in lo and "week" in lo:
                section = "sonnet"

            if not section:
                continue

            # ── percentage: "6%used" / "6% used" ──
            m = re.search(r'(\d+)\s*%\s*used', line, re.I)
            if m:
                pct = int(m.group(1))
                if section == "session":
                    d["session_used_pct"] = pct
                elif section == "weekly":
                    d["weekly_used_pct"] = pct

            # ── reset: tolerant pattern for "Resets"/"Reses"/"Reset" ──
            # ANSI stripping can eat characters, so match broadly:
            #   "Resets 4pm …", "Reses4pm …", "Reset Mar 27 …"
            rm = re.search(
                r'[Rr]es[et]*s?\s*(.+)', line)
            if rm:
                val = rm.group(1).strip()
                # drop trailing noise ("Esc to cancel", timezone in parens)
                val = re.sub(r'\s*Esc.*$', '', val).rstrip(". ")
                val = re.sub(r'\s*\([^)]*\)\s*$', '', val).strip()
                if val and len(val) > 2:
                    if section == "session":
                        d["session_reset"] = val
                    elif section == "weekly":
                        d["weekly_reset"] = val

        # ── plan from welcome screen: "Claude Max" / "ClaudeMax" ──
        m = re.search(r'Claude\s*(Max|Pro|Team|Enterprise|Free)',
                       clean, re.I)
        if m:
            d["plan"] = m.group(1).title()

        return d

    # ── OAuth token fetcher ───────────────────

    _CREDS_PATH = Path.home() / ".claude" / ".credentials.json"

    def _fetch_oauth_api(self):
        """Read the OAuth access token that Claude Code stores locally,
        then call the Claude.ai API to get live usage data."""
        if not self._CREDS_PATH.exists():
            return None
        try:
            with open(self._CREDS_PATH, "r", encoding="utf-8") as f:
                creds = json.load(f)
            oauth = creds.get("claudeAiOauth") or {}
            token = oauth.get("accessToken")
            if not token:
                return None

            # pre-fill plan from local credentials (no network needed)
            tier = oauth.get("rateLimitTier") or oauth.get("subscriptionType") or ""
            plan_local = tier.replace("default_claude_", "").replace("_", " ").title() or "Pro"

            print(f"    OAuth token found ({len(token)} chars), plan hint: {plan_local}")
        except Exception as e:
            print(f"    OAuth creds err: {e}")
            return None

        result = self._call_claude_api(
            auth_header=("Authorization", f"Bearer {token}"),
            plan_hint=plan_local,
            source_label="api",
        )
        # Even if the API call failed, populate plan from local creds
        if result is None and plan_local:
            self.data["plan"] = plan_local
        return result

    # ── cookie-based API fetcher ────────────────

    def _fetch_cookie_api(self):
        """Read sessionKey from browser cookies, call Claude API."""
        session_key, browser = _CookieDecryptor.get_session_key()
        if not session_key:
            return None
        print(f"    Got sessionKey from {browser} ({len(session_key)} chars)")

        return self._call_claude_api(
            auth_header=("Cookie", f"sessionKey={session_key}"),
            plan_hint=None,
            source_label="api",
        )

    # ── shared API call logic ──────────────────

    def _call_claude_api(self, *, auth_header, plan_hint, source_label):
        """GET /organizations → /usage using the given auth header.

        ``auth_header`` is a (name, value) tuple, e.g.
        ("Authorization", "Bearer …") or ("Cookie", "sessionKey=…").
        """
        headers = {
            auth_header[0]: auth_header[1],
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/131.0.0.0 Safari/537.36",
            "Accept": "application/json",
        }

        # step 1: get organizations
        try:
            req = Request("https://api.claude.ai/api/organizations",
                          headers=headers)
            with urlopen(req, timeout=15) as resp:
                orgs = json.loads(resp.read())
        except (URLError, HTTPError, json.JSONDecodeError) as e:
            print(f"    API /organizations err: {e}")
            return None

        if not isinstance(orgs, list) or len(orgs) == 0:
            print("    API: empty org list")
            return None

        org = orgs[0]
        org_id = org.get("uuid") or org.get("id") or org.get("organization_id")
        if not org_id:
            print(f"    API: no org id in {list(org.keys())}")
            return None
        print(f"    Org: {org.get('name', '?')} ({org_id[:12]}...)")

        # step 2: get usage
        try:
            req = Request(
                f"https://api.claude.ai/api/organizations/{org_id}/usage",
                headers=headers)
            with urlopen(req, timeout=15) as resp:
                usage = json.loads(resp.read())
        except (URLError, HTTPError, json.JSONDecodeError) as e:
            print(f"    API /usage err: {e}")
            return None

        return self._parse_api_usage(usage, org, plan_hint, source_label)

    def _parse_api_usage(self, usage, org, plan_hint=None, source_label="api"):
        """Turn the /usage JSON into our standard data dict.

        The response structure is not publicly documented, so this
        tries several known field patterns defensively.
        """
        d = self._empty()
        d["source"] = source_label

        # plan name: prefer org data, then local hint
        plan_found = False
        for key in ("rate_limit_tier", "plan", "billing_type"):
            v = org.get(key)
            if v:
                d["plan"] = str(v).replace("_", " ").replace("default claude ", "").title()
                plan_found = True
                break
        if not plan_found and plan_hint:
            d["plan"] = plan_hint

        # ── helper: dig a percentage out of a sub-dict ──
        def pct_from(blob, *keys):
            """Return an int 0-100 or None."""
            if blob is None:
                return None
            # direct "X_pct" / "X_percent" / "X_percentage" field
            for k in keys:
                for suffix in ("_pct", "_percent", "_percentage", "_used_pct"):
                    v = blob.get(f"{k}{suffix}")
                    if v is not None:
                        return max(0, min(100, int(v)))
            # compute from used / limit
            used = blob.get("used") or blob.get("tokens_used") or 0
            limit = blob.get("limit") or blob.get("max_tokens") or blob.get("allowed") or 0
            if limit > 0:
                return max(0, min(100, int(used / limit * 100)))
            return None

        def reset_from(blob):
            """Return a human string like '3h 20m' or None."""
            if blob is None:
                return None
            for k in ("reset_at", "resets_at", "reset_time", "expires_at"):
                v = blob.get(k)
                if not v:
                    continue
                try:
                    dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                    delta = dt - datetime.now(dt.tzinfo)
                    secs = max(0, int(delta.total_seconds()))
                    h, m = divmod(secs // 60, 60)
                    if h >= 24:
                        return f"{h // 24}d {h % 24}h"
                    return f"{h}h {m:02d}m"
                except Exception:
                    pass
            return None

        # The API may return:
        #   {"daily_usage": {...}, "monthly_usage": {...}}
        #   {"session_limit": {...}, "weekly_limit": {...}}
        #   {"messageLimit": {"remaining": N, ...}}
        #   or a flat dict with percentage fields

        # try nested blobs first
        session_blob = (usage.get("daily_usage")
                        or usage.get("session_limit")
                        or usage.get("session")
                        or usage.get("messageLimit"))
        weekly_blob  = (usage.get("monthly_usage")
                        or usage.get("weekly_limit")
                        or usage.get("weekly")
                        or usage.get("longTermUsage"))

        sp = pct_from(session_blob, "daily", "session", "message", "used")
        wp = pct_from(weekly_blob,  "monthly", "weekly", "long_term", "used")

        # if nothing nested, try flat fields
        if sp is None:
            sp = pct_from(usage, "daily", "session", "message")
        if wp is None:
            wp = pct_from(usage, "monthly", "weekly", "long_term")

        # remaining-based: messageLimit.remaining / total
        if sp is None and isinstance(session_blob, dict):
            rem = session_blob.get("remaining")
            tot = session_blob.get("total") or session_blob.get("limit")
            if rem is not None and tot:
                sp = max(0, min(100, int((1 - rem / tot) * 100)))

        if sp is not None:
            d["session_used_pct"] = sp
        if wp is not None:
            d["weekly_used_pct"] = wp

        sr = reset_from(session_blob) or reset_from(usage)
        wr = reset_from(weekly_blob)
        if sr:
            d["session_reset"] = sr
        if wr:
            d["weekly_reset"] = wr

        # debug: show raw keys so user can report the shape
        print(f"    API usage keys: {list(usage.keys())}")
        if session_blob and isinstance(session_blob, dict):
            print(f"    session blob keys: {list(session_blob.keys())}")

        return d

    def _fetch_jsonl(self):
        dirs = [Path.home() / ".claude" / "projects", Path.home() / ".claude"]
        total_in = total_out = total_cache = today_in = today_out = 0
        seen = set()
        today = datetime.now().date()
        nfiles = 0

        for d in dirs:
            if not d.exists(): continue
            for f in d.rglob("*.jsonl"):
                nfiles += 1
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                        for line in fh:
                            line = line.strip()
                            if not line or len(line) < 10: continue
                            try: entry = json.loads(line)
                            except: continue
                            if entry.get("type") != "assistant": continue
                            usage = entry.get("message",{}).get("usage",{})
                            if not usage: continue
                            mid = entry.get("message",{}).get("id","")
                            rid = entry.get("requestId","")
                            key = f"{mid}:{rid}"
                            if key in seen: continue
                            seen.add(key)
                            inp = usage.get("input_tokens",0)
                            out = usage.get("output_tokens",0)
                            cr = usage.get("cache_read_input_tokens",0)
                            cc = usage.get("cache_creation_input_tokens",0)
                            total_in += inp; total_out += out; total_cache += cr+cc
                            ts = entry.get("timestamp","")
                            if ts:
                                try:
                                    if datetime.fromisoformat(ts.replace("Z","+00:00")).date() == today:
                                        today_in += inp; today_out += out
                                except: pass
                except: continue

        print(f"    Scanned {nfiles} files, {len(seen)} messages")
        if total_in + total_out == 0: return None

        c30 = (total_in*3 + total_out*15 + total_cache*1.5) / 1e6
        ct = (today_in*3 + today_out*15) / 1e6

        def fmt(n):
            if n >= 1e6: return f"{n/1e6:.0f}M"
            if n >= 1e3: return f"{n/1e3:.0f}K"
            return str(n)

        return {
            "cost_today": round(ct,2), "cost_today_tokens": fmt(today_in+today_out),
            "cost_30d": round(c30,2), "cost_30d_tokens": fmt(total_in+total_out+total_cache),
        }


# ─────────────────────────────────────────────
# Tray icon  (unchanged)
# ─────────────────────────────────────────────

def _load_logo(size=28):
    """Load and resize the Claude starburst logo from assets/."""
    logo_path = _resource_path("assets") / "claude-logo.png"
    if not logo_path.exists():
        return None
    try:
        img = Image.open(logo_path).convert("RGBA")
        img = img.resize((size, size), Image.LANCZOS)
        return img
    except Exception:
        return None


def make_icon(sp=1.0, wp=1.0, sz=64):
    """Generate a system-tray icon with Claude orange usage arcs."""
    img = Image.new('RGBA', (sz, sz), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # draw Claude starburst as tray icon background
    logo = _load_logo(sz)
    if logo:
        img.paste(logo, (0, 0), logo)
    else:
        # fallback: simple orange circle
        d.ellipse([4, 4, sz - 4, sz - 4], fill=(217, 119, 87, 255))

    return img


# ─────────────────────────────────────────────
# Native popup window — Official Claude design
# ─────────────────────────────────────────────

class CodexBarPopup(ctk.CTkToplevel):
    """Borderless popup with official Claude branding — white + orange."""

    WIDTH = 370

    # ── Claude official palette ──
    BG          = "#FFFFFF"
    SURFACE     = "#FAF9F7"       # very subtle warm gray for sections
    PRIMARY     = "#191918"       # near-black text
    SECONDARY   = "#6F6E77"       # muted gray text
    TERTIARY    = "#A8A7B0"       # light helper text
    CLAUDE_ORG  = "#D97757"       # the starburst orange
    CLAUDE_LITE = "#FCEEE8"       # pale orange tint
    CLAUDE_MID  = "#F0C8B4"       # medium orange for track backgrounds
    BAR_TRACK   = "#F0EFED"       # neutral track
    DIVIDER     = "#ECEAE6"
    HOVER       = "#F5F3EF"
    BADGE_TEXT  = "#C25B3B"       # darker orange for badge text
    BADGE_BG    = "#FDF0EB"       # very pale orange badge background

    def __init__(self, master, data, *, on_close=None, on_refresh=None, on_quit=None):
        super().__init__(master)
        self._data = data
        self._on_close = on_close
        self._on_refresh = on_refresh
        self._on_quit = on_quit

        self.overrideredirect(True)
        self.configure(fg_color=self.BG)
        self.attributes("-topmost", True)
        self.attributes("-alpha", 0.0)

        # load logo
        self._logo_img = _load_logo(32)
        self._logo_ctk = None
        if self._logo_img:
            self._logo_ctk = ctk.CTkImage(self._logo_img, size=(32, 32))

        self._build_ui()

        self.update_idletasks()
        work = self._work_area()
        w = self.WIDTH
        h = self.winfo_reqheight()
        self._target_x = work[0] - w - 12
        self._target_y = work[1] - h - 12
        self.geometry(f"{w}x{h}+{self._target_x}+{self._target_y + 14}")

        self.after(30, self._apply_dwm)

        self.bind("<Escape>", lambda e: self._close())
        self.bind("<FocusOut>", self._on_focus_out)
        self.focus_force()
        self.after(40, self._animate_in, 0)

    # ── DWM helpers ──

    @staticmethod
    def _work_area():
        try:
            from ctypes import wintypes
            rect = wintypes.RECT()
            ctypes.windll.user32.SystemParametersInfoW(48, 0, ctypes.byref(rect), 0)
            return (rect.right, rect.bottom)
        except Exception:
            return (1920, 1080)

    def _apply_dwm(self):
        try:
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            # rounded corners
            pref = ctypes.c_int(2)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, 33, ctypes.byref(pref), ctypes.sizeof(pref))
            # shadow
            class MARGINS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_int), ("r", ctypes.c_int),
                            ("t", ctypes.c_int), ("b", ctypes.c_int)]
            m = MARGINS(0, 0, 1, 0)
            ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(m))
        except Exception:
            pass

    # ── animation ──

    def _animate_in(self, step, total=14):
        if step > total:
            return
        t = step / total
        ease = 1.0 - (1.0 - t) ** 3
        y = int(self._target_y + 18 * (1.0 - ease))
        alpha = min(ease * 1.0, 0.94)        # slightly transparent final
        try:
            self.geometry(f"+{self._target_x}+{y}")
            self.attributes("-alpha", alpha)
            self.after(14, self._animate_in, step + 1, total)
        except Exception:
            pass

    # ── focus ──

    def _on_focus_out(self, event):
        self.after(120, self._check_focus)

    def _check_focus(self):
        try:
            fw = self.focus_get()
            if fw is not None and str(fw).startswith(str(self)):
                return
        except Exception:
            pass
        self._close()

    # ── bar colour ──

    @staticmethod
    def _bar_color(pct):
        """Orange shades: light when low, vivid when medium, red when high."""
        if pct <= 50:
            return "#D97757"          # Claude orange
        if pct <= 80:
            return "#E8943E"          # warm amber
        return "#D94A3D"              # alert red

    # ── UI construction ──

    def _build_ui(self):
        d = self._data
        sp = d["session_used_pct"]
        wp = d["weekly_used_pct"]
        op = d["opus_used_pct"]
        has_data = d["source"] != "none"
        has_cost = d["cost_today"] > 0 or d["cost_30d"] > 0

        # ═══════════════════════════════════════
        # WARM GRADIENT FLARE — Apple-style glow
        # Subtle peach-to-transparent at the top
        # ═══════════════════════════════════════
        for color, h in [
            ("#FCEEE8", 6), ("#FCEEE8", 5), ("#FDF1EC", 5),
            ("#FDF4F0", 4), ("#FEF6F3", 4), ("#FEF8F6", 3),
            ("#FEFAF9", 3), ("#FFFCFB", 2), ("#FFFDFD", 2),
        ]:
            ctk.CTkFrame(self, fg_color=color, height=h,
                         corner_radius=0).pack(fill="x")

        # ═══════════════════════════════════════
        # HERO HEADER — logo + Claude + plan badge
        # ═══════════════════════════════════════
        hero = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        hero.pack(fill="x", padx=22, pady=(6, 0))

        # logo + title row
        title_row = ctk.CTkFrame(hero, fg_color="transparent")
        title_row.pack(fill="x")

        if self._logo_ctk:
            ctk.CTkLabel(title_row, text="", image=self._logo_ctk,
                         width=32, height=32).pack(side="left", padx=(0, 10))

        ctk.CTkLabel(title_row, text="Claude",
                     font=("Segoe UI Semibold", 22),
                     text_color=self.PRIMARY).pack(side="left")

        # plan badge — orange pill
        badge = ctk.CTkLabel(title_row, text=f"  {d['plan']}  ",
                             font=("Segoe UI Semibold", 11),
                             text_color=self.BADGE_TEXT,
                             fg_color=self.BADGE_BG,
                             corner_radius=10)
        badge.pack(side="right")

        # meta line — updated time + source
        meta = ctk.CTkFrame(hero, fg_color="transparent")
        meta.pack(fill="x", pady=(6, 0))

        # green live dot
        dot = ctk.CTkFrame(meta, fg_color="#5CB176", corner_radius=4,
                           width=7, height=7)
        dot.pack(side="left", padx=(1, 7), pady=5)

        ctk.CTkLabel(meta, text=d["updated"],
                     font=("Segoe UI", 12),
                     text_color=self.SECONDARY).pack(side="left")

        ctk.CTkLabel(meta, text=f"  {d['source']}",
                     font=("Segoe UI", 11),
                     text_color=self.TERTIARY).pack(side="left")

        # ═══════════════════════════════════════
        # USAGE SECTION
        # ═══════════════════════════════════════
        if has_data:
            # divider
            ctk.CTkFrame(self, fg_color=self.DIVIDER,
                         height=1, corner_radius=0).pack(fill="x", padx=20, pady=(14, 0))

            # section label
            ctk.CTkLabel(self, text="Usage",
                         font=("Segoe UI Semibold", 13),
                         text_color=self.TERTIARY,
                         anchor="w").pack(fill="x", padx=22, pady=(12, 2))

            self._usage_bar("Session", sp, d["session_reset"])
            self._usage_bar("Weekly", wp, d["weekly_reset"])

            if op > 0:
                self._usage_bar("Opus", op)

        # ═══════════════════════════════════════
        # COST SECTION
        # ═══════════════════════════════════════
        if has_cost:
            ctk.CTkFrame(self, fg_color=self.DIVIDER,
                         height=1, corner_radius=0).pack(fill="x", padx=20, pady=(10, 0))

            ctk.CTkLabel(self, text="Cost",
                         font=("Segoe UI Semibold", 13),
                         text_color=self.TERTIARY,
                         anchor="w").pack(fill="x", padx=22, pady=(12, 4))

            cost_card = ctk.CTkFrame(self, fg_color=self.SURFACE,
                                     corner_radius=10)
            cost_card.pack(fill="x", padx=20, pady=(0, 2))

            cost_inner = ctk.CTkFrame(cost_card, fg_color="transparent")
            cost_inner.pack(fill="x", padx=14, pady=12)

            # today row
            today_row = ctk.CTkFrame(cost_inner, fg_color="transparent")
            today_row.pack(fill="x")
            ctk.CTkLabel(today_row, text="Today",
                         font=("Segoe UI", 12),
                         text_color=self.SECONDARY).pack(side="left")
            ctk.CTkLabel(today_row,
                         text=f"${d['cost_today']:.2f}",
                         font=("Segoe UI Semibold", 13),
                         text_color=self.PRIMARY).pack(side="right")

            # 30d row
            month_row = ctk.CTkFrame(cost_inner, fg_color="transparent")
            month_row.pack(fill="x", pady=(4, 0))
            ctk.CTkLabel(month_row, text="Last 30 days",
                         font=("Segoe UI", 12),
                         text_color=self.SECONDARY).pack(side="left")
            ctk.CTkLabel(month_row,
                         text=f"${d['cost_30d']:.2f}",
                         font=("Segoe UI Semibold", 13),
                         text_color=self.PRIMARY).pack(side="right")

        # ═══════════════════════════════════════
        # NO DATA
        # ═══════════════════════════════════════
        if not has_data and not has_cost:
            nd = ctk.CTkFrame(self, fg_color="transparent")
            nd.pack(fill="x", padx=20, pady=28)
            ctk.CTkLabel(nd, text="No session data yet",
                         font=("Segoe UI", 13),
                         text_color=self.SECONDARY).pack()
            ctk.CTkLabel(nd, text="Run /usage in Claude Code to populate",
                         font=("Segoe UI", 11),
                         text_color=self.TERTIARY).pack(pady=(4, 0))

        # ═══════════════════════════════════════
        # FOOTER — links + actions
        # ═══════════════════════════════════════
        ctk.CTkFrame(self, fg_color=self.DIVIDER,
                     height=1, corner_radius=0).pack(fill="x", padx=20, pady=(10, 0))

        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.pack(fill="x", padx=14, pady=(6, 4))

        for label, action in [
            ("Dashboard", lambda: self._open_url("https://claude.ai/settings/billing")),
            ("Status",    lambda: self._open_url("https://status.anthropic.com")),
        ]:
            btn = ctk.CTkButton(
                footer, text=label,
                font=("Segoe UI", 12),
                text_color=self.CLAUDE_ORG,
                fg_color="transparent",
                hover_color=self.CLAUDE_LITE,
                anchor="w", height=30, corner_radius=8,
                width=80, command=action)
            btn.pack(side="left", padx=2)

        # refresh + quit on the right
        quit_btn = ctk.CTkButton(
            footer, text="Quit",
            font=("Segoe UI", 12),
            text_color=self.TERTIARY,
            fg_color="transparent",
            hover_color=self.HOVER,
            anchor="center", height=30, corner_radius=8,
            width=50, command=self._do_quit)
        quit_btn.pack(side="right", padx=2)

        refresh_btn = ctk.CTkButton(
            footer, text="Refresh",
            font=("Segoe UI Semibold", 12),
            text_color="#FFFFFF",
            fg_color=self.CLAUDE_ORG,
            hover_color="#C4654A",
            anchor="center", height=30, corner_radius=8,
            width=70, command=self._do_refresh)
        refresh_btn.pack(side="right", padx=2)

        # bottom padding
        ctk.CTkFrame(self, fg_color="transparent", height=8,
                     corner_radius=0).pack(fill="x")

    def _usage_bar(self, label, pct, reset=None):
        color = self._bar_color(pct)

        section = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        section.pack(fill="x", padx=20, pady=(4, 2))

        # label row — "Session" left, "6%" right
        label_row = ctk.CTkFrame(section, fg_color="transparent")
        label_row.pack(fill="x")

        ctk.CTkLabel(label_row, text=label,
                     font=("Segoe UI Semibold", 13),
                     text_color=self.PRIMARY).pack(side="left")

        ctk.CTkLabel(label_row, text=f"{pct}%",
                     font=("Segoe UI Semibold", 13),
                     text_color=color).pack(side="right")

        # progress bar — rounded, orange fill on light track
        track = ctk.CTkFrame(section, fg_color=self.BAR_TRACK,
                             height=8, corner_radius=4)
        track.pack(fill="x", pady=(5, 4))
        track.pack_propagate(False)

        fill_width = max(pct / 100.0, 0.015)
        fill = ctk.CTkFrame(track, fg_color=color, corner_radius=4, height=8)
        fill.place(relx=0, rely=0, relwidth=fill_width, relheight=1.0)

        # reset text
        if reset and reset != "unknown":
            ctk.CTkLabel(section, text=f"Resets {reset}",
                         font=("Segoe UI", 11),
                         text_color=self.TERTIARY,
                         anchor="w").pack(fill="x")

    # ── helpers ──

    def _open_url(self, url):
        webbrowser.open(url)
        self._close()

    def _close(self):
        try:
            self.destroy()
        except Exception:
            pass
        if self._on_close:
            self._on_close()

    def _do_refresh(self):
        self._close()
        if self._on_refresh:
            self._on_refresh()

    def _do_quit(self):
        self._close()
        if self._on_quit:
            self._on_quit()


# ─────────────────────────────────────────────
# App  (tkinter main loop + pystray background)
# ─────────────────────────────────────────────

class CodexBarApp:
    def __init__(self):
        self.fetcher = ClaudeDataFetcher()
        self.root = None
        self.tray = None
        self.popup = None
        self.running = True

    def start(self):
        print("[CodexBar] Fetching your real usage data...\n")
        self.fetcher.fetch_all()
        print(f"\n[CodexBar] Source: {self.fetcher.data['source']}")

        # ── hidden tkinter root ──
        ctk.set_appearance_mode("light")
        self.root = ctk.CTk()
        self.root.withdraw()

        # ── tray icon (background thread) ──
        d = self.fetcher.data
        sl = (100 - d["session_used_pct"]) / 100
        wl = (100 - d["weekly_used_pct"]) / 100

        menu = Menu(
            MenuItem('Open CodexBar', self._tray_open, default=True),
            MenuItem('Refresh', self._tray_refresh),
            Menu.SEPARATOR,
            MenuItem('Quit', self._tray_quit),
        )
        self.tray = pystray.Icon('CodexBar', make_icon(sl, wl), 'CodexBar', menu)
        threading.Thread(target=self.tray.run, daemon=True).start()

        # ── auto-refresh every 5 min ──
        self.root.after(300_000, self._auto_refresh)

        print("\n" + "=" * 50)
        print("  CodexBar running in system tray!")
        print("  Look for the icon near the clock.")
        print("  Click ^ (arrow) if hidden.")
        print("  Double-click = open panel.")
        print("=" * 50 + "\n")

        # ── mainloop (blocks) ──
        self.root.mainloop()

    # ── tray callbacks (called from pystray thread) ──

    def _tray_open(self, *_):
        self.root.after(0, self._show_popup)

    def _tray_refresh(self, *_):
        self.root.after(0, self._do_refresh)

    def _tray_quit(self, *_):
        self.root.after(0, self._do_quit)

    # ── popup ──

    def _show_popup(self):
        if self.popup is not None:
            try:
                self.popup.destroy()
            except Exception:
                pass
            self.popup = None

        self.popup = CodexBarPopup(
            self.root,
            self.fetcher.data,
            on_close=self._on_popup_closed,
            on_refresh=lambda: self.root.after(0, self._do_refresh),
            on_quit=lambda: self.root.after(0, self._do_quit),
        )

    def _on_popup_closed(self):
        self.popup = None

    # ── refresh ──

    def _do_refresh(self):
        def bg():
            self.fetcher.fetch_all()
            d = self.fetcher.data
            self.tray.icon = make_icon(
                (100 - d["session_used_pct"]) / 100,
                (100 - d["weekly_used_pct"]) / 100)
            print("[CodexBar] Refreshed")
        threading.Thread(target=bg, daemon=True).start()

    def _auto_refresh(self):
        if not self.running:
            return
        self._do_refresh()
        self.root.after(300_000, self._auto_refresh)

    # ── quit ──

    def _do_quit(self):
        print("[CodexBar] Bye!")
        self.running = False
        try:
            self.tray.stop()
        except Exception:
            pass
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            pass
        sys.exit(0)


# ─────────────────────────────────────────────

if __name__ == '__main__':
    print(r"""
   ========================================
    CodexBar for Windows v1.0.0
    Native popup — no browser needed
   ========================================
    """)
    CodexBarApp().start()
