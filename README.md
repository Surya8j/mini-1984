# mini-1984 — GNOME Shell Endpoint Monitoring Extension

Lightweight GNOME topbar extension for endpoint monitoring:
1. **Screenshot/screencast detection** — alerts when screenshots are taken while sensitive sites are visible
2. **Personal email detection** — alerts when personal email logins are detected on work endpoints

## How It Works

```
Topbar:  :)  →  :(  (red, 5s)  →  :)

Detection:
  Screenshot → scan visible browser windows → match sensitive patterns → alert + log
  Email poll → scan browser titles every 5s → match personal email patterns → alert + log (once per match)

Config priority:
  /etc/mini-1984/config.json (admin, locked) → ~/.config/mini-1984/config.json (local)
```

## Config File

All configuration is in a single JSON file — no gsettings commands needed:

```json
{
  "show_icon": true,
  "warning_duration": 5,

  "screenshot": {
    "enabled": true,
    "sensitive_patterns": ["App Dashboard", "admin.example.com"],
    "ignore_patterns": ["Google Search", "- Google -", "google.com/search"]
  },

  "email": {
    "enabled": true,
    "personal_patterns": ["@gmail.com", "@yahoo.com", "@outlook.com"],
    "work_patterns": ["@company.com"]
  },

  "log_path": ""
}
```

| Key | Description |
|-----|-------------|
| `show_icon` | Show/hide topbar icon. Detection runs silently when hidden. |
| `warning_duration` | Seconds to show `:(` before reverting to `:)` |
| `screenshot.sensitive_patterns` | Strings to match in browser window titles |
| `screenshot.ignore_patterns` | If title matches these, skip (e.g. search results) |
| `email.personal_patterns` | Email domains to flag (e.g. `@gmail.com`) |
| `email.work_patterns` | Email domains to ignore (your org's domain) |
| `log_path` | Custom log path. Empty = `~/.local/share/mini-1984/events.log` |

## Detection Details

### Screenshot Detection

Triggers when a screenshot/screencast tool is used while a sensitive site is visible.

**Methods:**
- Window monitor — detects screenshot tool windows (flameshot, gnome-screenshot, spectacle, etc.)
- D-Bus monitor — catches built-in GNOME screenshot (PrtSc, Alt+PrtSc)
- File monitor — watches for new screenshot/screencast files in resolved paths

**File paths resolved at runtime:**
- XDG user directories (`xdg-user-dir PICTURES/VIDEOS`)
- Flameshot save path from `~/.config/flameshot/flameshot.ini`
- `~/Videos/Screencasts` for GNOME screencast (Ctrl+Shift+Alt+R)
- Fallback: `~/Pictures`, `~/Videos`, `/tmp`

**Scope:**
- Only visible browser windows on the active workspace (all monitors)
- Only the active tab per browser window
- Minimized windows are skipped

### Email Detection

Polls browser window titles every 5 seconds for personal email patterns. Logs once per unique window+title combination — no repeated alerts for the same tab.

**Resets when:**
- Tab title changes
- GNOME Shell restarts
- New browser window opens

## GNOME Version Support

Supports GNOME 42–47. The build script auto-detects your version:

```bash
./build.sh        # auto-detect
./build.sh 42     # force GNOME 42–44
./build.sh 46     # force GNOME 45+
```

## Install — Local Testing (no sudo)

```bash
chmod +x install-local.sh build.sh
./install-local.sh
```

Edit your config:

```bash
nano ~/.config/mini-1984/config.json
```

Restart GNOME Shell (Alt+F2 → `r` → Enter), then enable:

```bash
gnome-extensions enable mini-1984@security.local
```

### Uninstall (local)

```bash
gnome-extensions disable mini-1984@security.local
rm -rf ~/.local/share/gnome-shell/extensions/mini-1984@security.local
rm -rf ~/.config/mini-1984
rm -rf ~/.local/share/mini-1984
```

## Deploy — Production (admin/sudo)

```bash
sudo chmod +x deploy-admin.sh build.sh
sudo ./deploy-admin.sh
```

Edit the admin config:

```bash
sudo nano /etc/mini-1984/config.json
```

The config at `/etc/` is owned by root — users can read but not modify.

Each user enables with:

```bash
gnome-extensions enable mini-1984@security.local
```

### Uninstall (admin)

```bash
sudo rm -rf /usr/share/gnome-shell/extensions/mini-1984@security.local
sudo rm -rf /etc/mini-1984
sudo rm /var/log/mini-1984.log
```

## SIEM Integration

Sample rules in `siem-rules/mini_1984.xml`.

Configure your SIEM agent to monitor:

```
Location: /var/log/mini-1984.log (production) or ~/.local/share/mini-1984/events.log (local)
Format: JSON (one event per line)
```

### Alert Levels

| Rule ID | Level | Event |
|---------|-------|-------|
| 100800  | 10    | Screenshot on sensitive site |
| 100801  | 12    | 3+ screenshots in 5 min (same user) |
| 100802  | 12    | Screen recording tool |
| 100810  | 8     | Personal email detected |
| 100811  | 10    | Repeated personal email usage |

## Log Format

**Screenshot event:**
```json
{
  "timestamp": "2026-03-10T14:30:22.123Z",
  "event_type": "screenshot_on_sensitive_site",
  "hostname": "dev-laptop",
  "user": "john",
  "detection_source": "window_monitor",
  "detection_tool": "flameshot",
  "sensitive_windows": [{"title": "Dashboard - Google Chrome", "browser": "Google-chrome", "match_type": "pattern", "match_value": "dashboard"}]
}
```

**Email event:**
```json
{
  "timestamp": "2026-03-10T14:35:10.456Z",
  "event_type": "personal_email_detected",
  "hostname": "dev-laptop",
  "user": "john",
  "detection_source": "email_monitor",
  "window_title": "Inbox - user@gmail.com - Gmail - Google Chrome",
  "browser": "Google-chrome",
  "matched_pattern": "@gmail.com"
}
```

## Project Structure

```
mini-1984@security.local/
├── build.sh                # Auto-detects GNOME version
├── install-local.sh        # Local install (no sudo)
├── deploy-admin.sh         # Production deploy (sudo)
├── config.json.example     # Sample config
├── metadata.json
├── src/
│   ├── extension-legacy.js # GNOME 42–44
│   └── extension-esm.js    # GNOME 45+
├── siem-rules/
│   └── mini_1984.xml       # Sample SIEM rules
└── .gitignore
```

## Security Hardening (admin)

The admin config at `/etc/mini-1984/config.json` is read-only for users. However, a user could bypass detection by:
- Disabling the extension
- Installing a modified local copy
- The local config at `~/.config/` takes lower priority than `/etc/`

To prevent bypass:
- Lock GNOME extension management via dconf
- Restrict `~/.local/share/gnome-shell/extensions/` with `chattr +i`
- Monitor for extension tampering via your SIEM
- The `show_icon: false` option lets the extension run silently

## Requirements

- GNOME Shell 42+ (tested on 42–47)
- No external dependencies
