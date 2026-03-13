#!/bin/bash
set -e

EXT_UUID="mini-1984@security.local"
SYSTEM_EXT_DIR="/usr/share/gnome-shell/extensions/$EXT_UUID"
CONFIG_DIR="/etc/mini-1984"
LOG_FILE="/var/log/mini-1984.log"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

echo "==> Deploying mini-1984 extension system-wide..."

bash "$SCRIPT_DIR/build.sh"

# Install extension
mkdir -p "$SYSTEM_EXT_DIR"
cp "$SCRIPT_DIR/metadata.json" "$SYSTEM_EXT_DIR/"
cp "$SCRIPT_DIR/extension.js" "$SYSTEM_EXT_DIR/"

# Install config
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    cp "$SCRIPT_DIR/config.json.example" "$CONFIG_DIR/config.json"
    # Set production log path
    python3 -c "
import json
with open('$CONFIG_DIR/config.json', 'r') as f:
    cfg = json.load(f)
cfg['log_path'] = '$LOG_FILE'
with open('$CONFIG_DIR/config.json', 'w') as f:
    json.dump(cfg, f, indent=2)
    f.write('\n')
"
    echo "    Created config: $CONFIG_DIR/config.json"
else
    echo "    Config already exists: $CONFIG_DIR/config.json (not overwritten)"
fi

# Lock config — readable by all, writable only by root
chmod 644 "$CONFIG_DIR/config.json"
chown root:root "$CONFIG_DIR/config.json"

# Set up log file
touch "$LOG_FILE"
chmod 662 "$LOG_FILE"
chown root:adm "$LOG_FILE"

echo ""
echo "==> Deployment complete!"
echo ""
echo "Admin commands:"
echo ""
echo "  Edit config:  sudo nano $CONFIG_DIR/config.json"
echo "  View log:     cat $LOG_FILE"
echo ""
echo "  Enable for all users (each user runs):"
echo "    gnome-extensions enable $EXT_UUID"
echo ""
echo "  SIEM agent — add log source:"
echo "    Location: $LOG_FILE"
echo "    Format: JSON"
