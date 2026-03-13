#!/bin/bash
set -e

EXT_UUID="mini-1984@security.local"
EXT_DIR="$HOME/.local/share/gnome-shell/extensions/$EXT_UUID"
CONFIG_DIR="$HOME/.config/mini-1984"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Building for your GNOME version..."
bash "$SCRIPT_DIR/build.sh"

echo "==> Installing mini-1984 extension locally..."

mkdir -p "$EXT_DIR"
cp "$SCRIPT_DIR/metadata.json" "$EXT_DIR/"
cp "$SCRIPT_DIR/extension.js" "$EXT_DIR/"

# Set up config if not exists
mkdir -p "$CONFIG_DIR"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    cp "$SCRIPT_DIR/config.json.example" "$CONFIG_DIR/config.json"
    echo "    Created config: $CONFIG_DIR/config.json"
else
    echo "    Config already exists: $CONFIG_DIR/config.json (not overwritten)"
fi

# Create log directory
mkdir -p "$HOME/.local/share/mini-1984"

echo ""
echo "==> Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit config: $CONFIG_DIR/config.json"
echo "  2. Restart GNOME Shell:"
echo "     - X11:    Alt+F2 → type 'r' → Enter"
echo "     - Wayland: Log out and log back in"
echo "  3. Enable: gnome-extensions enable $EXT_UUID"
echo "  4. Verify: look for ':)' in topbar"
echo ""
echo "Config: $CONFIG_DIR/config.json"
echo "Log:    ~/.local/share/mini-1984/events.log"
