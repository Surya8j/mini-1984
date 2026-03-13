#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GNOME_VERSION=$(gnome-shell --version 2>/dev/null | grep -oP '\d+' | head -1)

if [ -z "$GNOME_VERSION" ]; then
    echo "ERROR: Could not detect GNOME Shell version."
    echo "Usage: ./build.sh [42|43|44|45|46|47]"
    exit 1
fi

[ -n "$1" ] && GNOME_VERSION="$1"

echo "==> Detected GNOME Shell version: $GNOME_VERSION"

if [ "$GNOME_VERSION" -ge 45 ]; then
    echo "==> Building for GNOME 45+ (ESM format)"
    cp "$SCRIPT_DIR/src/extension-esm.js" "$SCRIPT_DIR/extension.js"
    python3 -c "
import json
with open('$SCRIPT_DIR/metadata.json', 'r') as f:
    meta = json.load(f)
meta['shell-version'] = ['45', '46', '47']
with open('$SCRIPT_DIR/metadata.json', 'w') as f:
    json.dump(meta, f, indent=2)
    f.write('\n')
"
else
    echo "==> Building for GNOME 42–44 (legacy format)"
    cp "$SCRIPT_DIR/src/extension-legacy.js" "$SCRIPT_DIR/extension.js"
    python3 -c "
import json
with open('$SCRIPT_DIR/metadata.json', 'r') as f:
    meta = json.load(f)
meta['shell-version'] = ['42', '43', '44']
with open('$SCRIPT_DIR/metadata.json', 'w') as f:
    json.dump(meta, f, indent=2)
    f.write('\n')
"
fi

echo "==> extension.js generated for GNOME $GNOME_VERSION"
