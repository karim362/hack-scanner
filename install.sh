#!/usr/bin/env bash
set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KAHA="$ROOT/bin/kaha"
[ ! -f "$KAHA" ] && { echo "Error: kaha not found"; exit 1; }
chmod +x "$KAHA" "$ROOT/bin/scan.sh" "$ROOT/lib/bootstrap.sh"
bash "$ROOT/lib/bootstrap.sh"
RC="$HOME/.bashrc"; [ -n "$ZSH_VERSION" ] && RC="$HOME/.zshrc"
grep -q "alias kaha=" "$RC" 2>/dev/null || { echo "" >> "$RC"; echo "# Hack Scanner" >> "$RC"; echo "alias kaha=\"$KAHA\"" >> "$RC"; echo "✔ Alias added to $RC"; }
echo "✔ Done. Run: source $RC && kaha"
