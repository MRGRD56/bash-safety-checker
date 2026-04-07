#!/bin/bash
# Claude Code PreToolUse hook for Bash/PowerShell command safety checking.
# Reads Claude Code stdin JSON, extracts command, calls checker.py,
# formats result for Claude Code approval UI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Read all of stdin (Claude Code sends JSON)
input=$(cat)

# Extract the command from tool_input.command using Python (no jq dependency)
command=$(python "$SCRIPT_DIR/checker_extract.py" "$input" 2>/dev/null) || exit 0

# Skip empty commands
[ -z "$command" ] && exit 0

# Call checker.py — on failure, gracefully pass through
result=$(python "$SCRIPT_DIR/checker.py" "$command" 2>/dev/null) || exit 0

# Parse result and format for Claude Code (loads .env via dotenv for BSC_AUTO_ALLOW_READONLY)
python -c "
import json, os, sys
from dotenv import load_dotenv

try:
    load_dotenv(os.path.join(sys.argv[2], '.env'))
    r = json.loads(sys.argv[1])
    read_only = r.get('readOnly', False)
    desc = r.get('description', 'Unknown command')
    reason = r.get('reason', '')
    auto_allow = os.getenv('BSC_AUTO_ALLOW_READONLY', 'false').lower() == 'true'
    nerd_font = os.getenv('BSC_NERD_FONT_SUPPORT', 'false').lower() == 'true'
    arrow = '\uf061' if nerd_font else '->'

    if read_only:
        msg = f'✅ {desc}'
        decision = 'allow' if auto_allow else 'ask'
    else:
        msg = f'❗ {desc}'
        if reason:
            msg += f' {arrow} {reason}'
        decision = 'ask'

    output = {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': decision,
            'permissionDecisionReason': msg
        }
    }
    print(json.dumps(output))
except Exception:
    pass
" "$result" "$SCRIPT_DIR"
