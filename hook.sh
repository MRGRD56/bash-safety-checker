#!/bin/bash
# Claude Code PreToolUse hook for Bash/PowerShell command safety checking.
# Reads Claude Code stdin JSON, extracts command, calls checker.py,
# formats result for Claude Code approval UI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Read all of stdin (Claude Code sends JSON)
input=$(cat)

# Extract command and tool name from tool_input using Python (no jq dependency)
extract_output=$(python "$SCRIPT_DIR/checker_extract.py" "$input" 2>/dev/null) || exit 0
command=$(echo "$extract_output" | head -n1)
tool_name=$(echo "$extract_output" | tail -n1)

# Skip empty commands
[ -z "$command" ] && exit 0

# Build checker.py args — pass --shell if tool_name is available
checker_args=(--format=json)
[ -n "$tool_name" ] && checker_args+=(--shell "$tool_name")
checker_args+=("$command")

# Call checker.py — on failure, gracefully pass through
result=$(python "$SCRIPT_DIR/checker.py" "${checker_args[@]}" 2>/dev/null) || exit 0

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
