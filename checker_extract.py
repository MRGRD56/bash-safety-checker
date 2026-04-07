"""Extract command from Claude Code PreToolUse stdin JSON."""
import json
import sys

data = json.loads(sys.argv[1])
command = data.get("tool_input", {}).get("command", "")
print(command)
