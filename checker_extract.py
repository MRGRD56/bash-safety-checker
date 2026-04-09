"""Extract command and tool name from Claude Code PreToolUse stdin JSON."""
import json
import sys

data = json.loads(sys.argv[1])
command = data.get("tool_input", {}).get("command", "")
tool_name = data.get("tool_name", "")
print(command)
print(tool_name)
