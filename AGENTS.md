# Bash Safety Checker

A Claude Code PreToolUse hook that classifies shell commands as **read-only** or **potentially destructive** using a local LLM, and displays the result in the Claude Code approval UI.

## Architecture

```
Claude Code (PreToolUse event)
    │
    ├─ stdin JSON: { tool_name: "Bash", tool_input: { command: "..." } }
    │
    ▼
hook.sh
    │
    ├─ Extracts command via checker_extract.py
    ├─ Calls checker.py with the command
    ├─ Formats LLM verdict into Claude Code hookSpecificOutput JSON
    │
    ▼
checker.py
    │
    ├─ Loads config from .env (BSC_* variables)
    ├─ Sends command to LLM via OpenAI-compatible /v1/chat/completions
    ├─ Returns JSON: { readOnly: bool, description: str, reason?: str }
    │
    ▼
Claude Code approval UI
    ├─ ✅ Read file contents from /etc/nginx/nginx.conf
    └─ ❗ Restart nginx service -> Service interruption
```

## Files

| File | Purpose |
|------|---------|
| `.env` | Configuration — BSC_API_URL, BSC_MODEL, and other settings (git-ignored) |
| `.env.example` | Configuration template |
| `checker.py` | Main CLI tool — sends command to LLM, returns JSON verdict |
| `checker_extract.py` | Helper — extracts command from Claude Code stdin JSON |
| `hook.sh` | Claude Code hook entry point — bridges stdin to checker.py |
| `requirements.txt` | Python dependencies (requests, python-dotenv) |

## Configuration

All settings are in `.env` (see `.env.example` for all options).

`BSC_API_URL` and `BSC_MODEL` are required. Everything else has sensible defaults.

`BSC_MODEL_PROFILE` controls the prompt format and output parsing:
- `general` (default) — general-purpose instruction-following prompt, outputs `{readOnly, description, reason}`
- `safeguard` — structured policy prompt for gpt-oss-safeguard-20b, outputs `{violation, description, reason}`, normalized to `readOnly` by `_normalize_result()`

## Error Handling

If the LLM is unavailable, times out, or returns unparseable output:
- `checker.py` exits with code 1
- `hook.sh` catches this and exits with code 0 (no output)
- Claude Code treats this as "hook had nothing to say" and shows normal approval dialog
- **User is never blocked by hook failures**

## Claude Code Hook Config

In `~/.claude/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell",
        "hooks": [
          {
            "type": "command",
            "command": "bash /path/to/bash-safety-checker/hook.sh",
            "timeout": 30,
            "statusMessage": "Checking command safety..."
          }
        ]
      }
    ]
  }
}
```

## Standalone Usage

```bash
python checker.py "ls -la /var/www"
# → {"readOnly": true, "description": "List files in /var/www with details"}

python checker.py "rm -rf /tmp/cache"
# → {"readOnly": false, "description": "Recursively delete /tmp/cache", "reason": "Permanent file deletion"}
```
