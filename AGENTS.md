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
    └─ ⚠️ Restart nginx service. Reason: Restarts a running service
```

## Files

| File | Purpose |
|------|---------|
| `.env` | Configuration (API URL, model, timeout, extra body, auto-allow) |
| `checker.py` | Main CLI tool — sends command to LLM, returns JSON verdict |
| `checker_extract.py` | Helper — extracts command from Claude Code stdin JSON |
| `hook.sh` | Claude Code hook entry point — bridges stdin to checker.py |
| `requirements.txt` | Python dependencies (requests, python-dotenv) |

## Configuration (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `BSC_API_URL` | `http://localhost:10001/v1` | LLM API base URL |
| `BSC_MODEL` | `GPT-OSS-20B:MXFP4` | Model name for completions |
| `BSC_TIMEOUT` | `15` | HTTP request timeout (seconds) |
| `BSC_EXTRA_BODY` | `{}` | Extra JSON fields merged into API request body |
| `BSC_AUTO_ALLOW_READONLY` | `false` | If `true`, read-only commands are auto-approved (skip approval dialog) |

## How Classification Works

The LLM receives a system prompt defining:
- **Read-only**: commands that ONLY retrieve/display information (ls, cat, grep, git status, docker ps, curl GET, etc.)
- **Destructive**: commands that create, modify, delete, or affect any state (rm, git push, docker run, pip install, curl POST, etc.)

Rules:
- Piped/chained commands: if ANY part is destructive → whole command is destructive
- Shell redirections (>, >>) → destructive
- Uncertain → classify as destructive (err on caution side)

## Error Handling

If the LLM is unavailable, times out, or returns unparseable output:
- `checker.py` exits with code 1 (stderr message)
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
            "command": "bash /c/apps/bash-safety-checker/hook.sh",
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
# → {"readOnly": false, "description": "Recursively delete /tmp/cache", "reason": "Permanently removes files and directories"}
```
