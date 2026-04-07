# Bash Safety Checker

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) hook that classifies shell commands as **read-only** or **potentially destructive** using a local LLM, and displays the result in the approval UI.

Works with any OpenAI-compatible API (`/v1/chat/completions`) — [llama.cpp](https://github.com/ggml-org/llama.cpp), [Ollama](https://ollama.com/), [vLLM](https://github.com/vllm-project/vllm), [LM Studio](https://lmstudio.ai/), etc.

## How it works

```
Claude Code (PreToolUse)
    │  stdin: { tool_name: "Bash", tool_input: { command: "..." } }
    ▼
hook.sh → checker.py → LLM API
    │
    ▼
Approval UI:
  ✅ List files in /var/www with details
  ❗ Delete all containers and volumes -> Permanent data loss
```

- **Read-only** commands (ls, grep, git status, docker ps, etc.) get a ✅ mark
- **Destructive** commands (rm, git push, docker run, pip install, etc.) get a ❗ mark with a reason
- If the LLM is unavailable, the hook silently passes through — **never blocks the user**

## Setup

### 1. Install dependencies

```bash
pip install requests python-dotenv
```

### 2. Configure

```bash
cp .env.example .env
```

Edit `.env` — at minimum set `BSC_API_URL` and `BSC_MODEL`:

```env
BSC_API_URL=http://localhost:8080/v1
BSC_MODEL=my-model-name
```

### 3. Add hook to Claude Code

Add this to your `~/.claude/settings.json` (global) or `.claude/settings.json` (per-project):

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

Replace `/path/to/bash-safety-checker` with the actual path. On Windows with Git Bash use forward slashes (e.g., `/c/apps/bash-safety-checker/hook.sh`).

Restart Claude Code to pick up the hook.

## Configuration

All settings are in `.env`. See [`.env.example`](.env.example) for all options.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BSC_API_URL` | **Yes** | — | LLM API base URL |
| `BSC_MODEL` | **Yes** | — | Model name |
| `BSC_TIMEOUT` | No | `15` | HTTP timeout (seconds) |
| `BSC_MAX_TOKENS` | No | `2048` | Max tokens for response. Increase for reasoning models |
| `BSC_SHORTEN_INPUT` | No | `false` | Replace long tokens/hashes with placeholders before sending to LLM |
| `BSC_EXTRA_BODY` | No | `{}` | Extra JSON fields merged into the API request body |
| `BSC_LANGUAGE` | No | *(empty = English)* | Language for descriptions (e.g., `русский`, `deutsch`) |
| `BSC_NERD_FONT_SUPPORT` | No | `false` | Use Nerd Font icons |
| `BSC_LOG_MAX_KB` | No | `512` | Max log file size in KB |
| `BSC_LOG_BACKUPS` | No | `2` | Number of rotated log files to keep |
| `BSC_AUTO_ALLOW_READONLY` | No | `false` | Auto-approve read-only commands (skip approval dialog) |

## Standalone usage

You can use `checker.py` directly from the terminal:

```bash
python checker.py "ls -la /var/www"
# {"readOnly": true, "description": "List files in /var/www with details"}

python checker.py "rm -rf /tmp/cache"
# {"readOnly": false, "description": "Recursively delete /tmp/cache", "reason": "Permanent file deletion"}
```

## Files

| File | Purpose |
|------|---------|
| `checker.py` | Main CLI — sends command to LLM, returns JSON verdict |
| `checker_extract.py` | Helper — extracts command from Claude Code hook stdin JSON |
| `hook.sh` | Claude Code hook entry point |
| `.env` | Your local configuration (git-ignored) |
| `.env.example` | Configuration template |

## How classification works

The LLM receives a system prompt that defines:

- **Read-only**: commands that only retrieve/display information (ls, cat, grep, git status, docker ps, curl GET, etc.)
- **Destructive**: commands that create, modify, delete, or affect any state (rm, git push, docker run, pip install, curl POST, etc.)

Key rules:
- Piped/chained commands — if **any** part is destructive, the whole command is destructive
- Shell redirections (`>`, `>>`) are destructive
- Unknown scripts/binaries are classified as destructive
- When uncertain, the LLM errs on the side of caution (classifies as destructive)

Uses `response_format` with JSON schema for guaranteed valid output.

## Logging

Logs are written to `checker.log` in the tool directory with automatic rotation:
- `checker.log` — current (up to `BSC_LOG_MAX_KB` KB)
- `checker.log.1`, `checker.log.2` — rotated backups (auto-deleted)

Logs include: commands received, raw LLM responses, errors.
