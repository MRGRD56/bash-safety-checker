"""Bash Safety Checker — classifies shell commands as read-only or destructive via LLM."""

import json
import logging
import logging.handlers
import os
import re
import sys

import requests
from dotenv import load_dotenv

# Load .env from script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(SCRIPT_DIR, ".env"))

API_URL = os.getenv("BSC_API_URL")
MODEL = os.getenv("BSC_MODEL")
if not API_URL or not MODEL:
    print("Error: BSC_API_URL and BSC_MODEL must be set in .env", file=sys.stderr)
    sys.exit(1)
TIMEOUT = int(os.getenv("BSC_TIMEOUT", "15"))
EXTRA_BODY = json.loads(os.getenv("BSC_EXTRA_BODY", "{}"))
MAX_TOKENS = int(os.getenv("BSC_MAX_TOKENS", "2048"))
SHORTEN_INPUT = os.getenv("BSC_SHORTEN_INPUT", "false").lower() == "true"
LANGUAGE = os.getenv("BSC_LANGUAGE", "")
LOG_MAX_BYTES = int(os.getenv("BSC_LOG_MAX_KB", "512")) * 1024
LOG_BACKUPS = int(os.getenv("BSC_LOG_BACKUPS", "2"))

# Rotating log: checker.log -> checker.log.1 -> checker.log.2 -> deleted
log = logging.getLogger("bsc")
log.setLevel(logging.DEBUG)
_handler = logging.handlers.RotatingFileHandler(
    os.path.join(SCRIPT_DIR, "checker.log"),
    maxBytes=LOG_MAX_BYTES,
    backupCount=LOG_BACKUPS,
    encoding="utf-8",
)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
log.addHandler(_handler)

SYSTEM_PROMPT = """\
You are a shell command safety classifier. You receive a shell command and must determine whether it is READ-ONLY or POTENTIALLY DESTRUCTIVE.

READ-ONLY means the command ONLY retrieves/displays information and has ZERO side effects. Examples:
- ls, dir, cat, head, tail, less, more, wc, file, stat, du, df
- grep, rg, find, locate, which, whereis, type
- git status, git log, git diff, git branch, git show, git remote -v
- docker ps, docker images, docker logs, docker inspect
- ps, top, htop, free, uptime, whoami, id, hostname, uname, env, printenv
- curl/wget with GET method (no -X POST, no -d, no --data)
- ping, nslookup, dig, traceroute, netstat, ss, ip addr
- systemctl status, journalctl (read logs)
- SELECT queries in databases
- echo, printf (when used standalone, not redirecting to files)
- Reading environment variables, checking versions (python --version, node -v)

DESTRUCTIVE (not read-only) means the command creates, modifies, deletes, or affects ANY state. Examples:
- Writing/creating/deleting files: touch, mkdir, rm, mv, cp, tee, > redirect, >> append
- Editing files: sed -i, nano, vim (when saving), chmod, chown
- Git write operations: git add, git commit, git push, git checkout, git reset, git merge, git rebase, git stash
- Package management: pip install, npm install, apt install, brew install
- Docker write ops: docker run, docker stop, docker rm, docker build, docker-compose up
- Service management: systemctl start/stop/restart, service restart
- Network mutations: curl -X POST/PUT/DELETE, curl -d, wget --post-data
- Database writes: INSERT, UPDATE, DELETE, DROP, CREATE, ALTER
- Process control: kill, killall, pkill
- System changes: reboot, shutdown, mount, umount

IMPORTANT RULES:
1. If a command is piped (|) or chained (&&, ||, ;), evaluate ALL parts. If ANY part is destructive, the whole command is destructive.
2. Shell redirections to files (>, >>) make a command destructive.
3. Command substitution $() or backticks inside a destructive command = destructive.
4. If uncertain, classify as destructive (err on the side of caution).
5. Subshells, eval, exec — treat as destructive unless the entire content is clearly read-only.
6. Running unknown scripts or binaries (python script.py, ./run.sh, /usr/local/bin/something, etc.) is DESTRUCTIVE — if you cannot determine with certainty what a script or binary does, classify it as destructive.

Respond with ONLY a JSON object, no markdown fencing, no extra text:
- If read-only: {"readOnly": true, "description": "Brief description of what this command does"}
- If destructive: {"readOnly": false, "description": "Brief description of what this command does", "reason": "What destructive side effect occurs"}

The description should be human-readable, concise (one sentence), and describe the ACTION (e.g., "List files in current directory", "Search for pattern in PHP files inside Docker container").
The reason must be a SHORT category of the side effect — do NOT repeat or rephrase the description.

Examples of correct description + reason pairs:
- description: "Creates directory, downloads JAR files and changes ownership on remote server" / reason: "Modifies remote filesystem"
- description: "Deletes all .tmp files in /var/cache recursively" / reason: "Permanent file deletion"
- description: "Sends POST request to create a user via API" / reason: "Mutates remote API state"
- description: "Restarts nginx service on production server" / reason: "Service interruption"
- description: "Runs database migration script" / reason: "Alters database schema"
- description: "Installs npm packages from package.json" / reason: "Modifies node_modules and lockfile"
- description: "Force-pushes current branch to origin" / reason: "Overwrites remote git history"
- description: "Runs unknown Python script log_data.py" / reason: "Unknown script behavior"."""

LANGUAGE_SUFFIX = """

IMPORTANT: Write ALL text values ("description" and "reason") in {language}. JSON keys must remain in English."""


def _shorten(command: str) -> str:
    """Replace long opaque strings (tokens, hashes, base64, etc.) with placeholders
    to reduce token count without losing structural information for classification."""
    # Replace long quoted strings (>60 chars) with placeholder keeping first 20 chars
    def _shorten_quoted(m):
        q = m.group(1)
        content = m.group(2)
        if len(content) > 60:
            return f"{q}<...long string ({len(content)} chars)...>{q}"
        return m.group(0)
    command = re.sub(r"""(['"])((?:(?!\1).){61,}?)\1""", _shorten_quoted, command)

    # Replace long unquoted tokens (>60 chars of base64/hex-like chars) — e.g. JWT, hashes
    def _shorten_token(m):
        return f"<...token ({len(m.group(0))} chars)...>"
    command = re.sub(r'[A-Za-z0-9_\-\.=+/]{61,}', _shorten_token, command)

    return command


def classify_command(command: str) -> dict:
    log.info("command: %s", command)
    if SHORTEN_INPUT:
        command_short = _shorten(command)
        if command_short != command:
            log.debug("shortened to: %s", command_short)
    else:
        command_short = command

    prompt = SYSTEM_PROMPT
    if LANGUAGE:
        prompt += LANGUAGE_SUFFIX.format(language=LANGUAGE)

    body = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": command_short},
        ],
        "temperature": 0.0,
        "max_tokens": MAX_TOKENS,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "safety_check",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {
                        "readOnly": {"type": "boolean"},
                        "description": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                    "required": ["readOnly", "description"],
                },
            },
        },
        **EXTRA_BODY,
    }

    url = f"{API_URL}/chat/completions"
    log.debug("request body: %s", json.dumps(body, ensure_ascii=False)[:2000])
    resp = requests.post(url, json=body, timeout=TIMEOUT)
    log.debug("HTTP %s, response: %s", resp.status_code, resp.text[:2000])
    resp.raise_for_status()

    data = resp.json()
    content = data["choices"][0]["message"]["content"].strip()
    log.debug("raw LLM response: %s", content)

    # Try to extract JSON from response (LLM may wrap it in markdown or add text)
    result = _parse_json(content)
    log.info("result: %s", json.dumps(result, ensure_ascii=False))
    return result


def _parse_json(text: str) -> dict:
    """Extract JSON object from LLM response, tolerating markdown fencing and surrounding text."""
    # 1. Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Strip markdown fencing
    if "```" in text:
        lines = text.split("\n")
        lines = [l for l in lines if not l.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

    # 3. Find first { ... } substring
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Cannot parse JSON from LLM response: {text[:200]}")


def main():
    if len(sys.argv) < 2:
        print("Usage: checker.py <command>", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]

    try:
        result = classify_command(command)
    except Exception as e:
        log.error("command: %s | error: %s", command, e)
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate expected structure
    if "readOnly" not in result or "description" not in result:
        log.error("command: %s | bad structure: %s", command, result)
        print("Error: LLM returned unexpected structure", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
