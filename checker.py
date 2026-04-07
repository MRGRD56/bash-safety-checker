"""Bash Safety Checker — classifies shell commands as read-only or destructive via LLM."""

import argparse
import json
import logging
import logging.handlers
import os
import re
import sys
import time

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
MODEL_PROFILE = os.getenv("BSC_MODEL_PROFILE", "general")
RESPONSE_FORMAT = os.getenv("BSC_RESPONSE_FORMAT", "true").lower() == "true"
SYSTEM_AS_USER = os.getenv("BSC_SYSTEM_AS_USER", "false").lower() == "true"

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

_STYLE_GUIDE = """
The description should be human-readable, concise (one sentence), and describe the ACTION (e.g., "List files in current directory").
The reason must be a SHORT capitalized category of the side effect — do NOT repeat or rephrase the description.

Examples of correct description + reason pairs (English):
- "Creates directory, downloads JAR files and changes ownership on remote server" / "Modifies remote filesystem"
- "Deletes all .tmp files in /var/cache recursively" / "Permanent file deletion"
- "Sends POST request to create a user via API" / "Mutates remote API state"
- "Restarts nginx service on production server" / "Service interruption"
- "Runs database migration script" / "Alters database schema"
- "Installs npm packages from package.json" / "Modifies node_modules and lockfile"
- "Force-pushes current branch to origin" / "Overwrites remote git history"
- "Runs unknown Python script log_data.py" / "Unknown script behavior"

Examples of correct description + reason pairs (русский):
- "Создаёт директорию и скачивает JAR-файлы на удалённом сервере" / "Изменение удалённой файловой системы"
- "Перезапускает сервис nginx на продакшен-сервере" / "Прерывание работы сервиса"
- "Выполняет миграцию базы данных" / "Изменение схемы БД"
- "Записывает вывод команды в файл /tmp/output.log" / "Запись в файл"
- "Запускает неизвестный bash-скрипт deploy.sh" / "Неизвестное поведение скрипта"
"""

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
""" + _STYLE_GUIDE

LANGUAGE_SUFFIX = """

IMPORTANT: Write ALL text values ("description" and "reason") in {language}. JSON keys must remain in English."""

SAFEGUARD_SYSTEM_PROMPT = """\
INSTRUCTIONS
Classify the given shell command as SAFE (read-only) or VIOLATING (destructive/state-mutating). A command is SAFE only if every part of it exclusively reads or displays information with zero side effects.

DEFINITIONS
SAFE (read-only): Command exclusively retrieves or displays information. Includes: ls, cat, grep, find, git status/log/diff, docker ps/logs, ps, free, whoami, curl/wget GET (no -d/--data/-X POST), ping, dig, echo/printf to stdout, SELECT queries, version checks.

VIOLATING (destructive): Command creates, modifies, deletes, or affects any state. Includes: file writes (touch, mkdir, rm, mv, cp, tee, >, >>), file edits (sed -i, chmod, chown), git writes (add, commit, push, checkout, reset, merge, rebase), package installs (pip, npm, apt), docker writes (run, stop, rm, build), service control (systemctl start/stop/restart), network mutations (curl -X POST/PUT/DELETE, curl -d), database writes (INSERT, UPDATE, DELETE, DROP, CREATE), process control (kill, pkill), system changes (reboot, shutdown).

VIOLATES (1) / SAFE (0)
1 — Any part of a piped or chained command is destructive
1 — Shell redirections to files (>, >>)
1 — Running unknown scripts or binaries (python script.py, ./run.sh)
1 — Subshells, eval, exec unless entire content is verifiably read-only
1 — Uncertain about the command's behavior
0 — All parts of the command are verifiably read-only

EXAMPLES
"ls -la /var/www" -> 0
"grep -r 'TODO' src/" -> 0
"git status && git diff HEAD" -> 0
"rm -rf /tmp/cache" -> 1
"git add . && git commit -m 'fix'" -> 1
"curl -X POST https://api.example.com/users -d '{}'" -> 1
"python ./deploy.py" -> 1
"cat file.txt > output.txt" -> 1
"echo hello | tee /tmp/log.txt" -> 1

Respond with a JSON object: {"violation": 0 or 1, "description": "brief description of what the command does", "reason": "short side effect category if violation=1, empty string if violation=0"}
""" + _STYLE_GUIDE


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

    if MODEL_PROFILE == "safeguard":
        prompt = SAFEGUARD_SYSTEM_PROMPT
    else:
        prompt = SYSTEM_PROMPT
    if LANGUAGE:
        prompt += LANGUAGE_SUFFIX.format(language=LANGUAGE)

    if SYSTEM_AS_USER:
        messages = [
            {"role": "user", "content": f"{prompt}\n\n{command_short}"},
        ]
    else:
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": command_short},
        ]

    body = {
        "model": MODEL,
        "messages": messages,
        "temperature": 0.0,
    }

    if MODEL_PROFILE == "safeguard":
        if RESPONSE_FORMAT:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "safety_check",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "violation": {"type": "integer"},
                            "description": {"type": "string"},
                            "reason": {"type": "string"},
                        },
                        "required": ["violation", "description"],
                    },
                },
            }
    else:
        body["max_tokens"] = MAX_TOKENS
        if RESPONSE_FORMAT:
            body["response_format"] = {
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
            }

    body.update(EXTRA_BODY)

    url = f"{API_URL}/chat/completions"
    log.debug("request body: %s", json.dumps(body, ensure_ascii=False)[:2000])
    resp = requests.post(url, json=body, timeout=TIMEOUT)
    log.debug("HTTP %s, response: %s", resp.status_code, resp.text[:2000])
    resp.raise_for_status()

    data = resp.json()
    msg = data["choices"][0]["message"]
    content = msg["content"].strip()
    reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
    log.debug("raw LLM response: %s", content)
    if reasoning:
        log.debug("reasoning: %s", reasoning[:500])

    # Try to extract JSON from response (LLM may wrap it in markdown or add text)
    result = _parse_json(content)
    result = _normalize_result(result)
    log.info("result: %s", json.dumps(result, ensure_ascii=False))
    return result, reasoning


def _normalize_result(result: dict) -> dict:
    """Map safeguard-20b output to the standard {readOnly, description, reason} contract."""
    if MODEL_PROFILE != "safeguard":
        return result
    violation = result.get("violation")
    if violation is None:
        violation = result.get("label", 0)
    read_only = int(violation) == 0
    normalized = {
        "readOnly": read_only,
        "description": result.get("description", ""),
    }
    if not read_only:
        normalized["reason"] = result.get("reason", "")
    return normalized


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


def _format_pretty(result: dict, elapsed: float, nerd_font: bool = False) -> str:
    """Format result as colored human-readable string with timing."""
    read_only = result.get("readOnly", False)
    desc = result.get("description", "Unknown command")
    reason = result.get("reason", "")

    if nerd_font:
        icon = "\uf058" if read_only else "\uf06a"
        arrow = "\uf061"
        time_prefix = "\uf017"
    else:
        icon = "\u2705" if read_only else "\u2757"
        arrow = "->"
        time_prefix = "in"

    color = "\033[32m" if read_only else "\033[31m"
    dim = "\033[2m"
    reset = "\033[0m"

    text = f"{icon} {desc}"
    if not read_only and reason:
        text += f" {arrow} {reason}"
    timing = f"{dim}{time_prefix} {elapsed:.3f} secs{reset}"
    return f"{color}{text}{reset}\n{timing}"


def _format_reasoning(reasoning: str, nerd_font: bool = False) -> str:
    """Format reasoning as dim text, optionally with thought-bubble icon."""
    dim = "\033[2m"
    reset = "\033[0m"
    icon = "\U000f02fc " if nerd_font else ""
    lines = [l for l in reasoning.strip().splitlines() if l.strip()]
    formatted = "\n".join(f"{dim}{icon}{line}{reset}" for line in lines)
    return formatted


def main():
    parser = argparse.ArgumentParser(description="Shell command safety classifier")
    parser.add_argument("command", help="Shell command to classify")
    parser.add_argument("-f", "--format", choices=["json", "pretty", "pretty-nf"],
                        default="json", dest="fmt")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show model reasoning (if available)")
    args = parser.parse_args()

    t0 = time.monotonic()
    try:
        result, reasoning = classify_command(args.command)
    except Exception as e:
        log.error("command: %s | error: %s", args.command, e)
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    elapsed = time.monotonic() - t0

    # Validate expected structure
    if "readOnly" not in result or "description" not in result:
        log.error("command: %s | bad structure: %s", args.command, result)
        print("Error: LLM returned unexpected structure", file=sys.stderr)
        sys.exit(1)

    if args.fmt == "json":
        output = dict(result)
        if args.verbose and reasoning:
            output["reasoning"] = reasoning
        print(json.dumps(output, ensure_ascii=False))
    else:
        if args.verbose and reasoning:
            print(_format_reasoning(reasoning, nerd_font=(args.fmt == "pretty-nf")))
        print(_format_pretty(result, elapsed, nerd_font=(args.fmt == "pretty-nf")))


if __name__ == "__main__":
    main()
