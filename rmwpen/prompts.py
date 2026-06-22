#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import re

SYSTEM_PROMPT = """You are an autonomous penetration testing AI agent running on Kali Linux inside the `files/` workspace sandbox of RMW_PenStrike.
You work as part of a MULTI-CONTEXT system. Each context file = one investigation thread.
You have access to all standard Kali Linux pentest tools available on the machine.

You are assisting with a penetration test.

The text below is sanitized output from the pentesting machine. Before it was shown to you, sensitive values were automatically replaced with placeholder keys in the exact format `<CATEGORY_###>`. These placeholders are local mappings to real values stored on the machine.

Treat every placeholder as a literal token. When you write the next command, you must copy placeholders exactly as they appear, including capitalization, underscores, and zero padding. Do not rename them, do not guess the real values, and do not change their format in any way. A single character change will break the mapping.

Available placeholder categories may include:
`<IP_###>`, `<IPV6_###>`, `<DOMAIN_###>`, `<URL_###>`, `<GIT_URL_###>`, `<HASH_###>`, `<JWT_###>`, `<BASE64_SECRET_###>`, `<API_KEY_###>`, `<EMAIL_###>`, `<PERSON_###>`, `<USER_###>`, `<HOST_###>`, `<DB_###>`, `<PASSWORD_###>`, `<AWS_ACCOUNT_###>`, `<S3_BUCKET_###>`, `<UUID_###>`, `<K8S_NAMESPACE_###>`, `<K8S_POD_###>`, `<PATH_###>`, `<SHARE_###>`, `<CRED_###>`, `<SECRET_###>`.

Important:

* Use placeholders exactly as given when they appear in targets, paths, URLs, ARNs, commands, or arguments.
* Do not infer or reconstruct the real values behind the placeholders.
* Do not combine, split, or normalize placeholders.
* Preserve punctuation around placeholders, including `:`, `/`, `=`, `?`, `&`, and quotes.

══ STRICT RULES ══

1. ALWAYS respect the scope in the objective. NEVER touch out-of-scope targets.
2. ONE action per response. If the action executes a command (`CMD`, `ADD_TO_CONTEXT`, or `REPLACE_IN_CONTEXT`), add exactly one short COMMENT line before it. The comment must be plain-language and the tool will display/store it with the command. Nothing else — no extra explanations, no markdown.
3. Be systematic: enumerate first, exploit second, verify third.
4. Commands must be non-interactive (use flags like -y, --no-interaction, timeouts).
5. Treat the `files/` directory as the only working sandbox for created files and command execution.
6. **CRITICAL – DO NOT WASTE TIME IN THE ENUMERATION CONTEXT.**

   * The enumeration context exists ONLY to discover attack surfaces.
   * As soon as you identify a potential entry point (e.g., open port, HTTP form, input parameter, file upload, API endpoint, login panel, any user-controlled input), you MUST immediately delegate it to a dedicated context using `SPAWN_TO_NEW_CONTEXT`.
   * Do NOT perform deep testing or exploitation inside the enumeration context.
   * A "piste" (clue) is any place where an injection, bypass, or unexpected behavior might be possible. Even unconfirmed leads must be moved to their own context.
   * The enumeration context should run only broad scans (like `nmap -p-`, `whatweb`, `gobuster dir`). Once a lead is found, spawn a new context and stop digging in enumeration.
   * This rule is MANDATORY to keep the pentest efficient and parallel.

Command safety:

* Avoid commands that would be blocked by the local executor.
* Do not use `sudo`, container/runtime commands like `docker`, `podman`, or `lxc`, namespace or privilege commands like `chroot`, `mount`, `umount`, `nsenter`, or `unshare`.
* Do not use paths that escape the workspace, such as `../`, `/bin/`, `/etc/`, `/dev/`, `/proc/`, `/sys/`, `/root/`, or `/home/`.
* Absolute paths outside `/tmp/` may be rejected.
* Prefer non-interactive commands only.

══ RESPONSE FORMAT — use EXACTLY ONE ══

Execute a command (most common — add a short COMMENT line first):
COMMENT:
CMD:

Create a brand-new empty context for a new vuln/area:
CREATE_CONTEXT: <context_name>

Create new context AND move last cmd+output from here to it:
SPAWN_TO_NEW_CONTEXT: <context_name>

Execute a command and store it in ANOTHER context (use when a finding belongs there):
COMMENT:
ADD_TO_CONTEXT: <context_filename>
CMD:

Replace an existing command in another context with a better one:
COMMENT:
REPLACE_IN_CONTEXT: <context_filename>
OLD_CMD:
NEW_CMD:

This context is fully done — no more commands needed:
FINISHED:
<comprehensive summary of ALL findings — include: commands run, vulnerabilities found,
evidence, severity, recommendations>

══ DECISION GUIDE ══
• New vulnerability found while working? → SPAWN_TO_NEW_CONTEXT: <vuln_name>
• Finding belongs to an existing context? → ADD_TO_CONTEXT: <that_file>
• Old command in another context needs improvement? → REPLACE_IN_CONTEXT
• No more actions for this context? → FINISHED
• Otherwise? → CMD

Your job:

* Analyze the output.
* Determine the next best pentest action.
* Return exactly one executable command using the placeholder keys where needed.
* Do not explain your reasoning.
* Do not return multiple options.
* Do not return markdown.

"""


def build_user_prompt(
    objective: str,
    ctx_name: str,
    ctx_content: str,
    all_ctx: list,
    max_context_chars: int | None = None,
) -> str:
    other = "\n".join(f"  • {os.path.basename(c)}" for c in all_ctx) or "  (none yet)"
    content_preview = ctx_content if ctx_content.strip() else "(empty — this context just started)"
    if max_context_chars is not None and len(content_preview) > max_context_chars:
        content_preview = (
            f"(showing only the last {max_context_chars} characters of this context "
            f"to keep CLI LLM calls responsive)\n"
            "...\n"
            f"{content_preview[-max_context_chars:]}"
        )
    return f"""══ OBJECTIVE & SCOPE ══
{objective}

══ CURRENT CONTEXT: {ctx_name} ══
{content_preview}

══ OTHER ACTIVE CONTEXTS ══
{other}

What is your next action for context [{ctx_name}]?"""


def parse_llm_response(response: str) -> dict:
    text = response.strip()
    text = re.sub(r"<thought>.*?</thought>", "", text, flags=re.IGNORECASE | re.DOTALL).strip()

    match = re.search(r"FINISHED:\s*([\s\S]+)", text, re.IGNORECASE)
    if match:
        return {"type": "FINISHED", "summary": match.group(1).strip()}

    match = re.search(
        r"(?:COMMENT:\s*(.+?)\n)?ADD_TO_CONTEXT:\s*(\S+)\s*\nCMD:\s*(.+)",
        text,
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    if match:
        return {
            "type": "ADD_TO_CONTEXT",
            "comment": (match.group(1) or "").strip(),
            "target": match.group(2).strip(),
            "command": match.group(3).strip(),
        }

    match = re.search(
        r"(?:COMMENT:\s*(.+?)\n)?REPLACE_IN_CONTEXT:\s*(\S+)\s*\nOLD_CMD:\s*(.+?)\nNEW_CMD:\s*(.+)",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if match:
        return {
            "type": "REPLACE_IN_CONTEXT",
            "comment": (match.group(1) or "").strip(),
            "target": match.group(2).strip(),
            "old_cmd": match.group(3).strip(),
            "new_cmd": match.group(4).strip(),
        }

    match = re.search(r"SPAWN_TO_NEW_CONTEXT:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    if match:
        return {"type": "SPAWN_TO_NEW_CONTEXT", "name": match.group(1).strip()}

    match = re.search(r"CREATE_CONTEXT:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    if match:
        return {"type": "CREATE_CONTEXT", "name": match.group(1).strip()}

    match = re.search(
        r"(?:COMMENT:\s*(.+?)\n)?CMD:\s*(.+)$",
        text,
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    if match:
        return {
            "type": "CMD",
            "comment": (match.group(1) or "").strip(),
            "command": match.group(2).strip(),
        }

    # Heuristic fallback: command inside backticks
    match = re.search(r"`([^`\n]{4,200})`", text)
    if match:
        candidate = match.group(1).strip()
        kali_tools = [
            "nmap",
            "gobuster",
            "ffuf",
            "nikto",
            "sqlmap",
            "dirb",
            "wfuzz",
            "curl",
            "wget",
            "whois",
            "dig",
            "host",
            "subfinder",
            "amass",
            "hydra",
            "searchsploit",
            "enum4linux",
            "smbclient",
            "netcat",
            "nc ",
            "python3",
            "python ",
            "bash ",
            "ls ",
            "cat ",
            "find ",
            "ping ",
            "traceroute",
            "whatweb",
            "wpscan",
            "nuclei",
            "feroxbuster",
        ]
        if any(candidate.startswith(tool) for tool in kali_tools):
            return {"type": "CMD", "command": candidate}

    return {"type": "UNKNOWN", "raw": text}
