#!/usr/bin/env python3
from __future__ import annotations

import argparse
import atexit
import json
import os
import shutil
import signal
import sys
import threading
import time
import zipfile
from pathlib import Path

import config as config_module
import executor as executor_module
import llm_client as llm_client_module
import storage as storage_module
from config import APP_CONFIG, PROJECT_NAME
from executor import execute_command, SensitiveDataAnonymizer, _DEFAULT_EXECUTOR
from llm_client import ALLOWED_LLM_BACKEND_MODES, CLI_CONTEXT_CHAR_LIMIT, LLM_BACKEND_MODE, call_llm
from logger import PRINT_LOCK, log
from prompts import SYSTEM_PROMPT, build_user_prompt, parse_llm_response
from storage import (
    all_contexts_finished,
    append_to_context,
    context_name_from_path,
    create_context_file,
    get_active_context_files,
    get_all_context_files,
    get_finished_context_files,
    is_finished,
    mark_context_finished,
    read_file,
    remove_last_entry_from_context,
    replace_entry_in_context,
    resolve_context_path,
    unmark_context_finished,
    write_file,
)

_ACTIVE_THREADS: dict[str, threading.Thread] = {}
_THREADS_LOCK = threading.Lock()
_CONTEXT_SEMAPHORE: threading.Semaphore | None = None

# Event global d'arrêt : permet à la finalisation (Ctrl+C) de stopper les agents.
_STOP_EVENT: threading.Event = threading.Event()


def unzip_files_directory(zip_path: Path, target_dir: Path) -> None:
    """Décompresse un fichier zip dans le dossier target_dir (écrase l'existant)."""
    if not zip_path.exists():
        raise FileNotFoundError(f"Fichier zip introuvable : {zip_path}")
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(target_dir.parent)
        log(f"Snapshot restauré depuis : {zip_path}", "MAIN")
    except Exception as e:
        log(f"Erreur lors de la décompression : {e}", "ERR")
        raise


def _resolve_cli_path(raw_value: str | None, fallback: Path, nested_name: str, label: str) -> Path:
    if raw_value is None:
        return fallback

    requested = Path(raw_value).expanduser()
    candidates: list[Path] = []

    def add_candidate(path: Path) -> None:
        if path not in candidates:
            candidates.append(path)

    add_candidate(requested)
    if not requested.is_absolute():
        add_candidate(Path.cwd() / requested)
        add_candidate(APP_CONFIG.base_dir / requested)
        add_candidate(APP_CONFIG.files_dir / requested)

    for base in list(candidates):
        if base.exists() and base.is_dir():
            add_candidate(base / nested_name)

    if requested.suffix == "":
        add_candidate(requested / nested_name)
        if not requested.is_absolute():
            add_candidate(Path.cwd() / requested / nested_name)
            add_candidate(APP_CONFIG.base_dir / requested / nested_name)
            add_candidate(APP_CONFIG.files_dir / requested / nested_name)

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate.resolve()

    tried = ", ".join(str(path) for path in candidates[:8]) or str(requested)
    raise FileNotFoundError(f"Could not resolve {label} path from '{raw_value}'. Tried: {tried}")


def _apply_runtime_config(scope_arg: str | None, mode: str, env_arg: str | None) -> None:
    global APP_CONFIG, LLM_BACKEND_MODE

    target_path = _resolve_cli_path(scope_arg, APP_CONFIG.target_file, "target.txt", "scope")
    env_path = None
    if env_arg is not None:
        env_path = _resolve_cli_path(env_arg, APP_CONFIG.env_file, "env.txt", "env")
    else:
        env_path = APP_CONFIG.env_file

    runtime_config = config_module.load_config(
        env_file=env_path,
        target_file=target_path,
        objective_file=APP_CONFIG.objective_file,
        state_file=APP_CONFIG.state_file,
    )

    if mode == "apis" and not runtime_config.llm_sources:
        raise ValueError(
            "Mode 'apis' requires API_KEYS in env.txt. Pass -e env.txt or a directory containing env.txt."
        )

    APP_CONFIG = runtime_config
    LLM_BACKEND_MODE = mode

    config_module.APP_CONFIG = runtime_config
    executor_module.APP_CONFIG = runtime_config
    storage_module.APP_CONFIG = runtime_config
    llm_client_module.APP_CONFIG = runtime_config
    llm_client_module.LLM_BACKEND_MODE = mode
    llm_client_module._CLI_SOLO_PROVIDER = None
    llm_client_module._CLI_NEXT_INDEX = 0
    try:
        llm_client_module._CLIENT_CACHE.clear()
    except Exception:
        pass


def build_arg_parser() -> argparse.ArgumentParser:
    description = (
        f"{PROJECT_NAME} — Autonomous Black-Box Pentest Tool.\n"
        "Use -s to point to a scope file.\n"
        "Use -m to choose the LLM backend.\n"
        "Use -e to point to env.txt.\n"
        "Use -n to set the maximum number of concurrent contexts (default 10).\n"
        "Use -f to restore a previous snapshot (zip file)."
    )
    epilog = (
        "LLM backend modes:\n"
        "  apis         -> use API_KEYS from env.txt with round-robin rotation\n"
        "  codex        -> send prompts to the local Codex CLI only\n"
        "  gemini       -> send prompts to the local Gemini CLI only\n"
        "  codex_gemini -> alternate Codex and Gemini; if one fails, keep using the survivor\n\n"
        "env.txt format:\n"
        "  API_KEYS_PENTEST = [\n"
        "      [\"api_key\", \"base_url\", \"model1\", \"model2\"...],\n"
        "      [\"api_key2\", \"base_url\", \"model1\"...],\n"
        "  ...]\n"
        "  API_KEYS_EXECUTOR = [\n"
        "      [\"api_key\", \"base_url\", \"model1\"...]...,\n"
        "  ]\n"
        "  API_KEYS_REPORT = [\n"
        "      [\"api_key\", \"base_url\", \"model1\"...]...,\n"
        "  ]\n"
        "If -m apis is selected, -e is required.\n\n"
        "Snapshot option:\n"
        "  -f files.zip : restore from this zip before starting, and save to the zip on exit (Ctrl+C or normal finish)."
    )
    parser = argparse.ArgumentParser(
        prog=" ",
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-s",
        "--scope",
        default=None,
        help=(
            "Scope file or directory. If a directory is given, target.txt is read from it. "
            "Default: files/target.txt"
        ),
    )
    parser.add_argument(
        "-m",
        "--mode",
        default="gemini",
        choices=sorted(ALLOWED_LLM_BACKEND_MODES),
        help="LLM backend mode. Default: gemini",
    )
    parser.add_argument(
        "-e",
        "--env",
        default=None,
        help=(
            "env.txt file or directory. If a directory is given, env.txt is read from it. "
            "Required when -m apis."
        ),
    )
    parser.add_argument(
        "-n",
        "--max-contexts",
        type=int,
        default=10,
        help="Maximum number of concurrent contexts (default 10).",
    )
    parser.add_argument(
        "-f",
        "--zip",
        type=str,
        default=None,
        help="Path to a zip file to restore snapshot from, and to save snapshot on exit.",
    )
    # Options cachées (nécessaires au code mais non affichées dans -h)
    parser.add_argument(
        "--redact-level",
        choices=["real", "partial", "full"],
        default="real",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--classification",
        default="CONFIDENTIAL",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--no-docx",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser


def generate_objective_and_mapping(target_raw: str) -> tuple[str, dict]:
    """
    Envoie target.txt brut au LLM, demande une anonymisation structurée.
    Retourne (objective_content, mapping_dict).
    Si le LLM échoue, utilise l'anonymizer Python sur le texte brut.
    """
    prompt = (
        "You are a penetration testing scope analyst. "
        "Read the raw target/scope description below. "
        "Your task is to produce a clean structured objective file with the following sections: TARGET, IN_SCOPE, OUT_OF_SCOPE, OBJECTIVES, RULES. "
        "However, before writing it, you must anonymize all sensitive values (IP addresses, URLs, domains, emails, usernames, passwords, tokens, etc.) "
        "by replacing them with placeholders in the format <CATEGORY_###> where CATEGORY is one of: IP, URL, DOMAIN, EMAIL, USER, HOST, DB, PASSWORD, SECRET, etc. "
        "Use a consistent numbering starting from 001 per category.\n\n"
        "After the objective content, you must provide a JSON mapping of each placeholder to its original value.\n\n"
        "Return your answer as a **single JSON object** with two keys:\n"
        "  - \"objective\": the text of the objective file with placeholders (as a string).\n"
        "  - \"mapping\": a dictionary where keys are the placeholders (e.g. '<URL_001>') and values are the original strings.\n\n"
        "Example:\n"
        "Given target: \"Target: example.com, IP 192.168.1.1\"\n"
        "The output should be:\n"
        "{\n"
        "  \"objective\": \"TARGET: <DOMAIN_001>\\nIN_SCOPE: <IP_001>\\nOUT_OF_SCOPE: nothing\\nOBJECTIVES: Identifying vulnerabilities\\nRULES: all\",\n"
        "  \"mapping\": {\n"
        "    \"<DOMAIN_001>\": \"example.com\",\n"
        "    \"<IP_001>\": \"192.168.1.1\"\n"
        "  }\n"
        "}\n\n"
        "Do not include any other text or explanation outside this JSON.\n\n"
        f"Raw target/scope description:\n{target_raw}"
    )

    log("Sending target.txt to LLM for anonymized objective generation...", "LLM")
    response = call_llm([{"role": "user", "content": prompt}], max_tokens=4096)

    log(f"LLM response length: {len(response)}", "LLM")
    log(f"LLM response preview: {response[:500]}...", "LLM")

    try:
        start = response.find('{')
        end = response.rfind('}') + 1
        if start == -1 or end == 0:
            raise ValueError("No JSON object found in response")
        json_str = response[start:end]
        data = json.loads(json_str)
        objective = data.get("objective", "").strip()
        mapping = data.get("mapping", {})
        if not isinstance(mapping, dict):
            raise ValueError("Mapping is not a dict")
        if not objective:
            raise ValueError("Objective is empty")
        log(f"LLM returned objective ({len(objective)} chars) and mapping ({len(mapping)} entries).", "LLM")
        return objective, mapping
    except (json.JSONDecodeError, ValueError) as e:
        log(f"Failed to parse LLM response as JSON: {e}", "ERR")
        log(f"Raw response: {response}", "ERR")
        log("Falling back to Python anonymizer...", "WARN")

        anonymizer = SensitiveDataAnonymizer()
        target_anonymized = anonymizer.sanitize(target_raw)
        mapping = anonymizer.mapping.copy()
        if not mapping:
            log("WARNING: Python anonymizer found no sensitive data in target.txt. Mapping will be empty.", "WARN")

        lines = target_anonymized.splitlines()
        has_sections = any('TARGET:' in line or 'IN_SCOPE:' in line or 'OUT_OF_SCOPE:' in line or 'OBJECTIVES:' in line or 'RULES:' in line for line in lines)
        if has_sections:
            objective = target_anonymized
        else:
            objective = f"TARGET: {target_anonymized}\nIN_SCOPE: all\nOUT_OF_SCOPE: nothing\nOBJECTIVES: Identifying vulnerabilities\nRULES: all"

        log(f"Fallback objective built (length {len(objective)}), mapping entries {len(mapping)}", "PHASE")
        return objective, mapping


def context_agent_loop(context_path: str, objective: str, stop_event: threading.Event) -> None:
    global _CONTEXT_SEMAPHORE
    if _CONTEXT_SEMAPHORE is None:
        _CONTEXT_SEMAPHORE = threading.Semaphore(10)
    _CONTEXT_SEMAPHORE.acquire()
    try:
        ctx_name = context_name_from_path(context_path)
        log(f"Agent started for: {ctx_name}", "THR")
        iteration = 0
        cli_context_limit = CLI_CONTEXT_CHAR_LIMIT if LLM_BACKEND_MODE in {"codex", "gemini", "codex_gemini"} else None

        while not stop_event.is_set() and iteration < APP_CONFIG.max_iterations:
            iteration += 1

            if not os.path.exists(context_path):
                log(f"[{ctx_name}] File disappeared, exiting.", "WARN")
                break
            if is_finished(context_path):
                log(f"[{ctx_name}] Already finished, exiting.", "CTX")
                break

            ctx_content = read_file(context_path)
            all_active = get_active_context_files()
            messages = [
                {
                    "role": "user",
                    "content": f"{SYSTEM_PROMPT}\n\n{build_user_prompt(objective, ctx_name, ctx_content, all_active, max_context_chars=cli_context_limit)}",
                }
            ]

            try:
                log(f"[{ctx_name}] LLM call #{iteration}...", "LLM")
                response = call_llm(messages)
            except Exception as exc:
                log(f"[{ctx_name}] LLM failed: {exc}. Waiting 20s...", "ERR")
                time.sleep(20)
                continue

            log(f"[{ctx_name}] → {response[:100].replace(chr(10), ' ')}", "ACT")
            action = parse_llm_response(response)
            action_type = action["type"]
            log(f"[{ctx_name}] Action type: {action_type}", "ACT")

            if action_type == "CMD":
                cmd = action["command"]
                comment = action.get("comment", "").strip()
                output = execute_command(cmd, comment=comment or None)
                append_to_context(context_path, cmd, output, comment or None)

            elif action_type == "CREATE_CONTEXT":
                new_name = action["name"]
                new_path = create_context_file(new_name)
                _spawn_context_agent(new_path, objective, stop_event)

            elif action_type == "SPAWN_TO_NEW_CONTEXT":
                new_name = action["name"]
                new_path = create_context_file(new_name)
                removed_comment, removed_cmd, removed_out = remove_last_entry_from_context(context_path)
                if removed_cmd:
                    append_to_context(new_path, removed_cmd, removed_out, removed_comment or None)
                    log(f"[{ctx_name}] Moved last entry → {Path(new_path).name}", "CTX")
                _spawn_context_agent(new_path, objective, stop_event)

            elif action_type == "ADD_TO_CONTEXT":
                target_name = action["target"]
                cmd = action["command"]
                comment = action.get("comment", "").strip()
                target_path = resolve_context_path(target_name)

                if target_path is None:
                    target_path = create_context_file(target_name)

                output = execute_command(cmd, comment=comment or None)

                if is_finished(target_path):
                    target_path = unmark_context_finished(target_path)

                append_to_context(target_path, cmd, output, comment or None)
                log(f"[{ctx_name}] Added cmd to {Path(target_path).name}", "CTX")
                _spawn_context_agent(target_path, objective, stop_event)

            elif action_type == "REPLACE_IN_CONTEXT":
                target_name = action["target"]
                old_cmd = action["old_cmd"]
                new_cmd = action["new_cmd"]
                comment = action.get("comment", "").strip()
                target_path = resolve_context_path(target_name)

                if target_path:
                    new_output = execute_command(new_cmd, comment=comment or None)
                    ok = replace_entry_in_context(
                        target_path,
                        old_cmd,
                        new_cmd,
                        new_output,
                        comment or None,
                    )
                    if ok:
                        log(f"[{ctx_name}] Replaced cmd in {Path(target_path).name}", "CTX")
                        if is_finished(target_path):
                            target_path = unmark_context_finished(target_path)
                        _spawn_context_agent(target_path, objective, stop_event)
                    else:
                        log(f"[{ctx_name}] Old cmd not found in {target_name}", "WARN")
                else:
                    log(f"[{ctx_name}] REPLACE_IN_CONTEXT target not found: {target_name}", "WARN")

            elif action_type == "FINISHED":
                summary = action["summary"]
                new_path = mark_context_finished(context_path, summary)
                log(f"[{ctx_name}] Context finished → {Path(new_path).name}", "CTX")
                break

            else:
                log(f"[{ctx_name}] Unknown action. Raw: {response[:150]}", "WARN")
                time.sleep(8)
                continue

            time.sleep(3)

        if iteration >= APP_CONFIG.max_iterations:
            log(f"[{ctx_name}] Reached MAX_ITERATIONS ({APP_CONFIG.max_iterations}). Stopping.", "WARN")

        log(f"[{ctx_name}] Agent loop exited (iterations={iteration})", "THR")
    finally:
        _CONTEXT_SEMAPHORE.release()
        with _THREADS_LOCK:
            _ACTIVE_THREADS.pop(context_path, None)


def _spawn_context_agent(context_path: str, objective: str, stop_event: threading.Event) -> None:
    with _THREADS_LOCK:
        existing = _ACTIVE_THREADS.get(context_path)
        if existing and existing.is_alive():
            return

        name = f"ctx-{context_name_from_path(context_path)}"
        thread = threading.Thread(
            target=context_agent_loop,
            args=(context_path, objective, stop_event),
            daemon=True,
            name=name,
        )
        _ACTIVE_THREADS[context_path] = thread
    thread.start()
    log(f"Thread spawned: {name}", "THR")


def print_status() -> None:
    active = get_active_context_files()
    finished = get_finished_context_files()
    with PRINT_LOCK:
        print("\n" + "─" * 55)
        print(f"  STATUS  |  Active: {len(active)}  |  Finished: {len(finished)}")
        print("─" * 55)
        for path in active:
            size = Path(path).stat().st_size if Path(path).exists() else 0
            print(f"  [ACTIVE  ] {Path(path).name:40s}  {size:>6} B")
        for path in finished:
            size = Path(path).stat().st_size if Path(path).exists() else 0
            print(f"  [FINISHED] {Path(path).name:40s}  {size:>6} B")
        print("─" * 55 + "\n")


def run(max_contexts: int, zip_input: Path | None) -> None:
    global _CONTEXT_SEMAPHORE, _DEFAULT_EXECUTOR

    # Restauration du snapshot si fourni
    if zip_input is not None:
        zip_path = Path(zip_input).expanduser().resolve()
        if zip_path.exists():
            log(f"Restauration du snapshot : {zip_path}", "MAIN")
            unzip_files_directory(zip_path, APP_CONFIG.files_dir)
        else:
            log(f"Fichier zip introuvable : {zip_path}, démarrage avec un dossier files/ vide.", "WARN")
            if APP_CONFIG.files_dir.exists():
                shutil.rmtree(APP_CONFIG.files_dir)
            APP_CONFIG.files_dir.mkdir(parents=True, exist_ok=True)
    else:
        APP_CONFIG.files_dir.mkdir(parents=True, exist_ok=True)

    # Initialiser l'anonymizer
    if _DEFAULT_EXECUTOR is None:
        _DEFAULT_EXECUTOR = SensitiveDataAnonymizer()

    _CONTEXT_SEMAPHORE = threading.Semaphore(max_contexts)

    # ========== AFFICHAGE DU LOGO ==========
    print("\n" + "═" * 62)
    print("  ██████╗ ███╗   ███╗██╗    ██╗        ██████╗ ███████╗███╗   ██╗")
    print("  ██╔══██╗████╗ ████║██║    ██║        ██╔══██╗██╔════╝████╗  ██║")
    print("  ██████╔╝██╔████╔██║██║ █╗ ██║        ██████╔╝█████╗  ██╔██╗ ██║")
    print("  ██╔══██╗██║╚██╔╝██║██║███╗██║        ██╔═══╝ ██╔══╝  ██║╚██╗██║")
    print("  ██║  ██║██║ ╚═╝ ██║╚███╔███╔╝███████╗██║     ███████╗██║ ╚████║")
    print("  ╚═╝  ╚═╝╚═╝     ╚═╝ ╚══╝╚══╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝")
    print("  ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗")
    print("  ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝")
    print("  ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  ")
    print("  ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  ")
    print("  ███████║   ██║   ██║  ██║██║██║  ██╗███████╗")
    print("  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝")
    print(f"  {PROJECT_NAME} — Autonomous Black-Box Pentest Tool")
    print("═" * 62 + "\n")
    log(f"Maximum concurrent contexts: {max_contexts}", "MAIN")

    # ========== GÉNÉRATION DE objective.txt ==========
    if APP_CONFIG.objective_file.exists():
        log("objective.txt found — skipping generation.", "PHASE")
        objective = read_file(APP_CONFIG.objective_file)
    else:
        if not APP_CONFIG.target_file.exists():
            raise FileNotFoundError("target.txt is required to generate objective.txt")
        target_raw = read_file(APP_CONFIG.target_file)
        objective, mapping = generate_objective_and_mapping(target_raw)

        write_file(APP_CONFIG.objective_file, objective)
        log(f"objective.txt written ({len(objective)} chars)", "PHASE")

        mapping_path = APP_CONFIG.base_dir / "mapping.txt"
        write_file(mapping_path, json.dumps(mapping, indent=2))
        log(f"mapping.txt written with {len(mapping)} entries at {mapping_path}", "PHASE")

        # Recharger l'anonymizer global
        _DEFAULT_EXECUTOR = SensitiveDataAnonymizer()
        log("Anonymizer reloaded with fresh mapping from disk.", "PHASE")

    log(f"Objective loaded ({len(objective)} chars)", "PHASE")

    # ========== CONTEXTE D'ÉNUMÉRATION ==========
    enum_path = APP_CONFIG.files_dir / f"{APP_CONFIG.context_prefix}enumeration{APP_CONFIG.context_ext}"
    if not enum_path.exists():
        log("Phase 2: Creating enumeration context", "PHASE")
        enum_path = Path(create_context_file("enumeration"))
    else:
        log("Enumeration context already exists — resuming.", "PHASE")

    stop_event = _STOP_EVENT
    _spawn_context_agent(str(enum_path), objective, stop_event)

    log("Orchestrator running. Ctrl+C to stop.\n", "MAIN")
    status_interval = 30
    last_status = 0.0

    try:
        while True:
            time.sleep(5)

            for ctx_path in get_active_context_files():
                with _THREADS_LOCK:
                    alive = ctx_path in _ACTIVE_THREADS and _ACTIVE_THREADS[ctx_path].is_alive()
                if not alive:
                    log(f"Restarting agent for: {Path(ctx_path).name}", "MAIN")
                    _spawn_context_agent(ctx_path, objective, stop_event)

            if time.time() - last_status >= status_interval:
                print_status()
                last_status = time.time()

            if all_contexts_finished():
                log("ALL CONTEXTS FINISHED — pentest complete!", "MAIN")
                break

    except KeyboardInterrupt:
        log("\nInterrupted by user — stopping all agents...", "MAIN")
        stop_event.set()
        time.sleep(4)

    for thread in list(_ACTIVE_THREADS.values()):
        thread.join(timeout=2)

    print("\n" + "═" * 62)
    print("  PENTEST COMPLETE — FINAL REPORT")
    print("═" * 62)
    print(f"\n  Objective:  {APP_CONFIG.objective_file}")
    print(f"  Sandbox:    {APP_CONFIG.files_dir}\n")

    all_ctx = sorted(get_all_context_files())
    for path in all_ctx:
        status = "✔ FINISHED" if is_finished(path) else "✘ INCOMPLETE"
        size = Path(path).stat().st_size if Path(path).exists() else 0
        print(f"  [{status}]  {Path(path).name}  ({size} B)")

    print(
        """
  ── Report files ──────────────────────────────────────────────
  Each context_*_finished.txt contains:
   • All commands executed and their outputs
   • Summary of findings for that investigation area
   • Vulnerabilities discovered with evidence

  To read a context:
    cat files/context_<name>_finished.txt
    less files/context_<name>_finished.txt
═══════════════════════════════════════════════════════════════
"""
    )


def main(argv: list[str] | None = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.mode == "apis" and not args.env:
        parser.error("Mode 'apis' requires -e/--env to point to env.txt or a directory containing env.txt.")

    try:
        _apply_runtime_config(args.scope, args.mode, args.env)
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))

    zip_path = Path(args.zip) if args.zip is not None else None

    # Installer les hooks de finalisation (rapport + zip) AVANT de lancer le pentest
    try:
        import report_finalize
        report_finalize.set_output_zip(zip_path)
        report_finalize.set_output_options(
            redact_level=args.redact_level,
            classification=args.classification,
            export_docx=not args.no_docx,
        )
        report_finalize.install_hooks()
        log("Hooks de finalisation installés.", "DEBUG")
    except Exception as e:
        log(f"Hooks de finalisation non installés : {e}", "ERR")

    run(args.max_contexts, zip_path)


if __name__ == "__main__":
    main()
