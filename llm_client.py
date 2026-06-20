#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

import httpx
from openai import OpenAI

from config import APP_CONFIG
from logger import log

# Change this manually to one of:
#   "apis"         -> use API_KEYS from env.txt with round-robin rotation
#   "codex"        -> send prompts to the local Codex CLI only
#   "gemini"       -> send prompts to the local Gemini CLI only
#   "codex_gemini" -> alternate Codex and Gemini; if one fails, keep using the survivor
LLM_BACKEND_MODE = "gemini"
ALLOWED_LLM_BACKEND_MODES = {"apis", "codex", "gemini", "codex_gemini"}
# Keep CLI prompts bounded so Codex/Gemini stay responsive on long-running contexts.
# Codex becomes unreliable once the current context grows too large, so this stays conservative.
CLI_CONTEXT_CHAR_LIMIT = 2000


@dataclass(frozen=True)
class LLMRoute:
    api_key: str
    base_url: str
    model: str


_API_ROTATION_LOCK = threading.Lock()
_CLI_ROTATION_LOCK = threading.Lock()
_CLIENT_CACHE: dict[tuple[str, str], OpenAI] = {}
_CLI_NEXT_INDEX = 0
_CLI_SOLO_PROVIDER: str | None = None
GEMINI_CLI_MODELS = ("gemini-2.5-flash", "gemini-2.5-flash-lite")

# États pour les trois sources
_ROTATION_INDEX_PENTEST = 0
_ROTATION_INDEX_EXECUTOR = 0
_ROTATION_INDEX_REPORT = 0


def _get_source_index(source: str) -> int:
    global _ROTATION_INDEX_PENTEST, _ROTATION_INDEX_EXECUTOR, _ROTATION_INDEX_REPORT
    if source == "pentest":
        return _ROTATION_INDEX_PENTEST
    elif source == "executor":
        return _ROTATION_INDEX_EXECUTOR
    elif source == "report":
        return _ROTATION_INDEX_REPORT
    else:
        return 0


def _set_source_index(source: str, idx: int) -> None:
    global _ROTATION_INDEX_PENTEST, _ROTATION_INDEX_EXECUTOR, _ROTATION_INDEX_REPORT
    if source == "pentest":
        _ROTATION_INDEX_PENTEST = idx
    elif source == "executor":
        _ROTATION_INDEX_EXECUTOR = idx
    elif source == "report":
        _ROTATION_INDEX_REPORT = idx


def _rotation_routes_pentest() -> tuple[LLMRoute, ...]:
    return tuple(
        LLMRoute(api_key=api_key, base_url=base_url, model=model)
        for api_key, base_url, model in APP_CONFIG.rotation_routes_pentest
    )


def _rotation_routes_executor() -> tuple[LLMRoute, ...]:
    return tuple(
        LLMRoute(api_key=api_key, base_url=base_url, model=model)
        for api_key, base_url, model in APP_CONFIG.rotation_routes_executor
    )


def _rotation_routes_report() -> tuple[LLMRoute, ...]:
    return tuple(
        LLMRoute(api_key=api_key, base_url=base_url, model=model)
        for api_key, base_url, model in APP_CONFIG.rotation_routes_report
    )


def _get_client(api_key: str, base_url: str) -> OpenAI:
    cache_key = (api_key, base_url)
    client = _CLIENT_CACHE.get(cache_key)
    if client is None:
        client = OpenAI(
            api_key=api_key,
            base_url=base_url,
            http_client=httpx.Client(trust_env=False),
        )
        _CLIENT_CACHE[cache_key] = client
    return client


def _normalize_prompt(messages: list) -> str:
    if not messages:
        return ""
    if len(messages) == 1:
        content = messages[0].get("content", "")
        return content if isinstance(content, str) else str(content)

    parts: list[str] = []
    for message in messages:
        role = str(message.get("role", "user")).upper()
        content = message.get("content", "")
        parts.append(f"{role}:\n{content if isinstance(content, str) else str(content)}")
    return "\n\n".join(parts)


def _call_api_backend(messages: list, max_tokens: int, source: str) -> str:
    """Appel API avec rotation pour la source donnée."""
    if source == "pentest":
        routes = _rotation_routes_pentest()
    elif source == "executor":
        routes = _rotation_routes_executor()
    elif source == "report":
        routes = _rotation_routes_report()
    else:
        raise ValueError(f"Unknown source: {source}")

    if not routes:
        raise RuntimeError(f"No LLM routes configured for source {source}.")

    with _API_ROTATION_LOCK:
        start_idx = _get_source_index(source)

    last_err: str | None = None
    total_routes = len(routes)

    for attempt in range(total_routes):
        idx = (start_idx + attempt) % total_routes
        route = routes[idx]
        try:
            client = _get_client(route.api_key, route.base_url)
            response = client.chat.completions.create(
                model=route.model,
                messages=messages,
                max_tokens=max_tokens,
                temperature=0.1,
                timeout=APP_CONFIG.llm_timeout_s,
            )
            content = response.choices[0].message.content or ""
            result = content.strip()
            with _API_ROTATION_LOCK:
                _set_source_index(source, (idx + 1) % total_routes)
            log(f"LLM ok ({route.model}) [source={source}]", "LLM")
            return result
        except Exception as exc:
            error_text = str(exc)
            last_err = f"{route.model}: {error_text[:120]}"
            if "timeout" in error_text.lower():
                log(f"Model {route.model} timed out, trying next...", "WARN")
            else:
                log(f"Model {route.model} error: {error_text[:120]}, trying next...", "WARN")

    raise RuntimeError(f"All LLM routes failed for source {source}. Last error: {last_err}")


def _call_codex_cli(prompt: str) -> str:
    with tempfile.NamedTemporaryFile(
        "w+", delete=False, encoding="utf-8", dir=str(APP_CONFIG.files_dir)
    ) as handle:
        output_path = Path(handle.name)

    try:
        timeout_s = max(APP_CONFIG.codex_timeout_s, 300)
        command = [
            "codex",
            "exec",
            "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox",
            "--ephemeral",
            "-c",
            'reasoning_effort="low"',
            "--output-last-message",
            str(output_path),
            "-",
        ]
        result = subprocess.run(
            command,
            input=prompt,
            text=True,
            capture_output=True,
            timeout=timeout_s,
            encoding="utf-8",
            errors="replace",
            cwd=str(APP_CONFIG.files_dir),
        )
        if result.returncode != 0:
            stderr = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(stderr or f"codex exited with code {result.returncode}")

        if output_path.exists():
            content = output_path.read_text(encoding="utf-8", errors="replace").strip()
            if content:
                log("LLM ok (codex)", "LLM")
                return content

        fallback = (result.stdout or result.stderr or "").strip()
        if fallback:
            log("LLM ok (codex)", "LLM")
            return fallback
        raise RuntimeError("codex returned an empty response")
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"codex timed out after {timeout_s}s") from exc
    finally:
        try:
            output_path.unlink(missing_ok=True)
        except Exception:
            pass


def _call_gemini_cli(prompt: str) -> str:
    last_error: str | None = None
    for model in GEMINI_CLI_MODELS:
        command = [
            "gemini",
            "--output-format",
            "text",
            "--yolo",
            "--sandbox",
            "false",
            "--model",
            model,
        ]
        try:
            result = subprocess.run(
                command,
                input=prompt,
                text=True,
                capture_output=True,
                timeout=APP_CONFIG.llm_timeout_s,
                encoding="utf-8",
                errors="replace",
                cwd=str(APP_CONFIG.files_dir),
            )
        except subprocess.TimeoutExpired as exc:
            last_error = f"gemini {model} timed out after {APP_CONFIG.llm_timeout_s}s"
            if model != GEMINI_CLI_MODELS[-1]:
                log(f"gemini model {model} timed out, trying fallback model...", "WARN")
                continue
            raise RuntimeError(last_error) from exc

        stdout_text = (result.stdout or "").strip()
        stderr_text = (result.stderr or "").strip()
        combined_error = "\n".join(part for part in (stderr_text, stdout_text) if part).strip()

        if result.returncode == 0 and stdout_text:
            log(f"LLM ok (gemini:{model})", "LLM")
            return stdout_text

        last_error = combined_error or f"gemini exited with code {result.returncode}"

        if model != GEMINI_CLI_MODELS[-1]:
            log(f"gemini model {model} failed, trying fallback model...", "WARN")
            continue

    raise RuntimeError(last_error or "gemini returned an empty response")


def _call_cli_backend(messages: list) -> str:
    global _CLI_NEXT_INDEX, _CLI_SOLO_PROVIDER

    prompt = _normalize_prompt(messages)
    providers = ["codex", "gemini"]

    with _CLI_ROTATION_LOCK:
        solo_provider = _CLI_SOLO_PROVIDER
        start_idx = _CLI_NEXT_INDEX

    if solo_provider in providers:
        ordered = [solo_provider, "gemini" if solo_provider == "codex" else "codex"]
    else:
        ordered = providers[start_idx:] + providers[:start_idx]

    last_err: str | None = None
    had_failure = False
    for provider in ordered:
        try:
            if provider == "codex":
                result = _call_codex_cli(prompt)
            else:
                result = _call_gemini_cli(prompt)

            with _CLI_ROTATION_LOCK:
                if solo_provider in providers:
                    _CLI_SOLO_PROVIDER = provider
                elif had_failure:
                    _CLI_SOLO_PROVIDER = provider
                else:
                    _CLI_NEXT_INDEX = 1 if provider == "codex" else 0
            return result
        except Exception as exc:
            last_err = f"{provider}: {str(exc)[:120]}"
            log(f"{provider} CLI error: {str(exc)[:120]}", "WARN")
            had_failure = True

    raise RuntimeError(f"All CLI LLM providers failed. Last error: {last_err}")


def call_llm(messages: list, max_tokens: int | None = None, source: str = "pentest") -> str:
    global _CLI_SOLO_PROVIDER

    if LLM_BACKEND_MODE not in ALLOWED_LLM_BACKEND_MODES:
        allowed = ", ".join(sorted(ALLOWED_LLM_BACKEND_MODES))
        raise ValueError(f"LLM_BACKEND_MODE must be one of: {allowed}")

    token_limit = APP_CONFIG.llm_max_tokens if max_tokens is None else max_tokens

    if LLM_BACKEND_MODE == "apis":
        _CLI_SOLO_PROVIDER = None
        return _call_api_backend(messages, token_limit, source)
    if LLM_BACKEND_MODE == "codex":
        _CLI_SOLO_PROVIDER = None
        return _call_codex_cli(_normalize_prompt(messages))
    if LLM_BACKEND_MODE == "gemini":
        _CLI_SOLO_PROVIDER = None
        return _call_gemini_cli(_normalize_prompt(messages))
    return _call_cli_backend(messages)
