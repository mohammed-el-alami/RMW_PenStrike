#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path

from config import APP_CONFIG
from logger import log

_FILE_LOCKS: dict[str, threading.Lock] = {}
_FILE_LOCKS_META = threading.Lock()


def _get_file_lock(path: str) -> threading.Lock:
    with _FILE_LOCKS_META:
        lock = _FILE_LOCKS.get(path)
        if lock is None:
            lock = threading.Lock()
            _FILE_LOCKS[path] = lock
        return lock


def read_file(path: str | Path) -> str:
    path_str = str(path)
    lock = _get_file_lock(path_str)
    with lock:
        try:
            with open(path_str, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except FileNotFoundError:
            return ""


def write_file(path: str | Path, content: str) -> None:
    path_obj = Path(path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    path_str = str(path_obj)
    lock = _get_file_lock(path_str)
    with lock:
        with open(path_str, "w", encoding="utf-8") as handle:
            handle.write(content)


def append_to_context(
    path: str | Path,
    cmd: str,
    output: str,
    comment: str | None = None,
) -> None:
    comment_text = (comment or "").strip()
    entry = "\n"
    if comment_text:
        entry += f"[COMMENT] {comment_text}\n"
    entry += f"[CMD] {cmd}\n[OUT]\n{output}\n[/OUT]\n"
    path_str = str(path)
    lock = _get_file_lock(path_str)
    with lock:
        with open(path_str, "a", encoding="utf-8") as handle:
            handle.write(entry)


def remove_last_entry_from_context(path: str | Path) -> tuple[str, str, str]:
    path_str = str(path)
    lock = _get_file_lock(path_str)
    with lock:
        try:
            content = open(path_str, "r", encoding="utf-8", errors="replace").read()
        except FileNotFoundError:
            return "", "", ""

        pattern = r"(?:\[COMMENT\] (.*?)\n)?\[CMD\] (.+?)\n\[OUT\]\n(.*?)\[/OUT\]"
        matches = list(re.finditer(pattern, content, re.DOTALL))
        if not matches:
            return "", "", ""

        last = matches[-1]
        comment_v = (last.group(1) or "").strip()
        cmd_v = last.group(2).strip()
        out_v = last.group(3).strip()
        new_content = content[: last.start()] + content[last.end() :]
        with open(path_str, "w", encoding="utf-8") as handle:
            handle.write(new_content)
        return comment_v, cmd_v, out_v


def replace_entry_in_context(
    path: str | Path,
    old_cmd: str,
    new_cmd: str,
    new_output: str,
    comment: str | None = None,
) -> bool:
    path_str = str(path)
    lock = _get_file_lock(path_str)
    with lock:
        try:
            content = open(path_str, "r", encoding="utf-8", errors="replace").read()
        except FileNotFoundError:
            return False

        escaped = re.escape(old_cmd)
        pattern = rf"(?:\[COMMENT\] .*?\n)?\[CMD\] {escaped}\n\[OUT\]\n.*?\[/OUT\]"
        comment_text = (comment or "").strip()
        new_block = ""
        if comment_text:
            new_block += f"[COMMENT] {comment_text}\n"
        new_block += f"[CMD] {new_cmd}\n[OUT]\n{new_output}\n[/OUT]"
        new_content, replaced = re.subn(pattern, new_block, content, flags=re.DOTALL)
        if replaced == 0:
            return False
        with open(path_str, "w", encoding="utf-8") as handle:
            handle.write(new_content)
        return True


def context_name_from_path(path: str | Path) -> str:
    base = os.path.basename(str(path))
    name = base.replace(APP_CONFIG.context_prefix, "", 1)
    name = name.replace(APP_CONFIG.finished_suffix + APP_CONFIG.context_ext, "")
    name = name.replace(APP_CONFIG.context_ext, "")
    return name


def is_finished(path: str | Path) -> bool:
    return APP_CONFIG.finished_suffix in os.path.basename(str(path))


def get_all_context_files() -> list[str]:
    files: list[str] = []
    for item in APP_CONFIG.files_dir.iterdir():
        if item.name.startswith(APP_CONFIG.context_prefix) and item.name.endswith(APP_CONFIG.context_ext):
            files.append(str(item))
    return sorted(files)


def get_active_context_files() -> list[str]:
    return [path for path in get_all_context_files() if not is_finished(path)]


def get_finished_context_files() -> list[str]:
    return [path for path in get_all_context_files() if is_finished(path)]


def all_contexts_finished() -> bool:
    context_files = get_all_context_files()
    return bool(context_files) and all(is_finished(path) for path in context_files)


def create_context_file(name: str) -> str:
    safe = re.sub(r"[^\w\-]", "_", name.strip().lower())[:40]
    path = APP_CONFIG.files_dir / f"{APP_CONFIG.context_prefix}{safe}{APP_CONFIG.context_ext}"
    if not path.exists():
        header = (
            f"# CONTEXT: {safe}\n"
            f"# Created: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"# This file records commands and outputs for: {safe}\n\n"
        )
        write_file(path, header)
        log(f"New context created: {path.name}", "CTX")
    return str(path)


def mark_context_finished(path: str | Path, summary: str) -> str:
    path_obj = Path(path)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    summary_text = (
        f"# CONTEXT FINISHED: {context_name_from_path(path_obj)}\n"
        f"# Completed: {timestamp}\n\n"
        f"{summary}\n"
    )
    new_path = path_obj.with_name(path_obj.name.replace(APP_CONFIG.context_ext, APP_CONFIG.finished_suffix + APP_CONFIG.context_ext))

    lock = _get_file_lock(str(path_obj))
    with lock:
        with open(path_obj, "w", encoding="utf-8") as handle:
            handle.write(summary_text)
        if path_obj != new_path:
            os.rename(path_obj, new_path)

    with _FILE_LOCKS_META:
        _FILE_LOCKS[str(new_path)] = _FILE_LOCKS.pop(str(path_obj), threading.Lock())
    log(f"Context finished → {new_path.name}", "CTX")
    return str(new_path)


def unmark_context_finished(path: str | Path) -> str:
    path_obj = Path(path)
    new_path = Path(str(path_obj).replace(APP_CONFIG.finished_suffix + APP_CONFIG.context_ext, APP_CONFIG.context_ext))
    if path_obj != new_path and path_obj.exists():
        lock = _get_file_lock(str(path_obj))
        with lock:
            os.rename(path_obj, new_path)
        with _FILE_LOCKS_META:
            _FILE_LOCKS[str(new_path)] = _FILE_LOCKS.pop(str(path_obj), threading.Lock())
        log(f"Context reopened: {new_path.name}", "CTX")
    return str(new_path)


def resolve_context_path(name_or_file: str) -> str | None:
    if os.path.isabs(name_or_file) and os.path.exists(name_or_file):
        return name_or_file

    candidate = APP_CONFIG.files_dir / name_or_file
    if candidate.exists():
        return str(candidate)

    target_lower = (
        name_or_file.lower()
        .replace(APP_CONFIG.context_prefix, "")
        .replace(APP_CONFIG.context_ext, "")
        .replace(APP_CONFIG.finished_suffix, "")
    )
    for path in get_all_context_files():
        fname = context_name_from_path(path).lower()
        if fname == target_lower or target_lower in fname:
            return path
    return None
