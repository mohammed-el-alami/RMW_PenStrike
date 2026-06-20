#!/usr/bin/env python3
from __future__ import annotations

import threading
import time

PRINT_LOCK = threading.Lock()

COLORS = {
    "INFO": "\033[0m",
    "PHASE": "\033[1;36m",
    "LLM": "\033[0;33m",
    "CMD": "\033[0;32m",
    "CTX": "\033[0;34m",
    "ACT": "\033[1;35m",
    "THR": "\033[0;35m",
    "WARN": "\033[1;33m",
    "ERR": "\033[1;31m",
    "MAIN": "\033[1;37m",
    "RESET": "\033[0m",
}


def log(msg: str, tag: str = "INFO") -> None:
    color = COLORS.get(tag, "")
    reset = COLORS["RESET"]
    with PRINT_LOCK:
        print(f"{color}[{tag:5s}] {msg}{reset}")

