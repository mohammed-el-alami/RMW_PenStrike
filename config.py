#!/usr/bin/env python3
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

PROJECT_NAME = "RMW-PenStrike"
BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = BASE_DIR / "files"
ENV_FILE = BASE_DIR / "env.txt"

CONTEXT_PREFIX = "context_"
CONTEXT_EXT = ".txt"
FINISHED_SUFFIX = "_finished"

TARGET_FILE = FILES_DIR / "target.txt"
OBJECTIVE_FILE = FILES_DIR / "objective.txt"
STATE_FILE = FILES_DIR / ".model_rotation_state.json"

MAX_CMD_OUTPUT = 4000
CMD_TIMEOUT_S = 180
MAX_ITERATIONS = 150
DEFAULT_LLM_TIMEOUT_S = 90
DEFAULT_LLM_MAX_TOKENS = 1024
DEFAULT_CODEX_TIMEOUT_S = 180

FILES_DIR.mkdir(parents=True, exist_ok=True)


@dataclass(frozen=True)
class LLMSourceConfig:
    api_key: str
    base_url: str
    models: tuple[str, ...]


@dataclass(frozen=True)
class AppConfig:
    project_name: str
    base_dir: Path
    files_dir: Path
    env_file: Path
    target_file: Path
    objective_file: Path
    state_file: Path
    context_prefix: str
    context_ext: str
    finished_suffix: str
    max_cmd_output: int
    cmd_timeout_s: int
    max_iterations: int
    llm_timeout_s: int
    llm_max_tokens: int
    codex_timeout_s: int
    # Sources pour chaque usage
    llm_sources: tuple[LLMSourceConfig, ...]          # pentest (principal)
    llm_sources_executor: tuple[LLMSourceConfig, ...] # executor (anonymisation)
    llm_sources_report: tuple[LLMSourceConfig, ...]   # report generator

    @property
    def rotation_routes(self) -> tuple[tuple[str, str, str], ...]:
        # Pour compatibilité avec l'ancien code
        routes: list[tuple[str, str, str]] = []
        for source in self.llm_sources:
            for model in source.models:
                routes.append((source.api_key, source.base_url, model))
        return tuple(routes)

    @property
    def rotation_routes_pentest(self) -> tuple[tuple[str, str, str], ...]:
        routes = []
        for source in self.llm_sources:
            for model in source.models:
                routes.append((source.api_key, source.base_url, model))
        return tuple(routes)

    @property
    def rotation_routes_executor(self) -> tuple[tuple[str, str, str], ...]:
        routes = []
        for source in self.llm_sources_executor:
            for model in source.models:
                routes.append((source.api_key, source.base_url, model))
        return tuple(routes)

    @property
    def rotation_routes_report(self) -> tuple[tuple[str, str, str], ...]:
        routes = []
        for source in self.llm_sources_report:
            for model in source.models:
                routes.append((source.api_key, source.base_url, model))
        return tuple(routes)


def _parse_env_file(path: Path) -> dict[str, object]:
    values: dict[str, object] = {}
    if not path.exists():
        return values

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue
        try:
            values[target.id] = ast.literal_eval(node.value)
        except Exception:
            continue
    return values


def _normalize_sources(raw_sources: object) -> tuple[LLMSourceConfig, ...]:
    if raw_sources in (None, "", []):
        return ()
    if not isinstance(raw_sources, (list, tuple)) or not raw_sources:
        raise ValueError(
            "env.txt API_KEYS must be a list of [api_key, base_url, model1, ...] entries."
        )

    sources: list[LLMSourceConfig] = []
    for entry in raw_sources:
        if not isinstance(entry, (list, tuple)) or len(entry) < 3:
            raise ValueError(
                "Each API_KEYS entry must be: [api_key, base_url, model1, model2, ...]"
            )
        api_key = str(entry[0]).strip()
        base_url = str(entry[1]).strip()
        models = tuple(str(model).strip() for model in entry[2:] if str(model).strip())
        if not api_key or not base_url or not models:
            raise ValueError("Each API_KEYS entry needs a key, a base URL, and at least one model.")
        sources.append(LLMSourceConfig(api_key=api_key, base_url=base_url, models=models))
    return tuple(sources)


def load_config(
    env_file: Path | None = None,
    target_file: Path | None = None,
    objective_file: Path | None = None,
    state_file: Path | None = None,
) -> AppConfig:
    resolved_env_file = ENV_FILE if env_file is None else Path(env_file)
    resolved_target_file = TARGET_FILE if target_file is None else Path(target_file)
    resolved_objective_file = OBJECTIVE_FILE if objective_file is None else Path(objective_file)
    resolved_state_file = STATE_FILE if state_file is None else Path(state_file)

    env_values = _parse_env_file(resolved_env_file)
    llm_sources = _normalize_sources(env_values.get("API_KEYS_PENTEST") or env_values.get("API_KEYS"))
    llm_sources_executor = _normalize_sources(env_values.get("API_KEYS_EXECUTOR") or env_values.get("API_KEYS"))
    llm_sources_report = _normalize_sources(env_values.get("API_KEYS_REPORT") or env_values.get("API_KEYS"))
    llm_timeout_s = int(env_values.get("LLM_TIMEOUT_S", DEFAULT_LLM_TIMEOUT_S))
    llm_max_tokens = int(env_values.get("LLM_MAX_TOKENS", DEFAULT_LLM_MAX_TOKENS))
    codex_timeout_s = int(env_values.get("CODEX_TIMEOUT_S", DEFAULT_CODEX_TIMEOUT_S))
    return AppConfig(
        project_name=PROJECT_NAME,
        base_dir=BASE_DIR,
        files_dir=FILES_DIR,
        env_file=resolved_env_file,
        target_file=resolved_target_file,
        objective_file=resolved_objective_file,
        state_file=resolved_state_file,
        context_prefix=CONTEXT_PREFIX,
        context_ext=CONTEXT_EXT,
        finished_suffix=FINISHED_SUFFIX,
        max_cmd_output=MAX_CMD_OUTPUT,
        cmd_timeout_s=CMD_TIMEOUT_S,
        max_iterations=MAX_ITERATIONS,
        llm_timeout_s=llm_timeout_s,
        llm_max_tokens=llm_max_tokens,
        codex_timeout_s=codex_timeout_s,
        llm_sources=llm_sources,
        llm_sources_executor=llm_sources_executor,
        llm_sources_report=llm_sources_report,
    )


APP_CONFIG = load_config()
