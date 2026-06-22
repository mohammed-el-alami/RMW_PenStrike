import base64
import ipaddress
import json
import math
import re
import subprocess
from binascii import Error as BinasciiError
from collections import Counter, defaultdict
from pathlib import Path
from config import APP_CONFIG
from logger import log
APP_DIR = Path(__file__).resolve().parent

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:  # pragma: no cover - optional legacy migration support
    Fernet = None
    InvalidToken = ValueError


def _default_llm_adapter(prompt: str) -> str:
    try:
        from llm_client import call_llm
    except Exception as exc:  # pragma: no cover - shared LLM stack unavailable
        raise RuntimeError("Shared LLM infrastructure is unavailable") from exc

    return call_llm([{"role": "user", "content": prompt}], max_tokens=512, source="executor")


_DEFAULT_EXECUTOR = None


def execute_command(
    cmd: str,
    timeout: int | None = None,
    comment: str | None = None,
) -> str:

    global _DEFAULT_EXECUTOR

    if comment:
        log(f"COMMENT: {comment}", "CMD")

    log(f"$ {cmd}", "CMD")

    if _DEFAULT_EXECUTOR is None:
        _DEFAULT_EXECUTOR = SensitiveDataAnonymizer()

    return _DEFAULT_EXECUTOR.executer(
        cmd,
        timeout=timeout,
    )


class SensitiveDataAnonymizer:
    TOKEN_PATTERN = re.compile(r"<([A-Z][A-Z0-9_]*)_(\d{3})>")
    JSON_START_PATTERN = re.compile(r"^\s*[\[{]")
    WORD_PATTERN = re.compile(r"[A-Za-z0-9_./+=:-]{21,}")
    # Ne plus bloquer automatiquement aucune catégorie
    BLOCKED_AUTOMATIC_CATEGORIES = set()
    FORBIDDEN_COMMAND_PATTERNS = [
        r"\.\./",
        r"/bin/",
        r"/etc/",
        r"/dev/",
        r"/proc/",
        r"/sys/",
        r"/root/",
        r"/home/",
        r"~",
        r"chroot\s",
        r"mount\s",
        r"umount\s",
        r"nsenter\s",
        r"unshare\s",
        r"sudo\s",
        r"docker\s",
        r"podman\s",
        r"lxc\s",
        r"cp\s.*\.\./",
        r"mv\s.*\.\./",
        r"ln\s.*\.\./",
    ]
    SAFE_ABSOLUTE_PATH_PREFIX = "/tmp/"
    LLM_EXCLUDED_VALUES = {
        "user",
        "username",
        "login",
        "password",
        "passwd",
        "pass",
        "passphrase",
        "pwd",
        "token",
        "secret",
        "apikey",
        "api_key",
        "access_token",
        "refresh_token",
        "authorization",
        "bearer",
        "cookie",
        "session",
        "sessionid",
        "admin",
        "host",
        "server",
        "email",
    }

    REGEX_PATTERNS = {
        "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "IP": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
        "UUID": re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "HASH": re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"),
        "BASE64_SECRET": re.compile(
            r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){4,}"
            r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?=$|[^A-Za-z0-9+/=])"
        ),
    }
    URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[^\s<>'\"()]+")

    CONTEXT_PATTERNS = {
        "CRED": re.compile(
            r"(?i)\b(?:username|user|login|password|passwd|pass|pwd)\s*[=:]\s*([^\s,;]+)"
        ),
        "PERSON": re.compile(r"(?im)^\s*cn\s*:\s*(.+?)\s*$"),
        "USER": re.compile(r"(?im)^\s*uid\s*:\s*([^\s,;]+)\s*$"),
        "EMAIL": re.compile(r"(?im)^\s*mail\s*:\s*([^\s,;]+)\s*$"),
        "API_KEY": re.compile(r"(?i)\b(?:apikey|api_key)\s*[=:]\s*([^\s,;]+)"),
        "K8S_NAMESPACE": re.compile(r"(?im)^\s*namespace\s*:\s*([^\s,;]+)\s*$"),
        "K8S_POD": re.compile(r"(?im)^\s*pod\s*:\s*([^\s,;]+)\s*$"),
        "SECRET": re.compile(
            r"(?i)\b(?:token|secret|apikey|api_key|access_token|refresh_token|key|"
            r"session|sessionid)\s*[=:]\s*([^\s,;]+)"
        ),
    }
    SQL_CONN_PATTERN = re.compile(
        r"(?i)(?P<field>Server|Database|User\s+ID|Password)\s*=\s*(?P<value>[^;\r\n]+)"
    )
    AUTHORIZATION_BEARER_PATTERN = re.compile(
        r"(?im)^(?P<prefix>\s*Authorization\s*:\s*Bearer\s+)"
        r"(?P<token>eyJ[A-Za-z0-9_-]*(?:\.\.\.|(?:\.[A-Za-z0-9_-]+){1,2}))"
        r"(?P<suffix>[^\r\n]*)$"
    )
    SMB_SHARE_HEADER_PATTERN = re.compile(r"(?i)^\s*Sharename\s+Type\b")
    SMB_SHARE_ROW_PATTERN = re.compile(
        r"^(?P<indent>\s*)(?P<share>\S+)(?P<spacing>\s{2,})"
        r"(?P<type>Disk|IPC|Printer|Device)\b"
    )
    AWS_S3_BUCKET_PATTERN = re.compile(r"(?i)\barn:aws:s3:::(?P<bucket>[a-z0-9.-]{3,63})\b")
    AWS_IAM_USER_PATTERN = re.compile(
        r"(?i)\barn:aws:iam::(?P<account>\d{12}):user/(?P<user>[A-Za-z0-9._-]+)\b"
    )

    def __init__(
        self,
        llm_client=None,
        key_file=None,
        map_file=None,
    ):
        self.llm_client = llm_client or _default_llm_adapter
        self.key_file = Path(key_file) if key_file else APP_DIR / "key.key"
        self.map_file = Path(map_file) if map_file else APP_DIR / "mapping.txt"

        self.mapping = {}
        self.reverse_mapping = {}
        self.counters = defaultdict(int)
        self.audit_log = []

        self._load_mapping()
        self._sync_counters()

    def sanitize(self, text: str, save: bool = True) -> str:
        if not isinstance(text, str):
            raise TypeError("sanitize(text) expects a string")

        self.audit_log.clear()
        result = text

        for _ in range(2):
            next_result = self._sanitize_json(result) if self._looks_like_json(result) else self._pipeline(result)
            result = next_result
            if not self._has_remaining_candidates(result):
                break

        if save:
            self._save_mapping()
        return result

    def desanitize(self, text: str) -> str:
        if not isinstance(text, str):
            raise TypeError("desanitize(text) expects a string")

        spans = []
        for token in sorted(self.mapping, key=len, reverse=True):
            for match in re.finditer(re.escape(token), text):
                spans.append((match.start(), match.end(), token, self.mapping[token]))

        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def executer(
        self,
        instruction: str,
        timeout: int | None = None,
    ) -> str:

        if not isinstance(instruction, str):
            raise TypeError("executer(instruction) expects a string")

        # NE PAS recharger le mapping ici, pour éviter d'écraser les ajouts en mémoire
        # self._load_mapping()   # <- SUPPRIMÉ
        log(f"Mapping loaded: {len(self.mapping)} entries", "DEBUG")

        # --- ÉTAPE 2 : préparer la commande (anonymisation si besoin) ---
        prepared_command = self._prepare_instruction(instruction)
        log(f"Prepared command: {prepared_command}", "DEBUG")

        # --- ÉTAPE 3 : remplacer les tokens par leurs valeurs réelles ---
        real_command = self._replace_tokens(prepared_command)
        log(f"Real command: {real_command}", "DEBUG")

        # --- ÉTAPE 4 : vérifier la sécurité ---
        safe, reason = self._is_safe_command(real_command)
        if not safe:
            return self.sanitize(
                f"[SECURITY BLOCKED] {reason} - command refused: {real_command}",
                save=True
            )

        # --- ÉTAPE 5 : exécuter ---
        try:
            completed = subprocess.run(
                real_command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=(
                    timeout
                    if timeout is not None
                    else APP_CONFIG.cmd_timeout_s
                ),
                cwd=str(APP_CONFIG.files_dir),
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            if not output.strip():
                output = "(no output — command produced nothing)"

            if len(output) > APP_CONFIG.max_cmd_output:
                half = APP_CONFIG.max_cmd_output // 2
                output = (
                    output[:half]
                    + f"\n\n... [OUTPUT TRUNCATED — showing first {half} "
                      f"and last {half} chars] ...\n\n"
                    + output[-half:]
                )

        except subprocess.TimeoutExpired as exc:
            output = (
                f"[TIMEOUT] Command killed after "
                f"{APP_CONFIG.cmd_timeout_s}s — "
                f"try a faster, narrower, or more targeted command."
            )
            if exc.stdout:
                output += "\n\nPartial stdout:\n" + str(exc.stdout)
            if exc.stderr:
                output += "\n\nPartial stderr:\n" + str(exc.stderr)
        except Exception as exc:
            output = (
                f"[ERROR executing command] "
                f"{exc.__class__.__name__}: {exc}"
            )

        # Sauvegarder le mapping (fusion avec l'existant) pour persister les nouveaux tokens
        return self.sanitize(output.rstrip("\n"), save=True)

    def _replace_tokens(self, text: str) -> str:
        """Remplace tous les tokens <CATEGORY_###> par leurs valeurs réelles."""
        if not self.mapping:
            log("WARNING: mapping is empty, tokens will not be replaced", "WARN")
            return text

        result = text
        for token, value in self.mapping.items():
            result = result.replace(token, value)
        return result

    @classmethod
    def _is_safe_command(cls, command: str):
        normalized_command = command.replace("\\", "/")
        stripped_command = normalized_command.lstrip()

        for pattern in cls.FORBIDDEN_COMMAND_PATTERNS:
            if re.search(pattern, normalized_command, re.IGNORECASE):
                return False, f"Forbidden pattern: {pattern}"

        if stripped_command.startswith("/") and not stripped_command.startswith(cls.SAFE_ABSOLUTE_PATH_PREFIX):
            return False, "Absolute path forbidden except /tmp"

        return True, None

    def _prepare_instruction(self, instruction: str) -> str:
        if self.TOKEN_PATTERN.search(instruction):
            return instruction
        return self.sanitize(instruction, save=True)

    def _load_mapping(self):
        if not self.map_file.exists():
            return

        try:
            payload = self.map_file.read_text(encoding="utf-8")
            self._set_mapping(json.loads(payload))
            self._save_mapping()
            return
        except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
            pass

        if self._load_legacy_encrypted_mapping():
            self._save_mapping()
            return

        self.mapping = {}
        self.reverse_mapping = {}

    def _load_legacy_encrypted_mapping(self) -> bool:
        if Fernet is None or not self.key_file.exists():
            return False

        try:
            fernet = Fernet(self.key_file.read_bytes())
            payload = fernet.decrypt(self.map_file.read_bytes())
            self._set_mapping(json.loads(payload.decode("utf-8")))
            return True
        except (InvalidToken, OSError, ValueError, json.JSONDecodeError):
            return False

    def _save_mapping(self):
        # Charger le mapping existant depuis le fichier
        existing = {}
        if self.map_file.exists():
            try:
                with open(self.map_file, 'r', encoding='utf-8') as f:
                    existing = json.load(f)
            except Exception:
                existing = {}
        # Fusionner : les nouvelles entrées écrasent les anciennes si même token
        merged = {**existing, **self.mapping}
        # Ne sauvegarder que si le mapping n'est pas vide
        if merged:
            self.map_file.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(merged, sort_keys=True, indent=2)
            self.map_file.write_text(payload, encoding='utf-8')
        else:
            log("Skipping saving empty mapping.", "WARN")

    def _set_mapping(self, mapping):
        if not isinstance(mapping, dict):
            self.mapping = {}
            self.reverse_mapping = {}
            return

        cleaned = {}
        reverse = {}
        for token, value in mapping.items():
            if not isinstance(token, str) or not isinstance(value, str):
                continue
            if not self.TOKEN_PATTERN.fullmatch(token):
                continue
            # Ne plus bloquer aucune catégorie
            # if self._is_blocked_mapping_token(token):
            #     continue
            if self._looks_like_token_artifact(value):
                continue
            if not self._is_valid_mapping_value(token, value):
                continue
            if value in reverse:
                continue
            cleaned[token] = value
            reverse[value] = token

        self.mapping = cleaned
        self.reverse_mapping = reverse

    def _sync_counters(self):
        self.counters.clear()
        for token in self.mapping:
            match = self.TOKEN_PATTERN.fullmatch(token)
            if match:
                category, index = match.groups()
                self.counters[category] = max(self.counters[category], int(index))

    def _looks_like_json(self, text: str) -> bool:
        return bool(self.JSON_START_PATTERN.match(text))

    def _sanitize_json(self, text: str) -> str:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return self._pipeline(text)

        sanitized = self._walk_json(parsed)
        return json.dumps(sanitized)

    def _walk_json(self, value, parent_key=None):
        if isinstance(value, dict):
            return {key: self._walk_json(item, key) for key, item in value.items()}
        if isinstance(value, list):
            return [self._walk_json(item, parent_key) for item in value]
        if isinstance(value, str):
            category = self._category_for_key(parent_key)
            if category and not self.TOKEN_PATTERN.fullmatch(value):
                return self._ensure_token(category, value)
            return self._pipeline(value)
        return value

    def _pipeline(self, text: str) -> str:
        text = self._apply_authorization_bearer_pass(text)
        text = self._apply_aws_pass(text)
        text = self._apply_sql_connection_pass(text)
        text = self._apply_kubernetes_pass(text)
        text = self._apply_ipv6_pass(text)
        text = self._apply_regex_pass(text)
        text = self._apply_context_pass(text)
        text = self._apply_smb_share_pass(text)
        text = self._apply_entropy_pass(text)
        text = self._apply_llm_fallback(text)
        return text

    @staticmethod
    def _is_valid_base64(value: str) -> bool:
        try:
            if len(value) % 4 != 0:
                return False
            base64.b64decode(value, validate=True)
            return True
        except (BinasciiError, ValueError):
            return False

    def _apply_regex_pass(self, text: str) -> str:
        spans = []
        for category, pattern in self.REGEX_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(0)
                if self.TOKEN_PATTERN.fullmatch(value):
                    continue
                if category == "BASE64_SECRET":
                    if not self._is_plausible_base64_secret(value):
                        continue
                spans.append((match.start(), match.end(), value, self._ensure_token(category, value)))
        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    @staticmethod
    def _overlaps_any_span(start: int, end: int, spans) -> bool:
        return any(start < span_end and end > span_start for span_start, span_end in spans)

    def _apply_context_pass(self, text: str) -> str:
        spans = []
        for category, pattern in self.CONTEXT_PATTERNS.items():
            for match in pattern.finditer(text):
                raw_value = match.group(1)
                value = raw_value.strip()
                if not value.endswith("..."):
                    value = value.rstrip(".,")
                token_candidate = value.rstrip("=")
                if (
                    not value
                    or self.TOKEN_PATTERN.fullmatch(value)
                    or self.TOKEN_PATTERN.fullmatch(token_candidate)
                ):
                    continue
                start = match.start(1)
                end = start + len(value)
                spans.append((start, end, value, self._ensure_token(category, value)))
        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def _apply_aws_pass(self, text: str) -> str:
        spans = []
        for match in self.AWS_S3_BUCKET_PATTERN.finditer(text):
            bucket = match.group("bucket")
            if self.TOKEN_PATTERN.fullmatch(bucket):
                continue
            spans.append(
                (match.start("bucket"), match.end("bucket"), bucket, self._ensure_token("S3_BUCKET", bucket))
            )

        for match in self.AWS_IAM_USER_PATTERN.finditer(text):
            account = match.group("account")
            user = match.group("user")
            if not self.TOKEN_PATTERN.fullmatch(account):
                spans.append(
                    (
                        match.start("account"),
                        match.end("account"),
                        account,
                        self._ensure_token("AWS_ACCOUNT", account),
                    )
                )
            if not self.TOKEN_PATTERN.fullmatch(user):
                spans.append(
                    (
                        match.start("user"),
                        match.end("user"),
                        user,
                        self._ensure_token("USER", user),
                    )
                )

        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def _apply_kubernetes_pass(self, text: str) -> str:
        spans = []
        for category, pattern in {"K8S_NAMESPACE": self.CONTEXT_PATTERNS["K8S_NAMESPACE"], "K8S_POD": self.CONTEXT_PATTERNS["K8S_POD"]}.items():
            for match in pattern.finditer(text):
                value = match.group(1).strip()
                if not value or self.TOKEN_PATTERN.fullmatch(value):
                    continue
                spans.append((match.start(1), match.end(1), value, self._ensure_token(category, value)))
        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def _apply_ipv6_pass(self, text: str) -> str:
        spans = []
        candidate_pattern = re.compile(r"(?<![\w])(?:[0-9A-Fa-f:]{2,})(?![\w])")

        for match in candidate_pattern.finditer(text):
            value = match.group(0)
            if value.count(":") < 2:
                continue
            if not re.search(r"[0-9A-Fa-f]", value):
                continue
            try:
                ipaddress.IPv6Address(value)
            except ValueError:
                continue
            if self.TOKEN_PATTERN.fullmatch(value):
                continue
            spans.append((match.start(), match.end(), value, self._ensure_token("IPV6", value)))

        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def _apply_sql_connection_pass(self, text: str) -> str:
        spans = []
        category_by_field = {
            "server": "HOST",
            "database": "DB",
            "user id": "USER",
            "password": "PASSWORD",
        }

        for match in self.SQL_CONN_PATTERN.finditer(text):
            field = match.group("field").lower()
            value = match.group("value").strip()
            if not value or self.TOKEN_PATTERN.fullmatch(value):
                continue
            category = category_by_field.get(field)
            if not category:
                continue
            start = match.start("value")
            end = match.end("value")
            spans.append((start, end, value, self._ensure_token(category, value)))

        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def _apply_authorization_bearer_pass(self, text: str) -> str:
        spans = []
        for match in self.AUTHORIZATION_BEARER_PATTERN.finditer(text):
            token = match.group("token").strip()
            if not token or self.TOKEN_PATTERN.fullmatch(token):
                continue
            replacement = f"{match.group('prefix')}{self._ensure_token('JWT', token)}{match.group('suffix')}"
            spans.append((match.start(), match.end(), match.group(0), replacement))

        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def _apply_smb_share_pass(self, text: str) -> str:
        spans = []
        in_share_table = False
        offset = 0

        for line in text.splitlines(keepends=True):
            line_body = line.rstrip("\r\n")

            if self.SMB_SHARE_HEADER_PATTERN.match(line_body):
                in_share_table = True
                offset += len(line)
                continue

            if in_share_table:
                stripped = line_body.strip()
                if not stripped:
                    in_share_table = False
                elif set(stripped) <= {"-", " "}:
                    pass
                else:
                    match = self.SMB_SHARE_ROW_PATTERN.match(line_body)
                    if match:
                        share = match.group("share")
                        if not self.TOKEN_PATTERN.fullmatch(share):
                            start = offset + match.start("share")
                            end = offset + match.start("type")
                            token = self._ensure_token("SHARE", share)
                            cell_width = match.start("type") - match.start("share")
                            replacement = token + (" " * max(1, cell_width - len(token)))
                            spans.append(
                                (start, end, share, replacement)
                            )
                    else:
                        in_share_table = False

            offset += len(line)

        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def _apply_entropy_pass(self, text: str) -> str:
        spans = []
        for match in self.WORD_PATTERN.finditer(text):
            value = match.group(0)
            if self.TOKEN_PATTERN.fullmatch(value):
                continue
            if "<" in value or ">" in value:
                continue
            if "=" in value and not value.endswith("="):
                continue
            if value.startswith("http://") or value.startswith("https://"):
                continue
            if re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", value):
                continue
            if any(tld in value for tld in [".com", ".org", ".net", ".io"]):
                continue
            if "/" in value and "." in value:
                continue
            if any(x in value.lower() for x in [" or ", "'=", "--", " union ", "select "]):
                continue
            if self._shannon_entropy(value) > 4.0:
                spans.append((match.start(), match.end(), value, self._ensure_token("SECRET", value)))
        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def _apply_llm_fallback(self, text: str) -> str:
        if self.llm_client is None:
            return text

        masked_text = self.TOKEN_PATTERN.sub("[TOKEN]", text)
        prompt = (
            "Identify only the sensitive VALUES in the text below.\n"
            "Return ONLY a JSON array of exact substrings copied from the text.\n"
            "Do not return generic domains, documentation links, public URLs, field names, labels, or words such as password, token, user, login, host, server, or admin.\n"
            "Only return a URL if the URL itself is clearly sensitive or required to execute the command safely.\n"
            "Return the secret value itself, not the surrounding sentence.\n"
            "If a secret is written in an obfuscated human-readable way, return the exact visible substring.\n"
            "If none exist, return [].\n\n"
            "Examples:\n"
            'TEXT: "password is swordfish"\n'
            'OUTPUT: ["swordfish"]\n'
            'TEXT: "token is tulip-red"\n'
            'OUTPUT: ["tulip-red"]\n'
            'TEXT: "login bob and passphrase BlueRiver9"\n'
            'OUTPUT: ["bob", "BlueRiver9"]\n'
            'TEXT: "Contact the admin at alice [at] corp dot internal."\n'
            'OUTPUT: ["alice [at] corp dot internal"]\n'
            'TEXT: "password token user admin"\n'
            "OUTPUT: []\n\n"
            f"TEXT:\n{masked_text}"
        )

        try:
            response = self.llm_client(prompt)
            items = json.loads(response)
        except Exception:
            return text

        if not isinstance(items, list):
            return text

        spans = []
        for item in items:
            if not self._is_valid_llm_candidate(item, text):
                continue
            token = self._ensure_token(self._category_for_llm_value(item), item)
            for match in re.finditer(re.escape(item), text):
                spans.append((match.start(), match.end(), item, token))

        return self._apply_spans(text, self._deduplicate_overlaps(spans))

    def _category_for_llm_value(self, value: str) -> str:
        if self.URL_PATTERN.fullmatch(value.strip()):
            return "URL"
        return "SECRET"

    def _is_valid_llm_candidate(self, item: str, source_text: str) -> bool:
        if not isinstance(item, str):
            return False

        value = item.strip()
        if not value:
            return False
        if self.TOKEN_PATTERN.fullmatch(value):
            return False
        if value.lower() in self.LLM_EXCLUDED_VALUES:
            return False
        if value not in source_text:
            return False
        if len(value) == 1:
            return False
        return True

    @staticmethod
    def _is_blocked_mapping_token(token: str) -> bool:
        return False

    @staticmethod
    def _is_valid_mapping_value(token: str, value: str) -> bool:
        category = SensitiveDataAnonymizer.TOKEN_PATTERN.fullmatch(token).group(1)
        if category == "BASE64_SECRET":
            return SensitiveDataAnonymizer._is_plausible_base64_secret(value)
        return True

    @staticmethod
    def _is_plausible_base64_secret(value: str) -> bool:
        if len(value) < 24:
            return False
        if len(value) % 4 != 0:
            return False
        if any(ch.isspace() for ch in value):
            return False
        if not re.search(r"[0-9+/=_-]", value) and len(value) < 48:
            return False
        if "/" in value and not re.search(r"[0-9+_= -]", value):
            return False
        try:
            decoded = base64.b64decode(value, validate=True)
        except (BinasciiError, ValueError):
            return False

        if len(decoded) < 16:
            return False

        try:
            decoded_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return True

        lowered = decoded_text.strip().lower()
        if not lowered:
            return False
        if any(marker in lowered for marker in ("<svg", "<html", "<script", "<!doctype", "<?xml", "document.", "window.", "function ", "class ")):
            return False
        if re.search(r"[{}<>]", decoded_text):
            return False
        if re.search(r"\b(?:platform|orchestrate|document|window|function|script|image|assets|static)\b", lowered):
            return False
        if sum(ch.isalpha() for ch in decoded_text) / max(len(decoded_text), 1) > 0.75 and any(ch.isspace() for ch in decoded_text):
            return False
        return True

    @staticmethod
    def _looks_like_token_artifact(value: str) -> bool:
        if SensitiveDataAnonymizer.TOKEN_PATTERN.search(value):
            return True
        if re.fullmatch(r"[A-Z][A-Z0-9_]*_\d{3}", value):
            return True
        return False

    def _has_remaining_candidates(self, text: str) -> bool:
        for pattern in [self.AWS_S3_BUCKET_PATTERN, self.AWS_IAM_USER_PATTERN]:
            if pattern.search(text):
                return True
        for pattern in self.REGEX_PATTERNS.values():
            if pattern.search(text):
                return True
        for pattern in self.CONTEXT_PATTERNS.values():
            if pattern.search(text):
                return True
        for match in self.WORD_PATTERN.finditer(text):
            if self._shannon_entropy(match.group(0)) > 4.0:
                return True
        return False

    def _ensure_token(self, category: str, value: str) -> str:
        existing = self.reverse_mapping.get(value)
        if existing:
            return existing

        self.counters[category] += 1
        token = f"<{category}_{self.counters[category]:03d}>"
        self.mapping[token] = value
        self.reverse_mapping[value] = token
        log(f"Added mapping: {token} -> {value[:50]}...", "DEBUG")
        return token

    def _deduplicate_overlaps(self, spans):
        ordered = sorted(
            spans,
            key=lambda item: (item[0], -(item[1] - item[0]), item[3]),
        )
        accepted = []
        occupied_until = -1

        for start, end, original, replacement in ordered:
            if start < occupied_until:
                continue
            accepted.append((start, end, original, replacement))
            occupied_until = end

        return accepted

    def _apply_spans(self, text: str, spans) -> str:
        if not spans:
            return text

        pieces = []
        cursor = len(text)
        for start, end, original, replacement in sorted(spans, key=lambda item: item[0], reverse=True):
            if end > cursor:
                continue
            pieces.append(text[end:cursor])
            pieces.append(replacement)
            self.audit_log.append((original, replacement))
            cursor = start
        pieces.append(text[:cursor])
        pieces.reverse()
        return "".join(pieces)

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        length = len(value)
        counts = Counter(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def _category_for_key(key):
        if not isinstance(key, str):
            return None

        normalized = key.lower()
        if normalized in {"username", "user", "login", "password", "passwd", "pass", "pwd"}:
            return "CRED"
        if normalized == "server":
            return "HOST"
        if normalized == "database":
            return "DB"
        if normalized in {"user id", "userid"}:
            return "USER"
        if normalized in {"mail", "email"}:
            return "EMAIL"
        if normalized == "apikey":
            return "API_KEY"
        if normalized == "api_key":
            return "API_KEY"
        if normalized == "namespace":
            return "K8S_NAMESPACE"
        if normalized == "pod":
            return "K8S_POD"
        if normalized == "cn":
            return "PERSON"
        if normalized == "uid":
            return "USER"
        if normalized in {
            "token",
            "secret",
            "apikey",
            "api_key",
            "access_token",
            "refresh_token",
            "authorization",
            "cookie",
            "session",
            "sessionid",
        }:
            return "SECRET"
        return None

