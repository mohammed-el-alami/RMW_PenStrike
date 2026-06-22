#!/usr/bin/env python3
"""Génération du rapport de pentest.

Toute la logique de production du rapport est isolée dans ce module afin de
ne pas alourdir main.py. main.py ne fait qu'importer `generate_pentest_report`
et l'appeler aux bons endroits.

Le rapport est produit par le MÊME LLM déjà sélectionné (via call_llm), à partir
des contextes d'investigation. Les données sensibles (cible réelle, tokens,
mots de passe…) sont remplacées par des placeholders AVANT l'envoi au LLM,
et le prompt force le LLM à conserver ces placeholders. Le remplacement final
($TARGET -> IP réelle, $PASSWORD -> vrai mdp) est fait manuellement ensuite.
"""
from __future__ import annotations

import json
import re
import time

import config
from llm_client import call_llm
from logger import log
from storage import (
    context_name_from_path,
    get_all_context_files,
    get_finished_context_files,
    is_finished,
    read_file,
    write_file,
)

REPORT_LANGUAGE          = "English"
REPORT_MAX_FINDINGS_CHARS = 16000
REPORT_MAX_TOKENS        = 8000
REPORT_FILENAME_PREFIX   = "RAPPORT_PENTEST"

REPORT_TARGET_PLACEHOLDER   = "$TARGET"  # gardé pour compatibilité mais plus utilisé
REPORT_TOKEN_PLACEHOLDER    = "$TOKEN"
REPORT_PASSWORD_PLACEHOLDER = "$PASSWORD"

_REPORT_GENERATED = False


# ── Collecte & sanitisation ──────────────────────────────────────────────────

def _collect_findings() -> str:
    parts: list[str] = []
    finished = get_finished_context_files()
    active   = [p for p in get_all_context_files() if p not in finished]
    for path in finished + active:
        try:
            content = read_file(path).strip()
        except Exception:
            continue
        if not content:
            continue
        status = "FINISHED" if is_finished(path) else "IN-PROGRESS"
        name   = context_name_from_path(path)
        parts.append(f"===== CONTEXT [{name}] ({status}) =====\n{content}")
    return "\n\n".join(parts).strip()


def _sanitize_findings(findings: str) -> str:
    app_config = config.APP_CONFIG
    sanitized  = findings

    # On ne modifie plus les placeholders ici pour ne pas introduire de
    # confusion. Le LLM doit utiliser les placeholders <CAT_###> déjà présents.
    # On supprime donc la substitution par $TARGET, etc. On garde juste
    # la troncature éventuelle.

    if len(sanitized) > REPORT_MAX_FINDINGS_CHARS:
        sanitized = (
            sanitized[:REPORT_MAX_FINDINGS_CHARS]
            + "\n\n... [FINDINGS TRUNCATED FOR REPORT GENERATION] ..."
        )
    return sanitized


# ── Prompt ───────────────────────────────────────────────────────────────────

def build_pentest_report_prompt(findings: str) -> list:
    system = (
        "You are a senior cybersecurity consultant who writes formal, client-ready "
        "penetration testing reports. You produce a single, well-structured report in "
        f"{REPORT_LANGUAGE}, in clean GitHub-flavoured Markdown, with no preamble and no "
        "code-fences wrapping the whole document.\n\n"
        "CRITICAL PLACEHOLDER RULE: The raw investigation data below contains placeholder "
        "tokens like <IP_001>, <URL_001>, <DOMAIN_001>, <BASE64_SECRET_004>, etc. "
        "You MUST copy these tokens EXACTLY as they appear — do not change them, "
        "do not renumber them, and do not invent new ones. Use them verbatim in the report. "
        "If you need to refer to a sensitive value that does not have a placeholder, "
        "create a new one using the same format <CATEGORY_###> (e.g., <URL_002>, <IP_005>). "
        "You must NEVER use dollar-sign placeholders like $TARGET, $TOKEN, or $PASSWORD "
        "because those cannot be mapped to real values. The report will be automatically "
        "processed to replace only the <CATEGORY_###> placeholders with actual data.\n\n"
        "Do not include any real sensitive values in the report. Use only placeholders "
        "from the input or new ones you create in the <CATEGORY_###> format."
    )

    user = f"""Write a complete PENETRATION TESTING REPORT from the raw investigation data below.
Follow EXACTLY this structure (every section is mandatory):

---

# Penetration Testing Report

**Date:** <today>
**Prepared by:** RMW-PenStrike
**Classification:** Client Confidential

---

## Document Control

### Client Confidentiality
This document contains Client Confidential information and may not be copied without written permission.

### Document Version Control

| Issue No. | Issue Date | Issued By | Change Description |
|---|---|---|---|
| 0.1 | <date> | RMW-PenStrike | Draft for internal review |
| 1.0 | <date> | RMW-PenStrike | Released to client |

---

## Table of Contents

Produce a numbered TOC listing EVERY section and sub-section that appears in this report,
with the EXACT titles you will use below. Format each line as:
  <number> <Section Title> .......................... <page hint>
Example:
  1. Executive Summary ................................ 3
  1.1 Assessment Summary .............................. 3
  1.2 Strategic Recommendations ....................... 4
  2. Technical Summary ................................ 5
  ...and so on for every section.

---

## Executive Summary

Write a professional non-technical paragraph (4-6 sentences) describing the engagement:
who commissioned it, what the target is (use its placeholder, e.g. <URL_001>), what the purpose was, and what the
overall outcome is.

### Assessment Summary

State the overall risk level in bold (e.g. **CRITICAL**) and explain the business impact
in 2-3 sentences.

Provide this severity breakdown table (count each finding you will document below):

| Phase | Description | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|---|
| 1 | Web/API Penetration Testing | <n> | <n> | <n> | <n> | <total> |
| | **Total** | <n> | <n> | <n> | <n> | <total> |

### Strategic Recommendations

Provide 4-6 concrete, prioritised bullet points — one per major finding category.
Start each with the severity in brackets, e.g. **[CRITICAL]** Fix XSS on search endpoint.

---

## 1. Technical Summary

### 1.1 Scope

List the in-scope target(s). Use the appropriate placeholders (e.g. <URL_001>, <IP_001>) for every real host/IP/URL.

### 1.2 Post Assessment Clean-up

State that any test accounts or artefacts created during the assessment should be
disabled or removed.

### 1.3 Risk Ratings

| # | Risk Rating | CVSSv3 Score | Description |
|---|---|---|---|
| 1 | CRITICAL | 9.0 - 10 | Requires resolution as quickly as possible. |
| 2 | HIGH | 7.0 - 8.9 | Requires resolution in a short term. |
| 3 | MEDIUM | 4.0 - 6.9 | Should be resolved throughout ongoing maintenance. |
| 4 | LOW | 1.0 - 3.9 | Should be addressed as part of routine maintenance. |
| 5 | INFO | 0 - 0.9 | Reported for information only. |

### 1.4 Findings Overview

| Ref | Description | Risk |
|---|---|---|
(one row per finding using IDs PT-1-1, PT-1-2, … in order of severity)

---

## 2. Technical Details

For EACH vulnerability found in the data, write a sub-section:

### 2.X <Vulnerability Title> — <SEVERITY>

**Ref ID:** PT-1-X

<One paragraph: what was found, how it works, and why it matters.>

**Vulnerability Details**

| Field | Value |
|---|---|
| Affects | <URL_001>/path |
| Parameter(s) | ... |
| Attack Vectors | ... |
| References | https://cwe.mitre.org/data/definitions/NNN.html |

**Evidence**
<Most relevant HTTP request/response or command output — use exact placeholders from the raw data>


**Remediation Guidance**

<Concrete, actionable steps to fix the issue.>

---

## 3. Appendices

### 3.1 Penetration Testing Methodology

State that the assessment follows the OWASP Testing Guide v4, covers OWASP Top 10, and
was structured in four phases: Reconnaissance → Enumeration → Exploitation → Reporting.
Add the OWASP Top 10 table (A1-A10) with a one-sentence description for each.

---

STRICT RULES:
- Every section above is MANDATORY even if data is thin — write "No evidence found" conservatively.
- The Table of Contents MUST list every ## and ### heading that appears in the document.
- Count findings accurately in the Assessment Summary table.
- EVERY finding MUST include a CWE reference as a full URL in the form
  https://cwe.mitre.org/data/definitions/NNN.html (this is required for automatic
  CVE/exploit enrichment of the report — never omit it).
- EVERY finding MUST include a concrete, actionable "Remediation Guidance" paragraph.
- Use EXACTLY the placeholder tokens that appear in the raw data (e.g., <IP_001>, <URL_001>, <BASE64_SECRET_004>).
  Do not invent new placeholders unless absolutely necessary, and if you do, use the same <CATEGORY_###> format.
- NEVER use $TARGET, $TOKEN, $PASSWORD, or any other dollar-sign placeholders.
- Output ONLY the Markdown — no introductory sentence, no trailing comment.

== RAW INVESTIGATION DATA ==
{findings}
"""
    return [
        {"role": "system", "content": system},
        {"role": "user",   "content": user},
    ]


# ── Post-traitement : normalisation des placeholders ─────────────────────────

def _normalize_placeholders(report_md: str) -> str:
    """
    Tente de remplacer les placeholders inventés par le LLM par ceux du mapping
    original si une correspondance approximative peut être faite.
    Corrige également les éventuels $TARGET, $TOKEN, $PASSWORD en utilisant
    le premier placeholder de la catégorie correspondante trouvé dans le mapping,
    ou les remplace par <URL_001> par défaut.
    """
    # On récupère le mapping existant depuis le fichier (si disponible)
    mapping_file = config.APP_CONFIG.base_dir / "mapping.txt"
    mapping = {}
    if mapping_file.exists():
        try:
            with open(mapping_file, 'r', encoding='utf-8') as f:
                mapping = json.load(f)
        except Exception:
            pass

    # Remplacer les $TARGET, $TOKEN, $PASSWORD par des placeholders <CAT_###>
    dollar_patterns = {
        r'\$TARGET\b': '<URL_001>',
        r'\$TOKEN\b': '<TOKEN_001>',
        r'\$PASSWORD\b': '<PASSWORD_001>',
        r'\$EMAIL\b': '<EMAIL_001>',
    }
    for pattern, replacement in dollar_patterns.items():
        report_md = re.sub(pattern, replacement, report_md)

    # Si le mapping existe, essayer de trouver de meilleures correspondances
    if mapping:
        # Extraire tous les placeholders du rapport (type <CAT_###>)
        report_tokens = set(re.findall(r'<([A-Z_]+)_(\d{3})>', report_md))
        # Tokens du mapping
        mapping_tokens = set()
        for token in mapping.keys():
            m = re.match(r'<([A-Z_]+)_(\d{3})>', token)
            if m:
                mapping_tokens.add((m.group(1), int(m.group(2))))

        # Pour chaque token du rapport qui n'est pas dans le mapping, essayer de le remplacer
        # par un token du mapping de même catégorie, en prenant le plus proche
        for cat, num in report_tokens:
            token = f"<{cat}_{num}>"
            if token in mapping:
                continue  # déjà présent
            # Chercher un token de même catégorie dans le mapping
            candidates = [t for t in mapping_tokens if t[0] == cat]
            if candidates:
                # Prendre celui avec le numéro le plus proche
                candidates_sorted = sorted(candidates, key=lambda x: abs(x[1] - int(num)))
                best_cat, best_num = candidates_sorted[0]
                best_token = f"<{best_cat}_{best_num:03d}>"
                report_md = report_md.replace(token, best_token)

    return report_md


# ── Point d'entrée public ────────────────────────────────────────────────────

def generate_pentest_report() -> str | None:
    """Génère le rapport via le LLM et l'écrit dans base_dir.
    Idempotent : un second appel retourne None sans régénérer."""
    global _REPORT_GENERATED
    if _REPORT_GENERATED:
        return None
    try:
        findings = _collect_findings()
        if not findings:
            log("Aucun finding à rapporter — génération du rapport ignorée.", "WARN")
            return None

        log("Génération du rapport de pentest via le LLM...", "MAIN")
        safe_findings = _sanitize_findings(findings)
        messages      = build_pentest_report_prompt(safe_findings)

        report_md = call_llm(messages, max_tokens=REPORT_MAX_TOKENS, source="report")
        if not report_md or not report_md.strip():
            log("Le LLM a renvoyé un rapport vide.", "ERR")
            return None

        # Post-traitement : normalisation des placeholders
        report_md = _normalize_placeholders(report_md)

        timestamp   = time.strftime("%Y%m%d_%H%M%S")
        report_path = config.APP_CONFIG.base_dir / f"{REPORT_FILENAME_PREFIX}_{timestamp}.md"
        write_file(report_path, report_md.strip() + "\n")
        _REPORT_GENERATED = True
        log(f"Rapport de pentest écrit : {report_path}", "MAIN")
        return str(report_path)
    except Exception as e:
        log(f"Erreur lors de la génération du rapport : {e}", "ERR")
        return None
