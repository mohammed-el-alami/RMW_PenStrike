#!/usr/bin/env python3
"""
report_enrich.py — Enrichissement automatique du rapport de pentest.

Pour chaque vulnérabilité du rapport (.md), ce module :
  1. extrait le CWE et la sévérité,
  2. interroge l'API publique NVD pour récupérer des CVE réels liés au CWE,
  3. construit des liens de recherche de PoC (ExploitDB, GitHub, Metasploit),
     et tente une recherche live GitHub si le réseau est disponible.

Mode HYBRIDE : si le réseau est disponible -> enrichissement live ;
sinon -> on ignore proprement (timeouts courts, jamais d'exception bloquante)
et on retombe sur les liens de recherche pré-construits.

Aucune dépendance externe obligatoire : utilise urllib de la stdlib.
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request

# ── Réglages réseau ──────────────────────────────────────────────────────────
NET_TIMEOUT_S      = 6      # timeout court par requête
NVD_MAX_CVES       = 3      # nb de CVE à afficher par finding
GITHUB_MAX_POCS    = 3      # nb de dépôts PoC à afficher par finding
ENRICH_ENABLED     = True   # passer à False pour désactiver tout réseau

NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API = "https://api.github.com/search/repositories"

_USER_AGENT = "RMW-PenStrike-Report/1.0"


# ── Détection réseau (hybride) ────────────────────────────────────────────────
_NET_OK: bool | None = None


def _network_available() -> bool:
    """Teste une seule fois si le réseau/NVD est joignable."""
    global _NET_OK
    if _NET_OK is not None:
        return _NET_OK
    if not ENRICH_ENABLED:
        _NET_OK = False
        return False
    try:
        req = urllib.request.Request(
            NVD_API + "?resultsPerPage=1",
            headers={"User-Agent": _USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=NET_TIMEOUT_S) as resp:
            _NET_OK = resp.status == 200
    except Exception:
        _NET_OK = False
    return _NET_OK


def _http_get_json(url: str) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(req, timeout=NET_TIMEOUT_S) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


# ── Parsing du rapport .md ────────────────────────────────────────────────────
def parse_findings(md_text: str) -> list[dict]:
    """
    Extrait la liste des findings depuis le rapport Markdown.
    Retourne une liste de dicts : {ref, title, severity, cwe, affects, remediation}.
    """
    findings: list[dict] = []

    # Découpe en sous-sections "### x.y Titre — SEVERITY"
    blocks = re.split(r"\n(?=###\s+\d+\.\d+\s)", md_text)
    for block in blocks:
        head = re.match(
            r"###\s+(\d+\.\d+)\s+(.+?)\s*[—\-]\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)",
            block, re.IGNORECASE,
        )
        if not head:
            continue

        title    = head.group(2).strip()
        severity = head.group(3).upper()

        ref_m = re.search(r"\*\*Ref ID:\*\*\s*([A-Za-z0-9\-]+)", block)
        ref   = ref_m.group(1).strip() if ref_m else "—"

        cwe_m = (re.search(r"cwe\.mitre\.org/data/definitions/(\d{1,5})", block, re.IGNORECASE)
                 or re.search(r"CWE[-\s]?(\d{1,5})", block, re.IGNORECASE))
        cwe   = f"CWE-{cwe_m.group(1)}" if cwe_m else None

        aff_m = re.search(r"\|\s*Affects\s*\|\s*(.+?)\s*\|", block, re.IGNORECASE)
        affects = aff_m.group(1).strip() if aff_m else "—"

        rem_m = re.search(
            r"\*\*Remediation Guidance\*\*\s*\n+(.+?)(?=\n###|\n##|\Z)",
            block, re.DOTALL | re.IGNORECASE,
        )
        remediation = ""
        if rem_m:
            remediation = " ".join(rem_m.group(1).split())[:400]

        findings.append({
            "ref": ref, "title": title, "severity": severity,
            "cwe": cwe, "affects": affects, "remediation": remediation,
        })

    return findings


# ── Enrichissement CVE (NVD) ──────────────────────────────────────────────────
def fetch_cves_for_cwe(cwe: str) -> list[dict]:
    """Récupère quelques CVE réels associés à un CWE via l'API NVD."""
    if not cwe or not _network_available():
        return []
    url = f"{NVD_API}?cweId={urllib.parse.quote(cwe)}&resultsPerPage={NVD_MAX_CVES}"
    data = _http_get_json(url)
    if not data:
        return []

    cves = []
    for item in data.get("vulnerabilities", [])[:NVD_MAX_CVES]:
        c = item.get("cve", {})
        cid = c.get("id", "")
        if not cid:
            continue
        # Description anglaise
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        # Score CVSS (v3.1 -> v3.0 -> v2)
        score = None
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                try:
                    score = metrics[key][0]["cvssData"]["baseScore"]
                    break
                except Exception:
                    pass
        cves.append({
            "id": cid,
            "score": score,
            "desc": (desc[:160] + "…") if len(desc) > 160 else desc,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
        })
    return cves


# ── Recherche de PoC (ExploitDB / GitHub / Metasploit) ────────────────────────
def build_poc_search_links(finding: dict) -> dict:
    """Construit les liens de recherche de PoC (toujours disponibles, hors-ligne)."""
    q_title = urllib.parse.quote(finding["title"])
    q_cwe   = urllib.parse.quote(finding["cwe"] or finding["title"])
    return {
        "exploitdb": f"https://www.exploit-db.com/search?q={q_title}",
        "github":    f"https://github.com/search?q={q_title}+poc&type=repositories",
        "metasploit":f"https://www.rapid7.com/db/?q={q_title}&type=metasploit",
    }


def fetch_github_pocs(finding: dict) -> list[dict]:
    """Recherche live de dépôts GitHub PoC (si réseau dispo)."""
    if not _network_available():
        return []
    # Requête : titre de la vuln + 'poc' / 'exploit'
    term = finding["cwe"] or finding["title"]
    query = urllib.parse.quote(f"{term} poc exploit")
    url = f"{GITHUB_API}?q={query}&sort=stars&order=desc&per_page={GITHUB_MAX_POCS}"
    data = _http_get_json(url)
    if not data:
        return []
    pocs = []
    for repo in data.get("items", [])[:GITHUB_MAX_POCS]:
        pocs.append({
            "name":  repo.get("full_name", ""),
            "stars": repo.get("stargazers_count", 0),
            "url":   repo.get("html_url", ""),
            "desc":  (repo.get("description") or "")[:120],
        })
    return pocs


# ── Pipeline d'enrichissement ─────────────────────────────────────────────────
def enrich_findings(findings: list[dict]) -> list[dict]:
    """Ajoute à chaque finding : cves[], poc_links{}, github_pocs[]."""
    online = _network_available()
    for f in findings:
        f["poc_links"]  = build_poc_search_links(f)
        f["cves"]       = fetch_cves_for_cwe(f["cwe"]) if online else []
        f["github_pocs"]= fetch_github_pocs(f)         if online else []
    return findings


def get_enrichment(md_text: str) -> dict:
    """
    Point d'entrée principal pour report_to_pdf.py.
    Retourne :
      {
        "online": bool,
        "findings": [ {ref,title,severity,cwe,affects,remediation,
                       cves[],poc_links{},github_pocs[]}, ... ]
      }
    """
    findings = parse_findings(md_text)
    enriched = enrich_findings(findings)
    return {"online": _network_available(), "findings": enriched}


# Priorité de remediation dérivée de la sévérité (pour le roadmap)
REMEDIATION_PRIORITY = {
    "CRITICAL": ("P1", "Immediate", "< 48h"),
    "HIGH":     ("P2", "Urgent",    "< 1 week"),
    "MEDIUM":   ("P3", "Planned",   "< 1 month"),
    "LOW":      ("P4", "Routine",   "Next cycle"),
    "INFO":     ("P5", "Optional",  "Best effort"),
}


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if not path:
        print("Usage: python3 report_enrich.py RAPPORT_PENTEST_xxx.md")
        sys.exit(1)
    with open(path, encoding="utf-8") as fh:
        txt = fh.read()
    result = get_enrichment(txt)
    print(f"Network online : {result['online']}")
    for f in result["findings"]:
        print(f"\n[{f['severity']}] {f['ref']} — {f['title']}  ({f['cwe']})")
        for c in f["cves"]:
            print(f"   CVE {c['id']} (score {c['score']}) {c['url']}")
        for p in f["github_pocs"]:
            print(f"   PoC ★{p['stars']} {p['name']} {p['url']}")
