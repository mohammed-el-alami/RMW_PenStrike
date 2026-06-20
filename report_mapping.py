#!/usr/bin/env python3
"""
report_mapping.py — Réinjection des valeurs réelles dans le rapport.

Concept de sécurité du projet :
  1. report_generator.py produit un rapport .md ANONYMISÉ : toutes les données
     sensibles y figurent sous forme de CLÉS (placeholders), p.ex. <IP_001>,
     <SECRET_001>, <HASH_001>, <BASE64_SECRET_008>, $TARGET, $TOKEN, ...
  2. Un fichier de MAPPING (fourni séparément) associe chaque clé à sa vraie
     valeur :  { "<IP_001>": "1.2.1.1", "<SECRET_001>": "cache-...", ... }
  3. report_to_pdf.py charge ce mapping juste avant le rendu et remplace les
     clés par les valeurs réelles -> le PDF final contient les vraies données.

Le .md reste anonymisé sur le disque ; seule la conversion en PDF (locale,
contrôlée) ré-injecte les secrets. C'est ce qui garantit que les valeurs
réelles ne transitent jamais par le LLM ni ne sont stockées en clair dans
le rapport Markdown.

Formats de mapping acceptés :
  - JSON  : { "<IP_001>": "1.2.1.1", ... }          (format de référence)
  - KV    : <IP_001>=1.2.1.1     ou    <IP_001> : 1.2.1.1   (une paire/ligne)
"""
from __future__ import annotations

import json
import re
from pathlib import Path


def load_mapping(path: str | Path) -> dict[str, str]:
    """
    Charge un fichier de mapping clé -> valeur réelle.
    Tente d'abord du JSON, puis retombe sur un parsing clé=valeur ligne à ligne.
    Retourne un dict {clé: valeur}. Lève FileNotFoundError si le fichier manque.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Fichier de mapping introuvable : {p}")

    text = p.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return {}

    # 1) JSON (format de référence du mapping.txt)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass

    # 2) Fallback : lignes "clé=valeur" ou "clé : valeur"
    mapping: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^\s*"?(.+?)"?\s*[:=]\s*"?(.*?)"?\s*$', line)
        if m:
            key, val = m.group(1).strip(), m.group(2)
            if key:
                mapping[key] = val
    return mapping


def apply_mapping(text: str, mapping: dict[str, str]) -> tuple[str, dict]:
    """
    Remplace chaque clé par sa valeur réelle dans `text`.

    Les clés les plus longues sont traitées en premier pour éviter qu'une clé
    courte ne casse une clé plus longue (p.ex. <SECRET_1> vs <SECRET_10>).

    Retourne (texte_modifié, stats) où stats = {
        "replaced":   nb total de remplacements effectués,
        "keys_used":  nb de clés distinctes réellement trouvées,
        "unused":     liste des clés du mapping jamais rencontrées,
        "leftover":   liste des placeholders encore présents après mapping,
    }
    """
    if not mapping:
        return text, {"replaced": 0, "keys_used": 0, "unused": [], "leftover": _find_leftover(text)}

    replaced_total = 0
    keys_used = 0
    unused: list[str] = []

    for key in sorted(mapping, key=len, reverse=True):
        count = text.count(key)
        if count:
            text = text.replace(key, mapping[key])
            replaced_total += count
            keys_used += 1
        else:
            unused.append(key)

    return text, {
        "replaced":  replaced_total,
        "keys_used": keys_used,
        "unused":    unused,
        "leftover":  _find_leftover(text),
    }


def _find_leftover(text: str) -> list[str]:
    """Détecte les placeholders NON résolus encore présents dans le texte."""
    patterns = [
        r"<[A-Z][A-Z0-9_]*?_\d+>",   # <IP_001>, <SECRET_010>, <BASE64_SECRET_008>
        r"\$[A-Z_]{3,}",             # $TARGET, $PASSWORD, $TOKEN, $EMAIL
    ]
    found: set[str] = set()
    for pat in patterns:
        found.update(re.findall(pat, text))
    return sorted(found)


def remap_markdown(md_text: str, mapping_path: str | Path | None) -> tuple[str, dict | None]:
    """
    Point d'entrée pour report_to_pdf.py.
    Si mapping_path est None -> renvoie le texte inchangé et stats=None.
    Sinon -> charge le mapping, l'applique, renvoie (texte_réel, stats).
    """
    if mapping_path is None:
        return md_text, None
    mapping = load_mapping(mapping_path)
    return apply_mapping(md_text, mapping)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 report_mapping.py RAPPORT.md mapping.txt [SORTIE.md]")
        sys.exit(1)
    md_path, map_path = sys.argv[1], sys.argv[2]
    out_path = sys.argv[3] if len(sys.argv) > 3 else None

    md = Path(md_path).read_text(encoding="utf-8", errors="replace")
    real, stats = remap_markdown(md, map_path)
    print(f"Remplacements : {stats['replaced']} "
          f"({stats['keys_used']} clés utilisées)")
    if stats["unused"]:
        print(f"Clés du mapping non utilisées : {len(stats['unused'])}")
    if stats["leftover"]:
        print(f"⚠ Placeholders non résolus : {stats['leftover']}")
    if out_path:
        Path(out_path).write_text(real, encoding="utf-8")
        print(f"Écrit : {out_path}")
