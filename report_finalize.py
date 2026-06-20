#!/usr/bin/env python3
"""
report_finalize.py — Orchestration de l'étape finale (TA partie).
Version avec logs détaillés pour diagnostiquer l'absence de rapport.
"""
from __future__ import annotations

import atexit
import os
import signal
import sys
import time
import zipfile
from pathlib import Path

import config
from logger import log

try:
    import report_generator
except Exception as e:
    log(f"report_generator import failed: {e}", "WARN")
    report_generator = None

try:
    import report_mapping
except Exception as e:
    log(f"report_mapping import failed: {e}", "WARN")
    report_mapping = None

try:
    import report_to_pdf
except Exception as e:
    log(f"report_to_pdf import failed: {e}", "WARN")
    report_to_pdf = None

try:
    import report_docx
except Exception as e:
    log(f"report_docx import failed: {e}", "WARN")
    report_docx = None

MAPPING_FILENAME = "mapping.txt"
PDF_PREFIX       = "RAPPORT_PENTEST"
DEFAULT_ZIP_NAME = "files.zip"

REDACT_LEVEL     = "real"
CLASSIFICATION   = "CONFIDENTIAL"
EXPORT_DOCX      = True
WATERMARK        = True

_FINALIZED = False
_CWD_AT_IMPORT = Path(os.getcwd())
_OUTPUT_ZIP_OVERRIDE: Path | None = None


def set_output_zip(zip_path: Path | None) -> None:
    global _OUTPUT_ZIP_OVERRIDE
    if zip_path is not None:
        _OUTPUT_ZIP_OVERRIDE = Path(zip_path)


def set_output_options(redact_level: str | None = None,
                       classification: str | None = None,
                       export_docx: bool | None = None,
                       watermark: bool | None = None) -> None:
    global REDACT_LEVEL, CLASSIFICATION, EXPORT_DOCX, WATERMARK
    if redact_level in ("real", "partial", "full"):
        REDACT_LEVEL = redact_level
    if classification:
        CLASSIFICATION = classification
    if export_docx is not None:
        EXPORT_DOCX = export_docx
    if watermark is not None:
        WATERMARK = watermark


def _find_mapping() -> Path | None:
    candidates = [
        config.APP_CONFIG.files_dir / MAPPING_FILENAME,
        config.APP_CONFIG.base_dir / MAPPING_FILENAME,
        _CWD_AT_IMPORT / MAPPING_FILENAME,
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            log(f"Mapping trouvé : {c}", "DEBUG")
            return c
    log("Aucun mapping.txt trouvé.", "WARN")
    return None


def _resolve_output_zip() -> Path:
    name = _OUTPUT_ZIP_OVERRIDE.name if _OUTPUT_ZIP_OVERRIDE else DEFAULT_ZIP_NAME
    return _CWD_AT_IMPORT / name


def _rebuild_output_zip(zip_path: Path) -> None:
    files_dir = config.APP_CONFIG.files_dir
    if not files_dir.exists():
        log("files/ n'existe pas, zip ignoré.", "WARN")
        return
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in sorted(files_dir.rglob("*")):
                if item.is_file():
                    if item.name == MAPPING_FILENAME:
                        continue
                    arcname = Path("files") / item.relative_to(files_dir)
                    zf.write(item, arcname)
            mapping_file = _find_mapping()
            if mapping_file and mapping_file.exists():
                zf.write(mapping_file, MAPPING_FILENAME)
                log(f"Mapping ajouté au zip : {mapping_file.name}", "DEBUG")
        log(f"Archive de sortie écrite : {zip_path}", "MAIN")
    except Exception as e:
        log(f"Erreur écriture archive de sortie : {e}", "ERR")


def _cleanup_scripts_dir(md_temp: Path | None) -> None:
    if md_temp and md_temp.exists():
        try:
            md_temp.unlink()
            log(f"Fichier MD temporaire supprimé : {md_temp.name}", "DEBUG")
        except Exception as e:
            log(f"Suppression MD échouée : {e}", "WARN")
    try:
        state = config.APP_CONFIG.state_file
        if state.exists():
            state.unlink()
    except Exception:
        pass
    try:
        map_in_base = config.APP_CONFIG.base_dir / MAPPING_FILENAME
        if map_in_base.exists():
            map_in_base.unlink()
            log("mapping.txt supprimé du dossier des scripts.", "DEBUG")
    except Exception as e:
        log(f"Suppression mapping.txt échouée : {e}", "WARN")
    try:
        import shutil
        files_dir = config.APP_CONFIG.files_dir
        if files_dir.exists():
            shutil.rmtree(files_dir)
            log(f"Dossier {files_dir} supprimé.", "MAIN")
    except Exception as e:
        log(f"Nettoyage files/ échoué : {e}", "WARN")


def _stop_pentest_agents() -> None:
    try:
        import main as _main
    except Exception:
        try:
            import __main__ as _main
        except Exception:
            return
    try:
        stop_event = getattr(_main, "_STOP_EVENT", None)
        if stop_event is not None and not stop_event.is_set():
            stop_event.set()
            log("Arrêt des agents demandé.", "MAIN")
        threads = list(getattr(_main, "_ACTIVE_THREADS", {}).values())
        deadline = time.time() + 6
        for t in threads:
            remaining = max(0.1, deadline - time.time())
            try:
                t.join(timeout=remaining)
            except Exception:
                pass
    except Exception as e:
        log(f"Erreur arrêt agents : {e}", "WARN")


def finalize(zip_output_path: Path | None = None) -> None:
    global _FINALIZED
    if _FINALIZED:
        log("Finalisation déjà effectuée.", "DEBUG")
        return
    _FINALIZED = True
    log("Début de la finalisation...", "MAIN")

    if zip_output_path is not None:
        set_output_zip(zip_output_path)

    files_dir = config.APP_CONFIG.files_dir
    if not files_dir.exists():
        log("files/ n'existe pas, finalisation sans rapport.", "WARN")
        return

    out_zip  = _resolve_output_zip()
    md_temp: Path | None = None
    pdf_out: Path | None = None

    # 1) Rapport Markdown
    if report_generator is not None:
        try:
            log("Génération du rapport Markdown...", "MAIN")
            md_path_str = report_generator.generate_pentest_report()
            if md_path_str:
                md_temp = Path(md_path_str)
                log(f"Rapport MD généré : {md_temp.name}", "MAIN")
        except Exception as e:
            log(f"Génération du rapport MD échouée : {e}", "ERR")
    else:
        log("report_generator non disponible (module importé ?)", "WARN")

    # 2+3) Mapping + PDF
    if md_temp and md_temp.exists() and report_to_pdf is not None:
        try:
            mapping_file = _find_mapping()
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            pdf_out = _CWD_AT_IMPORT / f"{PDF_PREFIX}_{timestamp}.pdf"
            log(f"Conversion PDF en cours vers {pdf_out.name}...", "MAIN")
            report_to_pdf.convert(
                str(md_temp),
                str(pdf_out),
                mapping_path=str(mapping_file) if mapping_file else None,
                classification=CLASSIFICATION,
                redact_level=REDACT_LEVEL,
                watermark=WATERMARK,
            )
            if pdf_out.exists():
                log(f"PDF généré : {pdf_out.name}", "MAIN")
            else:
                log("Le PDF n'a pas été créé.", "WARN")
        except Exception as e:
            log(f"Conversion PDF échouée : {e}", "ERR")
    else:
        if report_to_pdf is None:
            log("report_to_pdf non disponible (module manquant ?)", "WARN")
        else:
            log("Rapport MD absent, PDF non généré.", "WARN")

    # 3bis) Export Word
    if EXPORT_DOCX and md_temp and md_temp.exists() and report_docx is not None:
        try:
            md_real = md_temp.read_text(encoding="utf-8", errors="replace")
            mapping_file = _find_mapping()
            if mapping_file and REDACT_LEVEL in ("real", "partial") and report_mapping is not None:
                full_map = report_mapping.load_mapping(mapping_file)
                if REDACT_LEVEL == "partial":
                    SENS = ("SECRET","TOKEN","PASSWORD","API_KEY","JWT","CRED","HASH","AWS","PRIVATE")
                    full_map = {k: ("••••••••(redacted)" if any(s in k.upper() for s in SENS) else v)
                                for k, v in full_map.items()}
                md_real, _ = report_mapping.apply_mapping(md_real, full_map)
            docx_out = _CWD_AT_IMPORT / f"{PDF_PREFIX}_{timestamp}.docx"
            if report_docx.convert_md_to_docx(md_real, str(docx_out), classification=CLASSIFICATION):
                log(f"Export Word généré : {docx_out.name}", "MAIN")
            else:
                log("Échec de l'export Word.", "WARN")
        except Exception as e:
            log(f"Export Word ignoré : {e}", "WARN")
    else:
        if not EXPORT_DOCX:
            log("Export Word désactivé.", "DEBUG")
        elif report_docx is None:
            log("report_docx non disponible.", "WARN")

    # 4) Zip de sortie
    _rebuild_output_zip(out_zip)

    # 5) Nettoyage
    _cleanup_scripts_dir(md_temp)

    if pdf_out and pdf_out.exists():
        log(f"Livrables prêts dans {_CWD_AT_IMPORT} : {out_zip.name} + {pdf_out.name}", "MAIN")
    else:
        log(f"Livrable prêt dans {_CWD_AT_IMPORT} : {out_zip.name}", "MAIN")
    log("Finalisation terminée.", "MAIN")


# ── Hooks signaux ─────────────────────────────────────────────────────────────
_PREV_SIGINT  = None
_PREV_SIGTERM = None


def _signal_finalize(signum, frame):
    global _FINALIZED
    if _FINALIZED:
        return
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    except Exception:
        pass
    log("Interruption reçue — finalisation...", "WARN")
    _stop_pentest_agents()
    try:
        finalize()
    finally:
        os._exit(0)


def install_hooks() -> None:
    global _PREV_SIGINT, _PREV_SIGTERM
    log("Installation des hooks de finalisation...", "DEBUG")
    atexit.register(finalize)
    try:
        _PREV_SIGINT = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, _signal_finalize)
    except Exception as e:
        log(f"Échec hook SIGINT : {e}", "WARN")
    try:
        _PREV_SIGTERM = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, _signal_finalize)
    except Exception as e:
        log(f"Échec hook SIGTERM : {e}", "WARN")
