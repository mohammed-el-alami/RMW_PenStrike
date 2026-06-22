# RMW-PenStrike

RMW-PenStrike is an autonomous AI-driven penetration testing framework that automates the entire black-box assessment process, from reconnaissance to professional report generation. Leveraging a multi-agent, multi-LLM architecture, it enables parallel vulnerability investigations, advanced data anonymization, and automated OWASP-compliant reporting with CVSS, CWE, and CVE correlation.

## Overview

| Path | Purpose |
|---|---|
| `rmwpen/` | Main source code of the tool |
| `examples_input_output/` | Input and output file examples |
| `Rapport_RMW-PenStrike.pdf` | Complete project report |
| `Rapport_RMW-PenStrike_Latex.zip` | LaTeX source code of the report |
| `README.md` | Short repository presentation |

## Contents of `rmwpen/`

| File | Purpose |
|---|---|
| `main.py` | Command-line entry point |
| `config.py` | General project configuration |
| `llm_client.py` | Access layer for different LLM engines |
| `prompts.py` | Prompt construction and response processing |
| `executor.py` | Command execution and sensitive data anonymization |
| `storage.py` | Context file management |
| `logger.py` | Execution logging |
| `report_generator.py` | Markdown report generation |
| `report_enrich.py` | Report enrichment with CVEs and PoCs |
| `report_mapping.py` | Reinjection of real values from the mapping |
| `report_visuals.py` | Generation of report visual elements |
| `report_to_pdf.py` | Report conversion to PDF |
| `report_docx.py` | Report export to DOCX |
| `report_finalize.py` | Final generation orchestration |
| `install.sh` | Installation script |
| `uninstall.sh` | Uninstallation script |

## Provided Examples

| File | Purpose |
|---|---|
| `examples_input_output/example_input/target.txt` | Example input scope |
| `examples_input_output/example_input/env.txt` | Example environment configuration |
| `examples_input_output/example_output_1/RAPPORT_PENTEST_20260620_172903.pdf` | Example PDF report |
| `examples_input_output/example_output_1/RAPPORT_PENTEST_20260620_172903.docx` | Example DOCX report |
| `examples_input_output/example_output_1/files.zip` | Example snapshot |
| `examples_input_output/example_output_2/RAPPORT_PENTEST_20260620_160145.pdf` | Example PDF report |
| `examples_input_output/example_output_2/RAPPORT_PENTEST_20260620_160145.docx` | Example DOCX report |
| `examples_input_output/example_output_2/files.zip` | Example snapshot |

## Basic Usage

### Installation

```bash
sudo ./rmwpen/install.sh
```

### Uninstallation

```bash
sudo ./rmwpen/uninstall.sh
```

### Help

```bash
rmwpen -h
```

## Detailed Documentation

For the methodology, internal architecture, generation pipeline, and detailed usage instructions, refer to the project report:

- [Rapport_RMW-PenStrike.pdf](./Rapport_RMW-PenStrike.pdf)
