# LocalEvidenceAnalyzer

A Python CLI tool that analyzes security evidence folders using a local LLM (via Ollama) and generates structured security assessment reports with CVSSv3-scored findings.

## Features

- Recursive evidence folder scanning (configs, logs, scan outputs, text files)
- Multi-host support — analyze multiple hosts in a single run
- Two-phase LLM analysis: per-file analysis + cross-file deduplication/consolidation
- CVSSv3 scoring with vector strings for each finding
- Evidence file references for traceability
- Markdown and HTML report output
- Binary file detection and graceful skipping
- Works entirely offline with a local LLM

## Requirements

- Python 3.8+
- [Ollama](https://ollama.ai) running locally
- A pulled LLM model (default: `llama3.1:8b`)

## Installation

```bash
# Install Ollama (if not already installed)
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the default model
ollama pull llama3.1:8b

# Install Python dependencies
pip install -r requirements.txt
```

## Usage

```bash
# Analyze a single host
python analyzer.py /path/to/evidence/host1

# Analyze multiple hosts
python analyzer.py /evidence/host1 /evidence/host2 /evidence/host3

# Save report to file
python analyzer.py /evidence/host1 --output report.md

# Generate HTML report
python analyzer.py /evidence/host1 --format html --output report.html

# Use a different model
python analyzer.py /evidence/host1 --model mistral:7b

# Verbose output (shows progress)
python analyzer.py /evidence/host1 --verbose
```

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `folders` | (required) | One or more evidence folders |
| `--model` | `llama3.1:8b` | Ollama model name |
| `--output, -o` | stdout | Save report to file |
| `--format, -f` | `markdown` | Output format: `markdown` or `html` |
| `--ollama-host` | `http://localhost:11434` | Ollama API URL |
| `--chunk-size` | `50000` | Max chars per LLM chunk |
| `--verbose, -v` | off | Show analysis progress |

## How It Works

1. **File Walking** — Recursively scans each host folder, reads text files, skips binaries
2. **Phase 1 (Per-File Analysis)** — Each file is sent to the LLM individually for focused security analysis. Large files are chunked on line boundaries.
3. **Phase 2 (Consolidation)** — All raw findings are sent to the LLM for deduplication, CVSS score refinement, and severity ranking
4. **Report Generation** — Findings are rendered as a Markdown or HTML report with executive summary, per-finding details, and evidence references

## Report Structure

Each finding includes:
- **Title** and detailed description
- **Technical impact** assessment
- **Mitigation** steps
- **CVSSv3 score and vector** for standardized criticality rating
- **Evidence file path** referencing the source file
- **Host** identification

## Recommended Models

| Model | Context | RAM | Notes |
|-------|---------|-----|-------|
| `llama3.1:8b` | 128k | ~5GB | Default. Large context, strong reasoning |
| `mistral:7b` | 8k | ~4GB | Lightweight, use `--chunk-size 6000` |
| `qwen3:8b` | 32k | ~5GB | Strong structured output |

## Evidence Folder Structure

Organize evidence by host. Any text-based files are analyzed:

```
evidence/
├── host1/
│   ├── etc/
│   │   ├── passwd
│   │   ├── shadow
│   │   └── ssh/sshd_config
│   ├── nmap_scan.txt
│   └── lynis_report.txt
├── host2/
│   ├── apache_config.conf
│   └── access.log
```
