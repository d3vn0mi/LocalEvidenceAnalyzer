<p align="center">
  <h1 align="center">LocalEvidenceAnalyzer</h1>
  <p align="center">
    <strong>Offline security evidence analysis powered by local LLMs</strong>
  </p>
  <p align="center">
    <a href="#features">Features</a> &bull;
    <a href="#installation">Installation</a> &bull;
    <a href="#quick-start">Quick Start</a> &bull;
    <a href="#usage">Usage</a> &bull;
    <a href="#recommended-models">Models</a> &bull;
    <a href="#license">License</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
    <img src="https://img.shields.io/badge/python-3.8%2B-brightgreen.svg" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/ollama-local%20LLM-orange.svg" alt="Ollama">
  </p>
</p>

---

A Python CLI tool that analyzes security evidence folders using a local LLM (via [Ollama](https://ollama.ai)) and generates structured security assessment reports with CVSSv3-scored findings. Everything runs locally — your evidence never leaves your machine.

## Features

- **Recursive evidence scanning** — configs, logs, scan outputs, text files
- **Multi-host support** — analyze multiple hosts in a single run
- **Two-phase LLM analysis** — per-file analysis + cross-file deduplication and consolidation
- **CVSSv3 scoring** — vector strings and base scores for every finding
- **Evidence traceability** — each finding references its source file
- **Markdown & HTML reports** — professional output ready for clients
- **Custom security model** — Ollama Modelfile with CIS/STIG/NIST/OWASP tuning and few-shot examples
- **RAG knowledge base** — enrich analysis with your own security reference documents
- **Graceful interruption** — press Ctrl+C to generate a partial report or quit
- **Fully offline** — no data leaves your machine

## Requirements

- Python 3.8+
- [Ollama](https://ollama.ai) running locally
- A pulled LLM model (default: `llama3.1:8b`)

## Installation

```bash
# Clone the repository
git clone https://github.com/d3vn0mi/LocalEvidenceAnalyzer.git
cd LocalEvidenceAnalyzer

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Ollama (if not already installed)
curl -fsSL https://ollama.ai/install.sh | sh

# Pull the default model
ollama pull llama3.1:8b
```

## Quick Start

```bash
# Analyze an evidence folder
python analyzer.py analyze /evidence/host1 --verbose

# For best results, build the custom security model first (one-time)
python analyzer.py build-model

# Build the knowledge base index (re-run after adding reference docs)
python analyzer.py build-kb

# Analyze with custom model + knowledge base
python analyzer.py analyze /evidence/host1 --model lea-security --kb --verbose
```

## Usage

```bash
# Single host
python analyzer.py analyze /path/to/evidence/host1

# Multiple hosts
python analyzer.py analyze /evidence/host1 /evidence/host2 /evidence/host3

# Save report to file
python analyzer.py analyze /evidence/host1 --output report.md

# Generate HTML report
python analyzer.py analyze /evidence/host1 --format html --output report.html

# Use a different model
python analyzer.py analyze /evidence/host1 --model qwen2.5:32b

# Use the custom security model with knowledge base
python analyzer.py analyze /evidence/host1 --model lea-security --kb

# Shorthand (omit "analyze" subcommand)
python analyzer.py /evidence/host1 --verbose
```

### Auto-Save Checkpoint

Analysis progress is **automatically saved to disk** after each file is processed. If the process is killed, the PC shuts down, or an error occurs, no work is lost.

```bash
# On next run with the same evidence folders, you'll be prompted:
Checkpoint found: 42 findings from 15 files.
  Saved: 2026-03-19T14:30:00
  [r] Resume from checkpoint
  [s] Start fresh (discard checkpoint)

# Or resume automatically without prompting:
python analyzer.py analyze /evidence/host1 --resume

# Disable checkpointing:
python analyzer.py analyze /evidence/host1 --no-checkpoint
```

The checkpoint file is automatically deleted after a report is successfully generated.

### Graceful Interruption

Press **Ctrl+C** during analysis to get a prompt:

```
Interrupted! What would you like to do?
  [g] Generate report with findings collected so far
  [q] Quit without generating a report
Choice [g/q]:
```

Even after interruption, the checkpoint preserves all findings collected so far — you can resume later with `--resume`.

### CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `folders` | *(required)* | One or more evidence folders |
| `--model` | `llama3.1:8b` | Ollama model name |
| `--output, -o` | stdout | Save report to file |
| `--format, -f` | `markdown` | Output format: `markdown` or `html` |
| `--ollama-host` | `http://localhost:11434` | Ollama API URL |
| `--chunk-size` | `50000` | Max chars per LLM chunk |
| `--kb` | off | Enable knowledge base RAG enrichment |
| `--kb-dir` | `./knowledge_base` | Custom knowledge base directory |
| `--include-ext` | all text files | Only analyze these extensions (e.g. `.py .sh .conf`) |
| `--exclude-ext` | none | Skip files with these extensions (e.g. `.log .bak`) |
| `--verbose, -v` | off | Show analysis progress |
| `--no-checkpoint` | off | Disable auto-save checkpoint |
| `--resume` | off | Resume from checkpoint without prompting |

### Subcommands

| Command | Description |
|---------|-------------|
| `analyze` | Analyze evidence folders *(default)* |
| `build-model` | Build the custom `lea-security` Ollama model from Modelfile |
| `build-kb` | Build or rebuild the knowledge base index |

## How It Works

```
Evidence Folders ──> File Walker ──> Phase 1: Per-File Analysis ──> Phase 2: Consolidation ──> Report
                                          (LLM + RAG)              (Dedup + CVSS ranking)
```

1. **File Walking** — Recursively scans each host folder, reads text files, skips binaries
2. **Phase 1 — Per-File Analysis** — Each file is sent to the LLM for focused security analysis; large files are chunked on line boundaries; optional RAG context is injected from the knowledge base
3. **Phase 2 — Consolidation** — All raw findings are deduplicated, CVSS scores are refined, and findings are ranked by severity
4. **Report Generation** — Findings are rendered as a Markdown or HTML report with executive summary, per-finding details, and evidence references

### Report Structure

Each finding includes:

- **Title** and detailed description
- **Technical impact** assessment
- **Mitigation** steps with specific remediation actions
- **CVSSv3 score and vector** for standardized criticality rating
- **Evidence file path** referencing the source file
- **Host** identification

## Custom Security Model

The included `Modelfile` creates a security-tuned version of llama3.1:8b with:

- Detailed security analyst system prompt covering CIS, STIG, NIST, OWASP frameworks
- Few-shot examples of real findings (SSH, nmap, passwd analysis)
- Lower temperature (0.2) for consistent, deterministic output
- 128K context window

```bash
python analyzer.py build-model
python analyzer.py analyze /evidence/host1 --model lea-security
```

## Knowledge Base (RAG)

Add security reference documents to `knowledge_base/` to enrich analysis with domain-specific context. Uses a lightweight keyword-based retrieval system — no heavy vector DB dependencies.

**Included references:**
- SSH hardening (CIS benchmarks)
- Linux user/authentication security
- Network security (port analysis, TLS, firewalls)
- Web server security (Apache, Nginx, headers)
- System hardening (kernel, filesystem, services)

**Add your own:**
```bash
# Add .txt files — CIS benchmarks, runbooks, CVE lists, etc.
cp my_security_guide.txt knowledge_base/
cp cis_benchmark_notes.txt knowledge_base/

# Rebuild the index
python analyzer.py build-kb

# Analyze with KB enabled
python analyzer.py analyze /evidence/host1 --kb --verbose
```

## Recommended Models

| Model | Size | RAM | Speed | Notes |
|-------|------|-----|-------|-------|
| `llama3.1:8b` | 4.9 GB | ~8 GB | Fast | Default — good general performance |
| `lea-security` | 4.9 GB | ~8 GB | Fast | Custom-tuned with security prompts |
| `qwen2.5:14b` | ~9 GB | ~12 GB | Moderate | Better structured JSON output |
| `qwen2.5:32b` | ~20 GB | ~24 GB | Slower | Best quality — recommended for 32GB+ RAM |
| `mistral-small:24b` | ~15 GB | ~18 GB | Moderate | Strong reasoning |

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

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## Author

**d3vn0mi** — [github.com/d3vn0mi](https://github.com/d3vn0mi)

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
