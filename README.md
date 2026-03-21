<p align="center">
  <h1 align="center">鏡 Kagami</h1>
  <p align="center">
    <strong>Autonomous forensic analysis & configuration auditing powered by local LLMs</strong>
  </p>
  <p align="center">
    <em>by <a href="https://github.com/d3vn0mi">d3vn0mi</a></em>
  </p>
  <p align="center">
    <a href="#features">Features</a> &bull;
    <a href="#installation">Installation</a> &bull;
    <a href="#quick-start">Quick Start</a> &bull;
    <a href="#usage">Usage</a> &bull;
    <a href="#knowledge-base-rag">Knowledge Base</a> &bull;
    <a href="#recommended-models">Models</a> &bull;
    <a href="#roadmap">Roadmap</a> &bull;
    <a href="#license">License</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT">
    <img src="https://img.shields.io/badge/python-3.8%2B-brightgreen.svg" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/ollama-local%20LLM-orange.svg" alt="Ollama">
  </p>
</p>

---

Kagami (鏡, "mirror") is a Python CLI forensics analyst and configuration auditor that reflects the true security posture of your systems. It analyzes evidence folders using a local LLM (via [Ollama](https://ollama.ai)) and generates structured security assessment reports with CVSSv3-scored findings. Built for forensics analysts, configuration auditors, and pentesters. Everything runs locally — your evidence never leaves your machine.

## Features

- **Forensic evidence analysis** — configs, logs, scan outputs, text files with file type filtering
- **Configuration auditing** — CIS, STIG, NIST, OWASP compliance checking via LLM reasoning
- **Multi-host support** — analyze multiple hosts in a single run
- **Two-phase LLM analysis** — per-file analysis + cross-file deduplication and consolidation
- **CVSSv3 scoring** — vector strings and base scores for every finding
- **Evidence traceability** — each finding references its source file and host
- **Markdown & HTML reports** — professional output ready for clients
- **Auto-generated results** — each run creates a timestamped `results/` folder with the report and a `command.txt` audit trail
- **Live HTML preview** — watch findings populate in your browser in real time with `--live`
- **Rich progress UI** — animated progress bars, severity breakdown, and file-by-file status
- **Auto-save checkpoint** — progress saved to disk after each file; resume after crashes or power loss
- **Custom security model** — Ollama Modelfile with CIS/STIG/NIST/OWASP tuning and few-shot examples
- **RAG knowledge base** — 13 built-in security reference documents covering Linux, Fortinet, OWASP, LDAP, and more
- **File type filtering** — `--include-ext` / `--exclude-ext` to target specific file types
- **Graceful interruption** — press Ctrl+C to generate a partial report or quit
- **Fully offline** — no data leaves your machine

## Requirements

- Python 3.8+
- [Ollama](https://ollama.ai) running locally
- A pulled LLM model (default: `llama3.1:8b`)

## Installation

```bash
# Clone the repository
git clone https://github.com/d3vn0mi/Kagami.git
cd Kagami

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

### Dependencies

| Package | Purpose |
|---------|---------|
| `ollama` | Local LLM API client |
| `jinja2` | HTML report templating |
| `rich` | Progress bars, panels, and styled terminal output |

## Quick Start

```bash
# Analyze an evidence folder
python analyzer.py analyze /evidence/host1 --verbose

# For best results, build the custom security model first (one-time)
python analyzer.py build-model

# Or build with a different base model + embedded KB (one-time)
python analyzer.py build-model --base-model qwen2.5:32b --with-kb

# Build the knowledge base index (re-run after adding reference docs)
python analyzer.py build-kb

# Analyze with custom model (KB already embedded if built with --with-kb)
python analyzer.py analyze /evidence/host1 --model kagami-security --verbose

# Or use runtime KB injection instead
python analyzer.py analyze /evidence/host1 --model kagami-security --kb --verbose
```

## Usage

```bash
# Single host
python analyzer.py analyze /path/to/evidence/host1

# Multiple hosts
python analyzer.py analyze /evidence/host1 /evidence/host2 /evidence/host3

# Save report to a specific path (bypasses auto results directory)
python analyzer.py analyze /evidence/host1 --output report.md

# Generate HTML report
python analyzer.py analyze /evidence/host1 --format html --output report.html

# Use a different model
python analyzer.py analyze /evidence/host1 --model qwen2.5:32b

# Use the custom security model with knowledge base
python analyzer.py analyze /evidence/host1 --model kagami-security --kb

# Only analyze specific file types
python analyzer.py analyze /evidence/host1 --include-ext .conf .txt .sh .py

# Only analyze specific filenames across all hosts
python analyzer.py analyze /evidence/host1 /evidence/host2 --include-name sudoers sshd_config

# Glob patterns work too
python analyzer.py analyze /evidence/* --include-name "*.conf" "authorized_keys"

# Skip certain file types
python analyzer.py analyze /evidence/host1 --exclude-ext .log .bak .tmp

# Live HTML preview — open live.html in your browser during analysis
python analyzer.py analyze /evidence/host1 --live live.html --verbose

# Parallel analysis — 4 files at a time (set OLLAMA_NUM_PARALLEL=4 first)
python analyzer.py analyze /evidence/host1 --workers 4 --verbose

# Shorthand (omit "analyze" subcommand)
python analyzer.py /evidence/host1 --verbose
```

### Results Directory

By default, each run creates a timestamped results folder:

```
results/
├── 20260319_143022/
│   ├── report.md          # Generated report
│   └── command.txt        # Exact command used to produce this report
├── 20260319_151500/
│   ├── report.html
│   └── command.txt
```

Use `--output` to bypass this and write to a specific path instead.

### Progress UI

When running with `--verbose` or `--output`, a rich live display shows real-time progress:

```
╭─ Kagami ───────────────────────────────────────╮
│ Hosts: webserver01                              │
│ Model: kagami-security                          │
│ Features: KB (130 chunks) | Checkpoint: saved   │
╰─────────────────────────────────────────────────╯

 ⠋ Phase 1 ━━━━━━━━━━━━━━━━━━━━━╸━━━━━━━  10/15 files  0:02:30

 ✓ etc/ssh/sshd_config          3 findings
 ✓ etc/passwd                   2 findings
 ✓ nmap_scan.txt                5 findings
 ⠋ apache_config.conf           analyzing...

 Findings: 42 raw  Critical: 3  High: 12  Medium: 18  Low: 9
```

After completion, a styled summary table is displayed:

```
┌─── Final Report Summary ───┐
│ Severity   │ Count         │
├────────────┼───────────────┤
│ Critical   │     3         │
│ High       │    12         │
│ Medium     │    18         │
│ Low        │     9         │
├────────────┼───────────────┤
│ Total      │    42         │
└────────────┴───────────────┘

Report saved to: results/20260319_143022/report.md
```

### Auto-Save Checkpoint

Analysis progress is **automatically saved to disk** after each file is processed. If the process crashes, is killed, or the PC shuts down, no work is lost.

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

Checkpoint files are written atomically (crash-safe) and automatically deleted after a report is successfully generated.

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
| `--output, -o` | auto (`results/<timestamp>/`) | Save report to specific file (bypasses auto results directory) |
| `--format, -f` | `markdown` | Output format: `markdown` or `html` |
| `--ollama-host` | `http://localhost:11434` | Ollama API URL |
| `--chunk-size` | `50000` | Max chars per LLM chunk |
| `--kb` | off | Enable knowledge base RAG enrichment |
| `--kb-dir` | `./knowledge_base` | Custom knowledge base directory |
| `--include-ext` | all text files | Only analyze these extensions (e.g. `.py .sh .conf`) |
| `--exclude-ext` | none | Skip files with these extensions (e.g. `.log .bak`) |
| `--include-name` | none | Only analyze files matching these names/glob patterns (e.g. `sudoers sshd_config '*.conf'`) |
| `--exclude-name` | none | Skip files matching these names/glob patterns |
| `--live` | none | Write a live-updating HTML report to FILE (auto-refreshes in browser) |
| `--verbose, -v` | off | Show rich progress UI |
| `--workers, -w` | `1` | Number of parallel file analysis workers (see [Performance Tuning](#performance-tuning)) |
| `--no-checkpoint` | off | Disable auto-save checkpoint |
| `--resume` | off | Resume from checkpoint without prompting |

### Subcommands

| Command | Description |
|---------|-------------|
| `analyze` | Analyze evidence folders *(default when omitted)* |
| `build-model` | Build the custom `kagami-security` Ollama model (supports `--base-model` and `--with-kb`) |
| `build-kb` | Build or rebuild the knowledge base index |

## How It Works

```
Evidence Folders ──> File Walker ──> Phase 1: Per-File Analysis ──> Phase 2: Consolidation ──> Report
                     (filter by        (LLM + RAG context)         (Dedup + CVSS ranking)
                      extension)        [checkpoint after each]
```

1. **File Walking** — Recursively scans each host folder, reads text files, skips binaries. Optionally filters by extension with `--include-ext` / `--exclude-ext`.
2. **Phase 1 — Per-File Analysis** — Each file is sent to the LLM for focused security analysis. Large files are chunked on line boundaries. Optional RAG context is injected from the knowledge base. Progress is checkpointed after each file.
3. **Phase 2 — Consolidation** — All raw findings are deduplicated, CVSS scores are refined, and findings are ranked by severity.
4. **Report Generation** — Findings are rendered as a Markdown or HTML report with executive summary, per-finding details, and evidence references.

### Report Structure

Each finding includes:

- **Title** and detailed description
- **Technical impact** assessment
- **Mitigation** steps with specific remediation actions
- **CVSSv3 score and vector** for standardized criticality rating
- **Evidence file path** referencing the source file
- **Host** identification

## Custom Security Model

The included `Modelfile` creates a security-tuned Ollama model with:

- Detailed security analyst system prompt covering CIS, STIG, NIST, OWASP frameworks
- Few-shot examples of real findings (SSH, nmap, passwd analysis)
- Lower temperature (0.2) for consistent, deterministic output
- 128K context window

```bash
# Build with default base model (llama3.1:8b)
python analyzer.py build-model

# Build with a different base model (e.g. Qwen)
python analyzer.py build-model --base-model qwen2.5:32b

# Build with KB baked into the model's system prompt
python analyzer.py build-model --base-model qwen2.5:32b --with-kb

# Use the built model (no --kb flag needed if KB was embedded)
python analyzer.py analyze /evidence/host1 --model kagami-security
```

### build-model Options

| Option | Default | Description |
|--------|---------|-------------|
| `--base-model` | `llama3.1:8b` | Base Ollama model to build from (e.g. `qwen2.5:32b`, `mistral-small:24b`) |
| `--with-kb` | off | Embed all knowledge base documents into the model's system prompt |
| `--kb-dir` | `./knowledge_base` | Custom knowledge base directory (used with `--with-kb`) |
| `--ollama-host` | `http://localhost:11434` | Ollama API URL |

When `--with-kb` is used, the entire knowledge base is injected into the model's system prompt at build time. This means the model always has access to reference material without needing `--kb` at runtime. The trade-off is a larger model context on every request — for smaller models (8b), runtime `--kb` may be more efficient since it only injects relevant chunks.

## Knowledge Base (RAG)

Kagami includes a comprehensive security knowledge base with **13 reference documents** covering forensics, pentesting, and configuration auditing. Uses a lightweight keyword-based retrieval system — no heavy vector DB dependencies.

### Built-in Reference Documents

| Document | Coverage |
|----------|----------|
| `ssh_hardening.txt` | SSH config directives, ciphers, key management (CIS) |
| `linux_user_security.txt` | passwd/shadow analysis, sudo, PAM, SSSD (per-distro) |
| `system_hardening.txt` | Kernel sysctl, file permissions, services, auditd (per-distro) |
| `network_security.txt` | Nmap port analysis, TLS/SSL, DNS, firewalld/UFW/nftables |
| `web_server_security.txt` | Apache/Nginx configs, security headers, web app indicators |
| `fortinet_security.txt` | FortiGate admin, policies, VPN, known CVEs (CVE-2022-42475, etc.) |
| `firewall_hardening.txt` | iptables, nftables, firewalld (RHEL), UFW (Ubuntu/Debian) |
| `owasp_top10.txt` | OWASP A01–A10 (2021) with config patterns and log indicators |
| `ldap_security.txt` | OpenLDAP, 389 DS, ACLs, TLS, password policy, replication |
| `linux_rhel_hardening.txt` | SELinux, FIPS, RPM integrity, AIDE, authselect (RHEL/CentOS) |
| `linux_ubuntu_debian_hardening.txt` | AppArmor, APT security, UFW, debsums, snap (Ubuntu/Debian) |
| `privilege_escalation.txt` | SUID/GTFOBins, sudo misconfigs, capabilities, container escape |
| `log_forensics.txt` | Brute force, persistence, lateral movement, log tampering, web shells |

### Add Your Own References

```bash
# Add .txt files — CIS benchmarks, runbooks, CVE lists, etc.
cp my_security_guide.txt knowledge_base/
cp cis_benchmark_notes.txt knowledge_base/

# Rebuild the index
python analyzer.py build-kb

# Analyze with KB enabled
python analyzer.py analyze /evidence/host1 --kb --verbose
```

## Performance Tuning

By default, files are analyzed one at a time. If you have idle CPU/GPU capacity (common on multi-core Macs or machines with powerful GPUs), use `--workers` to analyze multiple files in parallel:

```bash
# Analyze 4 files at a time
python analyzer.py analyze /evidence/host1 --workers 4 --verbose

# Combine with your custom model
python analyzer.py analyze /evidence/host1 --model kagami-security --workers 4 --verbose
```

### Ollama Parallel Slots

Ollama must also be configured to handle concurrent requests. By default Ollama processes one request at a time. Set the `OLLAMA_NUM_PARALLEL` environment variable **before starting Ollama**:

```bash
# Allow Ollama to process 4 requests concurrently
OLLAMA_NUM_PARALLEL=4 ollama serve

# Or export it in your shell profile
export OLLAMA_NUM_PARALLEL=4
```

### Recommended Settings

| Machine | `--workers` | `OLLAMA_NUM_PARALLEL` | Notes |
|---------|-------------|----------------------|-------|
| 8 GB RAM, 8b model | 1–2 | 2 | Conservative — avoids swapping |
| 16 GB RAM, 8b model | 2–4 | 4 | Good balance |
| 32 GB RAM, 32b model | 2–3 | 3 | Larger models need more RAM per slot |
| 64 GB+ RAM or GPU offload | 4–8 | 8 | Max throughput |

**Tip:** `--workers` should not exceed `OLLAMA_NUM_PARALLEL` — extra workers will just queue on the Ollama side.

## Recommended Models

| Model | Size | RAM | Speed | Notes |
|-------|------|-----|-------|-------|
| `llama3.1:8b` | 4.9 GB | ~8 GB | Fast | Default — good general performance |
| `kagami-security` | 4.9 GB | ~8 GB | Fast | Custom-tuned with security prompts |
| `qwen2.5:14b` | ~9 GB | ~12 GB | Moderate | Better structured JSON output |
| `qwen2.5:32b` | ~20 GB | ~24 GB | Slower | Best quality — recommended for 32GB+ RAM |
| `mistral-small:24b` | ~15 GB | ~18 GB | Moderate | Strong reasoning |

## Project Structure

```
Kagami/
├── analyzer.py             # CLI entrypoint + orchestration
├── file_walker.py          # Recursive dir walk, binary detection, extension filtering
├── llm_client.py           # Ollama wrapper, chunking, JSON parsing
├── prompts.py              # LLM prompt templates (Phase 1 + Phase 2)
├── report.py               # Finding dataclass, Markdown + HTML rendering
├── progress.py             # Rich progress bars and live display
├── knowledge_base.py       # RAG keyword index and retrieval
├── Modelfile               # Custom Ollama model definition
├── requirements.txt        # Python dependencies
├── knowledge_base/         # Security reference documents (13 files)
│   ├── ssh_hardening.txt
│   ├── linux_user_security.txt
│   ├── system_hardening.txt
│   ├── network_security.txt
│   ├── web_server_security.txt
│   ├── fortinet_security.txt
│   ├── firewall_hardening.txt
│   ├── owasp_top10.txt
│   ├── ldap_security.txt
│   ├── linux_rhel_hardening.txt
│   ├── linux_ubuntu_debian_hardening.txt
│   ├── privilege_escalation.txt
│   └── log_forensics.txt
├── results/                # Auto-generated reports (gitignored)
└── LICENSE                 # MIT License
```

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

## Roadmap

### Phase 1 — Evidence Folder Analysis (Current)
Analyze pre-collected evidence folders from forensic acquisitions, configuration exports, or pentest artifacts. This is the current functionality.

### Phase 2 — Autonomous Filesystem Scanning
Run Kagami directly on a live system to autonomously discover, collect, and audit security-relevant files from the local filesystem. Planned capabilities:

- **Auto-discovery** — scan known security-relevant paths (`/etc/ssh/`, `/etc/sudoers.d/`, `/etc/pam.d/`, systemd units, cron jobs, etc.)
- **Live system profiling** — detect OS, distro, running services, and tailor the audit scope accordingly
- **Configuration drift detection** — compare live configs against CIS/STIG baselines
- **Scheduled audits** — run periodic scans and diff reports over time
- **Agent mode** — daemonize for continuous compliance monitoring

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## Author

**d3vn0mi** — [github.com/d3vn0mi](https://github.com/d3vn0mi)

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
