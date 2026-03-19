#!/usr/bin/env python3
"""LocalEvidenceAnalyzer - Security evidence analysis using local LLMs."""

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from file_walker import walk_evidence
from knowledge_base import KnowledgeBase
from llm_client import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MODEL,
    analyze_file,
    chunk_content,
    consolidate_findings,
    validate_connection,
)
from progress import AnalysisProgress, QuietProgress
from report import findings_from_dicts, render_html, render_markdown

CUSTOM_MODEL_NAME = "lea-security"

# Signals the analysis loop to stop and generate a partial report
_interrupted = False


def _handle_interrupt(signum, frame):
    """Handle Ctrl+C during analysis."""
    global _interrupted

    if _interrupted:
        # Second Ctrl+C — abort immediately
        print("\nAborting immediately.", file=sys.stderr)
        sys.exit(130)

    print(file=sys.stderr)
    print("\nInterrupted! What would you like to do?", file=sys.stderr)
    print("  [g] Generate report with findings collected so far", file=sys.stderr)
    print("  [q] Quit without generating a report", file=sys.stderr)

    try:
        choice = input("Choice [g/q]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nAborting.", file=sys.stderr)
        sys.exit(130)

    if choice == "g":
        _interrupted = True  # signal the loop to stop
    else:
        print("Exiting.", file=sys.stderr)
        sys.exit(130)


def _checkpoint_path(args):
    """Derive the checkpoint file path from the output flag or use a default."""
    if args.output:
        return args.output + ".checkpoint.json"
    return ".lea_checkpoint.json"


def _save_checkpoint(path, raw_findings, skipped, hosts, processed, args):
    """Atomically save analysis progress to a checkpoint file."""
    data = {
        "version": 1,
        "saved_at": datetime.now().isoformat(),
        "model": args.model,
        "folders": [os.path.abspath(f) for f in args.folders],
        "hosts": hosts,
        "processed_files": sorted(processed),
        "skipped_files": skipped,
        "raw_findings": raw_findings,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)  # atomic on POSIX


def _load_checkpoint(path, args):
    """Load a checkpoint file if it exists and matches the current run config."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    if data.get("version") != 1:
        return None
    # Verify the checkpoint matches the current folders
    current_folders = sorted(os.path.abspath(f) for f in args.folders)
    saved_folders = sorted(data.get("folders", []))
    if current_folders != saved_folders:
        return None
    return data


def _remove_checkpoint(path):
    """Remove checkpoint file and its temp file after successful completion."""
    for p in (path, path + ".tmp"):
        try:
            os.remove(p)
        except OSError:
            pass


def parse_args():
    # Detect if the first positional argument is a known subcommand.
    # If not, inject "analyze" so that `analyzer.py /path` works like
    # `analyzer.py analyze /path` (backwards-compatible shorthand).
    known_commands = {"analyze", "build-model", "build-kb"}
    if len(sys.argv) > 1 and sys.argv[1] not in known_commands and not sys.argv[1].startswith("-"):
        sys.argv.insert(1, "analyze")

    parser = argparse.ArgumentParser(
        description="Analyze security evidence folders using a local LLM and generate a findings report.",
        epilog="Example: python analyzer.py /evidence/host1 /evidence/host2 --output report.md",
    )

    subparsers = parser.add_subparsers(dest="command")

    # Main analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze evidence folders")
    _add_analyze_args(analyze_parser)

    # Build custom model
    build_parser = subparsers.add_parser(
        "build-model",
        help="Build the custom security-tuned Ollama model from Modelfile",
    )
    build_parser.add_argument(
        "--ollama-host",
        default="http://localhost:11434",
        help="Ollama API URL (default: http://localhost:11434)",
    )
    build_parser.add_argument(
        "--base-model",
        default=None,
        help="Base Ollama model to use instead of llama3.1:8b (e.g. qwen2.5:32b)",
    )
    build_parser.add_argument(
        "--with-kb",
        action="store_true",
        default=False,
        help="Embed knowledge base content into the model's system prompt",
    )
    build_parser.add_argument(
        "--kb-dir",
        default=None,
        help="Knowledge base directory (default: ./knowledge_base)",
    )

    # Build/rebuild knowledge base index
    kb_parser = subparsers.add_parser(
        "build-kb",
        help="Build or rebuild the knowledge base index",
    )
    kb_parser.add_argument(
        "--kb-dir",
        default=None,
        help="Knowledge base directory (default: ./knowledge_base)",
    )

    return parser.parse_args()


def _add_analyze_args(parser):
    """Add analysis arguments to a parser."""
    parser.add_argument(
        "folders",
        nargs="*",
        help="One or more host evidence folders to analyze",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama model to use (default: {DEFAULT_MODEL}). Use 'lea-security' for the custom model.",
    )
    parser.add_argument(
        "--output", "-o",
        help="Save report to file (default: print to stdout)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["markdown", "html"],
        default="markdown",
        dest="output_format",
        help="Report output format (default: markdown)",
    )
    parser.add_argument(
        "--ollama-host",
        default="http://localhost:11434",
        help="Ollama API URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Max characters per LLM chunk (default: {DEFAULT_CHUNK_SIZE})",
    )
    parser.add_argument(
        "--kb",
        action="store_true",
        default=False,
        help="Enable knowledge base context enrichment (RAG)",
    )
    parser.add_argument(
        "--kb-dir",
        default=None,
        help="Knowledge base directory (default: ./knowledge_base)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--include-ext",
        nargs="+",
        metavar="EXT",
        help="Only analyze files with these extensions (e.g. .py .sh .txt .conf)",
    )
    parser.add_argument(
        "--exclude-ext",
        nargs="+",
        metavar="EXT",
        help="Skip files with these extensions (e.g. .log .bak .tmp)",
    )
    parser.add_argument(
        "--include-name",
        nargs="+",
        metavar="PATTERN",
        help="Only analyze files matching these names/patterns (e.g. sudoers sshd_config '*.conf')",
    )
    parser.add_argument(
        "--exclude-name",
        nargs="+",
        metavar="PATTERN",
        help="Skip files matching these names/patterns (e.g. '*.log' '*.bak')",
    )
    parser.add_argument(
        "--no-checkpoint",
        action="store_true",
        default=False,
        help="Disable auto-save checkpoint (progress will be lost on crash)",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Resume from a previous checkpoint without prompting",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=1,
        help="Number of parallel file analysis workers (default: 1). "
             "Set higher to utilize more CPU cores with Ollama.",
    )
    parser.add_argument(
        "--live",
        metavar="FILE",
        default=None,
        help="Write a live-updating HTML report to FILE during analysis. "
             "Open it in a browser to watch findings appear in real time.",
    )


def build_model(ollama_host, base_model=None, with_kb=False, kb_dir=None):
    """Build the custom security model from the Modelfile.

    Args:
        ollama_host: Ollama API URL.
        base_model: Override the base model (e.g. 'qwen2.5:32b').
        with_kb: If True, embed knowledge base content into the system prompt.
        kb_dir: Custom knowledge base directory.
    """
    modelfile_path = os.path.join(os.path.dirname(__file__) or ".", "Modelfile")

    if not os.path.exists(modelfile_path):
        print(f"Error: Modelfile not found at {modelfile_path}", file=sys.stderr)
        sys.exit(1)

    # Read the original Modelfile
    with open(modelfile_path, 'r') as f:
        modelfile_content = f.read()

    # Swap the base model if requested
    actual_base = base_model or "llama3.1:8b"
    if base_model:
        modelfile_content = modelfile_content.replace(
            "FROM llama3.1:8b", f"FROM {base_model}", 1
        )
        print(f"Using base model: {base_model}")

    # Embed KB content into the system prompt if requested
    if with_kb:
        kb = KnowledgeBase(kb_dir=kb_dir) if kb_dir else KnowledgeBase()
        kb_content = _load_kb_for_embedding(kb)
        if kb_content:
            # Insert KB reference material before the closing triple-quotes of SYSTEM
            modelfile_content = modelfile_content.replace(
                '\n"""',
                f'\n\nEMBEDDED SECURITY KNOWLEDGE BASE:\n'
                f'Use the following reference material to improve your analysis.\n'
                f'---\n{kb_content}\n---\n"""',
                1,  # only replace the last triple-quote closing SYSTEM
            )
            print(f"Embedded knowledge base into model system prompt")
        else:
            print("Warning: No KB documents found, building without embedded KB.", file=sys.stderr)

    # Write a temporary Modelfile with modifications
    if base_model or with_kb:
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.Modelfile', delete=False)
        tmp.write(modelfile_content)
        tmp.close()
        build_path = tmp.name
    else:
        build_path = modelfile_path

    print(f"Building custom model '{CUSTOM_MODEL_NAME}'...")
    print(f"This requires '{actual_base}' to be already pulled.")
    print()

    try:
        result = subprocess.run(
            ["ollama", "create", CUSTOM_MODEL_NAME, "-f", build_path],
            capture_output=False,
        )
        if result.returncode == 0:
            print(f"\nModel '{CUSTOM_MODEL_NAME}' built successfully!")
            print(f"Use it with: python analyzer.py --model {CUSTOM_MODEL_NAME} /path/to/evidence")
            if with_kb:
                print("KB is embedded — no need for --kb flag at analysis time.")
        else:
            print(f"\nError building model. Make sure Ollama is running and '{actual_base}' is pulled.", file=sys.stderr)
            sys.exit(1)
    except FileNotFoundError:
        print("Error: 'ollama' command not found. Is Ollama installed?", file=sys.stderr)
        sys.exit(1)
    finally:
        # Clean up temp file
        if build_path != modelfile_path:
            os.unlink(build_path)


def _load_kb_for_embedding(kb):
    """Load all KB documents and return their concatenated content for embedding.

    Summarizes each document with a header for clarity inside the system prompt.
    """
    if not os.path.isdir(kb.kb_dir):
        return ""

    parts = []
    for root, _dirs, files in os.walk(kb.kb_dir):
        for filename in sorted(files):
            if filename.startswith('.'):
                continue
            filepath = os.path.join(root, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
            except (UnicodeDecodeError, OSError):
                continue
            if not content:
                continue
            # Use filename (without extension) as a section header
            section_name = os.path.splitext(filename)[0].replace('_', ' ').title()
            parts.append(f"### {section_name}\n{content}")
            print(f"  Embedded: {filename}")

    return "\n\n".join(parts)


def build_kb(kb_dir=None):
    """Build or rebuild the knowledge base index."""
    kb = KnowledgeBase(kb_dir=kb_dir) if kb_dir else KnowledgeBase()
    print(f"Building knowledge base from: {kb.kb_dir}")
    count = kb.build(verbose=True)
    if count == 0:
        print(f"\nNo documents found in {kb.kb_dir}")
        print("Add .txt files with security reference content to this directory.")
    else:
        print(f"\nKnowledge base built: {count} documents indexed")


def _get_kb_context(kb, content, filepath):
    """Build KB context string for a file analysis prompt."""
    # Query with both file content (truncated) and filename for relevance
    query_text = f"{filepath}\n{content[:2000]}"
    results = kb.query(query_text, top_k=3)

    if not results:
        return ""

    context_parts = ["Reference security knowledge:\n---"]
    for r in results:
        context_parts.append(f"[Source: {r['source']}]\n{r['text']}")
    context_parts.append("---\n\nUse the above reference knowledge to inform your analysis.\n\n")

    return "\n".join(context_parts)


def _write_live_report(live_path, raw_findings, hosts, files_done, files_total,
                       skipped_files, is_complete=False):
    """Write an auto-refreshing HTML report atomically."""
    from report import render_live_html
    html = render_live_html(
        raw_findings, hosts, files_done, files_total,
        skipped_files=skipped_files, is_complete=is_complete,
    )
    tmp = live_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(html)
    os.replace(tmp, live_path)


def _generate_report(all_raw_findings, hosts, all_skipped, args, client,
                     partial=False, ckpt_path=None, progress=None):
    """Consolidate findings and render the final report."""
    if partial:
        print(f"\nGenerating partial report with {len(all_raw_findings)} finding(s) collected so far...",
              file=sys.stderr)

    # Phase 2: Consolidation
    if all_raw_findings:
        if progress:
            progress.start_phase2()
        # Restore default signal handling during consolidation so a second
        # Ctrl+C during this phase aborts cleanly
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        consolidated = consolidate_findings(
            client, all_raw_findings, args.model, args.chunk_size
        )
        if progress:
            progress.finish_phase2(len(consolidated))
    else:
        consolidated = []

    # Convert to Finding objects
    findings = findings_from_dicts(consolidated)

    # Render report
    if args.output_format == "html":
        report = render_html(findings, hosts, all_skipped)
    else:
        report = render_markdown(findings, hosts, all_skipped)

    # Stop live display before writing output
    if progress:
        progress.print_final_summary(findings, output_path=args.output)

    # Output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        if not args.verbose:
            print(f"Report saved to {args.output}")
    else:
        print(report)

    # Clean up checkpoint after successful report generation
    if ckpt_path:
        _remove_checkpoint(ckpt_path)


def run_analysis(args):
    """Run the main analysis pipeline."""
    global _interrupted
    _interrupted = False

    if not args.folders:
        print("Error: At least one evidence folder is required.", file=sys.stderr)
        print("Usage: python analyzer.py [analyze] <folder1> [folder2] ...", file=sys.stderr)
        sys.exit(1)

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s",
    )

    # Normalize extension filters (ensure they start with a dot)
    include_ext = None
    exclude_ext = None
    if args.include_ext:
        include_ext = {e if e.startswith('.') else f'.{e}' for e in args.include_ext}
    if args.exclude_ext:
        exclude_ext = {e if e.startswith('.') else f'.{e}' for e in args.exclude_ext}

    # Validate input folders
    for folder in args.folders:
        if not os.path.isdir(folder):
            print(f"Error: Evidence folder not found: {folder}", file=sys.stderr)
            sys.exit(1)

    # Validate --live and --output don't point to same file
    if args.live and args.output:
        if os.path.abspath(args.live) == os.path.abspath(args.output):
            print("Error: --live and --output cannot point to the same file.", file=sys.stderr)
            sys.exit(1)

    # Initialize knowledge base if requested
    kb = None
    if args.kb:
        kb = KnowledgeBase(kb_dir=args.kb_dir) if args.kb_dir else KnowledgeBase()
        if kb.is_available:
            if not kb._loaded:
                kb._load_index()
        else:
            print("Warning: Knowledge base not found. Run 'python analyzer.py build-kb' first.", file=sys.stderr)
            print("Continuing without knowledge base enrichment.", file=sys.stderr)
            kb = None

    # Connect to Ollama
    client = validate_connection(args.ollama_host, args.model)

    # Install Ctrl+C handler for graceful interruption
    signal.signal(signal.SIGINT, _handle_interrupt)

    # Checkpoint setup
    use_checkpoint = not args.no_checkpoint
    ckpt_path = _checkpoint_path(args) if use_checkpoint else None
    processed_files = set()

    # Phase 1: Per-file analysis
    all_raw_findings = []
    all_skipped = []
    hosts = []

    # Check for existing checkpoint to resume from
    if use_checkpoint:
        ckpt_data = _load_checkpoint(ckpt_path, args)
        if ckpt_data:
            n_findings = len(ckpt_data.get("raw_findings", []))
            n_files = len(ckpt_data.get("processed_files", []))
            resume = False
            if args.resume:
                resume = True
            else:
                print(f"\nCheckpoint found: {n_findings} findings from {n_files} files.",
                      file=sys.stderr)
                print(f"  Saved: {ckpt_data.get('saved_at', 'unknown')}", file=sys.stderr)
                print("  [r] Resume from checkpoint", file=sys.stderr)
                print("  [s] Start fresh (discard checkpoint)", file=sys.stderr)
                try:
                    choice = input("Choice [r/s]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    choice = "s"
                resume = choice == "r"

            if resume:
                all_raw_findings = ckpt_data.get("raw_findings", [])
                all_skipped = ckpt_data.get("skipped_files", [])
                hosts = ckpt_data.get("hosts", [])
                processed_files = set(ckpt_data.get("processed_files", []))
                print(f"Resuming: {n_findings} findings, {n_files} files already done.",
                      file=sys.stderr)
            else:
                _remove_checkpoint(ckpt_path)

    # Initialize progress display (use rich when --verbose or output goes to file)
    use_rich = args.verbose or args.output
    if use_rich:
        progress = AnalysisProgress()
    else:
        progress = QuietProgress()

    progress.set_config(
        model=args.model,
        kb_enabled=kb is not None,
        kb_chunks=len(kb.chunks) if kb else 0,
    )
    if use_checkpoint:
        progress.set_checkpoint_status("enabled")
    if processed_files:
        # Preload severity counts from resumed findings
        progress.add_findings(all_raw_findings)

    progress.start()

    # Live report tracking
    live_files_done = len(processed_files)
    live_files_total = 0

    # Write initial (empty) live report so user can open it right away
    if args.live:
        _write_live_report(args.live, all_raw_findings, hosts,
                           live_files_done, live_files_total, all_skipped)
        print(f"Live report: {os.path.abspath(args.live)} (open in browser)",
              file=sys.stderr)

    try:
        for folder in args.folders:
            if _interrupted:
                break

            host_name = os.path.basename(os.path.abspath(folder))
            if host_name not in hosts:
                hosts.append(host_name)

            files, skipped = walk_evidence(folder, include_ext=include_ext,
                                              exclude_ext=exclude_ext,
                                              include_name=args.include_name,
                                              exclude_name=args.exclude_name)
            all_skipped.extend(
                f"{host_name}/{s}" for s in skipped
                if f"{host_name}/{s}" not in all_skipped
            )

            if not files:
                print(f"Warning: No readable text files in {folder}", file=sys.stderr)
                continue

            progress.start_host(host_name, len(files), len(skipped))
            live_files_total += len(files)

            # Filter out already-processed files (checkpoint resume)
            pending_files = []
            for filepath, content in files:
                file_key = f"{host_name}/{filepath}"
                if file_key in processed_files:
                    progress.skip_file(filepath)
                else:
                    pending_files.append((filepath, content))

            num_workers = max(1, args.workers)

            if num_workers <= 1 or len(pending_files) <= 1:
                # Sequential path — original behavior
                for filepath, content in pending_files:
                    if _interrupted:
                        break

                    progress.start_file(filepath)

                    kb_context = ""
                    if kb:
                        kb_context = _get_kb_context(kb, content, filepath)

                    file_findings = []
                    chunks = chunk_content(content, args.chunk_size)
                    for chunk in chunks:
                        if _interrupted:
                            break
                        findings = analyze_file(
                            client, chunk, filepath, host_name, args.model,
                            kb_context=kb_context,
                        )
                        all_raw_findings.extend(findings)
                        file_findings.extend(findings)

                    progress.add_findings(file_findings)
                    progress.finish_file(filepath, len(file_findings))

                    live_files_done += 1
                    if args.live:
                        _write_live_report(args.live, all_raw_findings, hosts,
                                           live_files_done, live_files_total, all_skipped)

                    if use_checkpoint and not _interrupted:
                        processed_files.add(f"{host_name}/{filepath}")
                        _save_checkpoint(ckpt_path, all_raw_findings, all_skipped,
                                         hosts, processed_files, args)
                        progress.set_checkpoint_status("saved")
            else:
                # Parallel path — multiple workers analyze files concurrently
                def _analyze_one_file(filepath, content):
                    """Analyze a single file and return its findings."""
                    kb_context = ""
                    if kb:
                        kb_context = _get_kb_context(kb, content, filepath)

                    file_findings = []
                    chunks = chunk_content(content, args.chunk_size)
                    for chunk in chunks:
                        if _interrupted:
                            break
                        findings = analyze_file(
                            client, chunk, filepath, host_name, args.model,
                            kb_context=kb_context,
                        )
                        file_findings.extend(findings)
                    return filepath, file_findings

                # Mark all pending files as started
                for filepath, _ in pending_files:
                    progress.start_file(filepath)

                with ThreadPoolExecutor(max_workers=num_workers) as executor:
                    future_to_file = {
                        executor.submit(_analyze_one_file, fp, content): fp
                        for fp, content in pending_files
                    }

                    for future in as_completed(future_to_file):
                        if _interrupted:
                            break

                        filepath, file_findings = future.result()
                        all_raw_findings.extend(file_findings)

                        progress.add_findings(file_findings)
                        progress.finish_file(filepath, len(file_findings))

                        live_files_done += 1
                        if args.live:
                            _write_live_report(args.live, all_raw_findings, hosts,
                                               live_files_done, live_files_total, all_skipped)

                        if use_checkpoint and not _interrupted:
                            processed_files.add(f"{host_name}/{filepath}")
                            _save_checkpoint(ckpt_path, all_raw_findings, all_skipped,
                                             hosts, processed_files, args)
                            progress.set_checkpoint_status("saved")

        _generate_report(all_raw_findings, hosts, all_skipped, args, client,
                         partial=_interrupted, ckpt_path=ckpt_path, progress=progress)

        # Final live report write (remove auto-refresh, show "complete")
        if args.live:
            _write_live_report(args.live, all_raw_findings, hosts,
                               live_files_done, live_files_total, all_skipped,
                               is_complete=True)
    finally:
        progress.stop()


def main():
    args = parse_args()

    if args.command == "build-model":
        build_model(
            args.ollama_host,
            base_model=args.base_model,
            with_kb=args.with_kb,
            kb_dir=getattr(args, 'kb_dir', None),
        )
    elif args.command == "build-kb":
        build_kb(getattr(args, 'kb_dir', None))
    else:
        run_analysis(args)


if __name__ == "__main__":
    main()
