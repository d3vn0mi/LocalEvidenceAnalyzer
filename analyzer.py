#!/usr/bin/env python3
"""LocalEvidenceAnalyzer - Security evidence analysis using local LLMs."""

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
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


def build_model(ollama_host):
    """Build the custom security model from the Modelfile."""
    modelfile_path = os.path.join(os.path.dirname(__file__) or ".", "Modelfile")

    if not os.path.exists(modelfile_path):
        print(f"Error: Modelfile not found at {modelfile_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Building custom model '{CUSTOM_MODEL_NAME}' from {modelfile_path}...")
    print("This requires 'llama3.1:8b' to be already pulled.")
    print()

    try:
        result = subprocess.run(
            ["ollama", "create", CUSTOM_MODEL_NAME, "-f", modelfile_path],
            capture_output=False,
        )
        if result.returncode == 0:
            print(f"\nModel '{CUSTOM_MODEL_NAME}' built successfully!")
            print(f"Use it with: python analyzer.py --model {CUSTOM_MODEL_NAME} /path/to/evidence")
        else:
            print(f"\nError building model. Make sure Ollama is running and llama3.1:8b is pulled.", file=sys.stderr)
            sys.exit(1)
    except FileNotFoundError:
        print("Error: 'ollama' command not found. Is Ollama installed?", file=sys.stderr)
        sys.exit(1)


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


def _generate_report(all_raw_findings, hosts, all_skipped, args, client,
                     partial=False, ckpt_path=None):
    """Consolidate findings and render the final report."""
    if partial:
        print(f"\nGenerating partial report with {len(all_raw_findings)} finding(s) collected so far...",
              file=sys.stderr)

    # Phase 2: Consolidation
    if all_raw_findings:
        if args.verbose:
            print("Consolidating and deduplicating findings...")
        # Restore default signal handling during consolidation so a second
        # Ctrl+C during this phase aborts cleanly
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        consolidated = consolidate_findings(
            client, all_raw_findings, args.model, args.chunk_size
        )
        if args.verbose:
            print(f"Consolidated to {len(consolidated)} findings")
    else:
        consolidated = []

    # Convert to Finding objects
    findings = findings_from_dicts(consolidated)

    # Render report
    if args.output_format == "html":
        report = render_html(findings, hosts, all_skipped)
    else:
        report = render_markdown(findings, hosts, all_skipped)

    # Output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
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

    # Validate input folders
    for folder in args.folders:
        if not os.path.isdir(folder):
            print(f"Error: Evidence folder not found: {folder}", file=sys.stderr)
            sys.exit(1)

    # Initialize knowledge base if requested
    kb = None
    if args.kb:
        kb = KnowledgeBase(kb_dir=args.kb_dir) if args.kb_dir else KnowledgeBase()
        if kb.is_available:
            if not kb._loaded:
                kb._load_index()
            if args.verbose:
                print(f"Knowledge base loaded: {len(kb.chunks)} chunks")
        else:
            print("Warning: Knowledge base not found. Run 'python analyzer.py build-kb' first.", file=sys.stderr)
            print("Continuing without knowledge base enrichment.", file=sys.stderr)
            kb = None

    # Connect to Ollama
    if args.verbose:
        print(f"Connecting to Ollama at {args.ollama_host}...")
    client = validate_connection(args.ollama_host, args.model)
    if args.verbose:
        print(f"Using model: {args.model}")

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

    for folder in args.folders:
        if _interrupted:
            break

        host_name = os.path.basename(os.path.abspath(folder))
        if host_name not in hosts:
            hosts.append(host_name)

        if args.verbose:
            print(f"\n--- Analyzing host: {host_name} ({folder}) ---")

        files, skipped = walk_evidence(folder)
        all_skipped.extend(
            f"{host_name}/{s}" for s in skipped
            if f"{host_name}/{s}" not in all_skipped
        )

        if not files:
            print(f"Warning: No readable text files in {folder}", file=sys.stderr)
            continue

        if args.verbose:
            print(f"Found {len(files)} text files ({len(skipped)} skipped)")

        for i, (filepath, content) in enumerate(files, 1):
            if _interrupted:
                break

            # Skip files already processed in a resumed checkpoint
            file_key = f"{host_name}/{filepath}"
            if file_key in processed_files:
                if args.verbose:
                    print(f"  [{i}/{len(files)}] Skipping {filepath} (already in checkpoint)")
                continue

            if args.verbose:
                print(f"  [{i}/{len(files)}] Analyzing {filepath}...")

            # Get KB context if available
            kb_context = ""
            if kb:
                kb_context = _get_kb_context(kb, content, filepath)
                if args.verbose and kb_context:
                    print(f"    Knowledge base context injected")

            chunks = chunk_content(content, args.chunk_size)
            for chunk_idx, chunk in enumerate(chunks):
                if _interrupted:
                    break

                if args.verbose and len(chunks) > 1:
                    print(f"    Chunk {chunk_idx + 1}/{len(chunks)}")

                findings = analyze_file(
                    client, chunk, filepath, host_name, args.model,
                    kb_context=kb_context,
                )
                all_raw_findings.extend(findings)

                if args.verbose and findings:
                    print(f"    Found {len(findings)} finding(s)")

            # Save checkpoint after each file completes
            if use_checkpoint and not _interrupted:
                processed_files.add(file_key)
                _save_checkpoint(ckpt_path, all_raw_findings, all_skipped,
                                 hosts, processed_files, args)
                if args.verbose:
                    print(f"    Checkpoint saved ({len(all_raw_findings)} findings)")

    if args.verbose and not _interrupted:
        print(f"\n--- Phase 1 complete: {len(all_raw_findings)} raw findings ---")

    _generate_report(all_raw_findings, hosts, all_skipped, args, client,
                     partial=_interrupted, ckpt_path=ckpt_path)


def main():
    args = parse_args()

    if args.command == "build-model":
        build_model(args.ollama_host)
    elif args.command == "build-kb":
        build_kb(getattr(args, 'kb_dir', None))
    else:
        run_analysis(args)


if __name__ == "__main__":
    main()
