#!/usr/bin/env python3
"""LocalEvidenceAnalyzer - Security evidence analysis using local LLMs."""

import argparse
import logging
import os
import subprocess
import sys

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


def run_analysis(args):
    """Run the main analysis pipeline."""
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

    # Phase 1: Per-file analysis
    all_raw_findings = []
    all_skipped = []
    hosts = []

    for folder in args.folders:
        host_name = os.path.basename(os.path.abspath(folder))
        hosts.append(host_name)

        if args.verbose:
            print(f"\n--- Analyzing host: {host_name} ({folder}) ---")

        files, skipped = walk_evidence(folder)
        all_skipped.extend(f"{host_name}/{s}" for s in skipped)

        if not files:
            print(f"Warning: No readable text files in {folder}", file=sys.stderr)
            continue

        if args.verbose:
            print(f"Found {len(files)} text files ({len(skipped)} skipped)")

        for i, (filepath, content) in enumerate(files, 1):
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
                if args.verbose and len(chunks) > 1:
                    print(f"    Chunk {chunk_idx + 1}/{len(chunks)}")

                findings = analyze_file(
                    client, chunk, filepath, host_name, args.model,
                    kb_context=kb_context,
                )
                all_raw_findings.extend(findings)

                if args.verbose and findings:
                    print(f"    Found {len(findings)} finding(s)")

    if args.verbose:
        print(f"\n--- Phase 1 complete: {len(all_raw_findings)} raw findings ---")

    # Phase 2: Consolidation
    if all_raw_findings:
        if args.verbose:
            print("Consolidating and deduplicating findings...")
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
