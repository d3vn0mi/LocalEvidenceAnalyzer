#!/usr/bin/env python3
"""LocalEvidenceAnalyzer - Security evidence analysis using local LLMs."""

import argparse
import logging
import os
import sys

from file_walker import walk_evidence
from llm_client import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MODEL,
    analyze_file,
    chunk_content,
    consolidate_findings,
    validate_connection,
)
from report import findings_from_dicts, render_html, render_markdown


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze security evidence folders using a local LLM and generate a findings report.",
        epilog="Example: python analyzer.py /evidence/host1 /evidence/host2 --output report.md",
    )
    parser.add_argument(
        "folders",
        nargs="+",
        help="One or more host evidence folders to analyze",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama model to use (default: {DEFAULT_MODEL})",
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
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    return parser.parse_args()


def main():
    args = parse_args()

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

            chunks = chunk_content(content, args.chunk_size)
            for chunk_idx, chunk in enumerate(chunks):
                if args.verbose and len(chunks) > 1:
                    print(f"    Chunk {chunk_idx + 1}/{len(chunks)}")

                findings = analyze_file(client, chunk, filepath, host_name, args.model)
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


if __name__ == "__main__":
    main()
