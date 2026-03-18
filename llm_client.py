"""Ollama LLM client for security evidence analysis."""

import json
import logging
import re
import sys

import ollama

from prompts import SYSTEM_PROMPT, PHASE1_PROMPT_TEMPLATE, PHASE2_PROMPT_TEMPLATE

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_CHUNK_SIZE = 50000


def validate_connection(host, model):
    """Validate Ollama is running and the model is available."""
    try:
        client = ollama.Client(host=host)
        models = client.list()
        model_names = []
        for m in models.get("models", []):
            model_names.append(m.get("name", ""))
            # Also match without tag (e.g. "llama3.1:8b" matches "llama3.1:8b-instruct-...")
            base = m.get("name", "").split(":")[0]
            model_names.append(base)

        # Check if the requested model (or its base name) is available
        model_base = model.split(":")[0]
        found = any(
            model in name or model_base == name.split(":")[0]
            for name in model_names
        )
        if not found:
            print(f"Error: Model '{model}' not found locally.", file=sys.stderr)
            print(f"Pull it with: ollama pull {model}", file=sys.stderr)
            print(f"Available models: {', '.join(m.get('name', '') for m in models.get('models', []))}", file=sys.stderr)
            sys.exit(1)

        return client
    except Exception as e:
        if "connection" in str(e).lower() or "refused" in str(e).lower():
            print(f"Error: Cannot connect to Ollama at {host}", file=sys.stderr)
            print("Is Ollama running? Start it with: ollama serve", file=sys.stderr)
        else:
            print(f"Error connecting to Ollama: {e}", file=sys.stderr)
        sys.exit(1)


def chunk_content(content, max_chars=DEFAULT_CHUNK_SIZE):
    """Split content into chunks on line boundaries."""
    if len(content) <= max_chars:
        return [content]

    chunks = []
    lines = content.splitlines(keepends=True)
    current_chunk = []
    current_size = 0

    for line in lines:
        if current_size + len(line) > max_chars and current_chunk:
            chunks.append("".join(current_chunk))
            current_chunk = []
            current_size = 0
        current_chunk.append(line)
        current_size += len(line)

    if current_chunk:
        chunks.append("".join(current_chunk))

    return chunks


def parse_json_response(text):
    """Extract JSON array from LLM response with multiple fallback strategies."""
    text = text.strip()

    # Strategy 1: Direct parse
    try:
        result = json.loads(text)
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return [result]
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract from markdown code fences
    fence_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', text, re.DOTALL)
    if fence_match:
        try:
            result = json.loads(fence_match.group(1).strip())
            if isinstance(result, list):
                return result
            if isinstance(result, dict):
                return [result]
        except json.JSONDecodeError:
            pass

    # Strategy 3: Find [...] substring
    bracket_match = re.search(r'\[.*\]', text, re.DOTALL)
    if bracket_match:
        try:
            result = json.loads(bracket_match.group(0))
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    # Strategy 4: Find {...} and wrap in array
    brace_match = re.search(r'\{.*\}', text, re.DOTALL)
    if brace_match:
        try:
            result = json.loads(brace_match.group(0))
            if isinstance(result, dict):
                return [result]
        except json.JSONDecodeError:
            pass

    logger.warning("Failed to parse JSON from LLM response: %s...", text[:200])
    return []


def analyze_file(client, content, filepath, host_name, model, kb_context=""):
    """Phase 1: Analyze a single file (or chunk) for security findings."""
    prompt = PHASE1_PROMPT_TEMPLATE.format(
        host_name=host_name,
        filepath=filepath,
        content=content,
        kb_context=kb_context,
    )

    try:
        response = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return parse_json_response(response["message"]["content"])
    except Exception as e:
        logger.warning("LLM error analyzing %s: %s", filepath, e)
        return []


def consolidate_findings(client, findings, model, chunk_size=DEFAULT_CHUNK_SIZE):
    """Phase 2: Deduplicate, rank, and refine findings."""
    if not findings:
        return []

    findings_json = json.dumps(findings, indent=2)

    # If findings fit in one prompt, do a single consolidation call
    if len(findings_json) <= chunk_size:
        return _consolidate_batch(client, findings_json, model)

    # Otherwise, batch the consolidation
    batches = []
    current_batch = []
    current_size = 0

    for finding in findings:
        finding_str = json.dumps(finding)
        if current_size + len(finding_str) > chunk_size and current_batch:
            batches.append(current_batch)
            current_batch = []
            current_size = 0
        current_batch.append(finding)
        current_size += len(finding_str)

    if current_batch:
        batches.append(current_batch)

    # Consolidate each batch
    intermediate = []
    for batch in batches:
        batch_json = json.dumps(batch, indent=2)
        result = _consolidate_batch(client, batch_json, model)
        intermediate.extend(result)

    # Final consolidation pass if we had multiple batches
    if len(batches) > 1:
        final_json = json.dumps(intermediate, indent=2)
        if len(final_json) <= chunk_size:
            return _consolidate_batch(client, final_json, model)

    return intermediate


def _consolidate_batch(client, findings_json, model):
    """Run a single consolidation prompt."""
    prompt = PHASE2_PROMPT_TEMPLATE.format(findings_json=findings_json)

    try:
        response = client.chat(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        return parse_json_response(response["message"]["content"])
    except Exception as e:
        logger.warning("LLM error during consolidation: %s", e)
        return []
