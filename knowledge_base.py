"""RAG knowledge base for enriching security analysis with reference documents."""

import hashlib
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Default location for the knowledge base index
DEFAULT_KB_DIR = os.path.join(os.path.dirname(__file__), "knowledge_base")
DEFAULT_INDEX_PATH = os.path.join(os.path.dirname(__file__), ".kb_index.json")

# Chunk size for splitting knowledge base documents
KB_CHUNK_SIZE = 1000  # characters per chunk
KB_CHUNK_OVERLAP = 200  # overlap between chunks


def _chunk_text(text, chunk_size=KB_CHUNK_SIZE, overlap=KB_CHUNK_OVERLAP):
    """Split text into overlapping chunks on line boundaries."""
    lines = text.splitlines(keepends=True)
    chunks = []
    current = []
    current_size = 0

    for line in lines:
        current.append(line)
        current_size += len(line)

        if current_size >= chunk_size:
            chunks.append("".join(current))
            # Keep overlap lines
            overlap_lines = []
            overlap_size = 0
            for prev_line in reversed(current):
                if overlap_size + len(prev_line) > overlap:
                    break
                overlap_lines.insert(0, prev_line)
                overlap_size += len(prev_line)
            current = overlap_lines
            current_size = overlap_size

    if current:
        chunks.append("".join(current))

    return chunks


def _simple_hash(text):
    """Hash text for deduplication."""
    return hashlib.md5(text.encode()).hexdigest()[:12]


def _tokenize(text):
    """Simple word tokenization for keyword matching."""
    import re
    return set(re.findall(r'[a-zA-Z0-9_\-\.\/]{2,}', text.lower()))


class KnowledgeBase:
    """Simple keyword-based knowledge base using an inverted index.

    No heavy dependencies (no chromadb/faiss). Uses TF-based keyword matching
    for retrieval, which works well for security content where specific terms
    (CVE IDs, config directives, service names) are highly discriminative.
    """

    def __init__(self, kb_dir=None, index_path=None):
        self.kb_dir = kb_dir or DEFAULT_KB_DIR
        self.index_path = index_path or DEFAULT_INDEX_PATH
        self.chunks = []       # list of {"id", "text", "source", "tokens"}
        self.inverted = {}     # token -> set of chunk indices
        self._loaded = False

    def build(self, verbose=False):
        """Build the index from documents in kb_dir."""
        if not os.path.isdir(self.kb_dir):
            logger.warning("Knowledge base directory not found: %s", self.kb_dir)
            return 0

        self.chunks = []
        self.inverted = {}

        doc_count = 0
        for root, _dirs, files in os.walk(self.kb_dir):
            for filename in sorted(files):
                filepath = os.path.join(root, filename)
                relpath = os.path.relpath(filepath, self.kb_dir)

                # Skip hidden files and non-text
                if filename.startswith('.'):
                    continue

                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        content = f.read()
                except (UnicodeDecodeError, OSError):
                    continue

                if not content.strip():
                    continue

                doc_count += 1
                text_chunks = _chunk_text(content)

                for chunk_text in text_chunks:
                    idx = len(self.chunks)
                    tokens = _tokenize(chunk_text)
                    self.chunks.append({
                        "id": _simple_hash(chunk_text),
                        "text": chunk_text.strip(),
                        "source": relpath,
                        "tokens": tokens,
                    })
                    for token in tokens:
                        if token not in self.inverted:
                            self.inverted[token] = set()
                        self.inverted[token].add(idx)

                if verbose:
                    print(f"  Indexed: {relpath} ({len(text_chunks)} chunks)")

        self._loaded = True
        self._save_index()

        if verbose:
            print(f"Knowledge base: {doc_count} documents, {len(self.chunks)} chunks indexed")

        return doc_count

    def _save_index(self):
        """Save the index to disk for faster loading."""
        data = {
            "chunks": [
                {"id": c["id"], "text": c["text"], "source": c["source"]}
                for c in self.chunks
            ],
        }
        try:
            with open(self.index_path, 'w') as f:
                json.dump(data, f)
        except OSError as e:
            logger.warning("Could not save index: %s", e)

    def _load_index(self):
        """Load a previously built index."""
        if self._loaded:
            return True

        if not os.path.exists(self.index_path):
            return False

        try:
            with open(self.index_path, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return False

        self.chunks = []
        self.inverted = {}

        for chunk_data in data.get("chunks", []):
            idx = len(self.chunks)
            tokens = _tokenize(chunk_data["text"])
            self.chunks.append({
                "id": chunk_data["id"],
                "text": chunk_data["text"],
                "source": chunk_data["source"],
                "tokens": tokens,
            })
            for token in tokens:
                if token not in self.inverted:
                    self.inverted[token] = set()
                self.inverted[token].add(idx)

        self._loaded = True
        return len(self.chunks) > 0

    def query(self, text, top_k=5):
        """Find the most relevant knowledge base chunks for given text.

        Uses TF-based scoring: chunks with the most matching tokens score highest.
        """
        if not self._loaded:
            if not self._load_index():
                return []

        query_tokens = _tokenize(text)
        if not query_tokens:
            return []

        # Score each chunk by number of matching tokens
        scores = {}
        for token in query_tokens:
            for idx in self.inverted.get(token, set()):
                scores[idx] = scores.get(idx, 0) + 1

        if not scores:
            return []

        # Sort by score descending, take top_k
        ranked = sorted(scores.items(), key=lambda x: -x[1])[:top_k]

        results = []
        for idx, score in ranked:
            chunk = self.chunks[idx]
            results.append({
                "text": chunk["text"],
                "source": chunk["source"],
                "relevance_score": score,
            })

        return results

    @property
    def is_available(self):
        """Check if a knowledge base is available (either in memory or on disk)."""
        if self._loaded and self.chunks:
            return True
        return os.path.exists(self.index_path)
