"""Recursive directory walker with binary file detection."""

import fnmatch
import os
import logging

logger = logging.getLogger(__name__)

BINARY_EXTENSIONS = {
    '.bin', '.exe', '.dll', '.so', '.o', '.pyc', '.pyo', '.class',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.tiff', '.webp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.gz', '.tar', '.bz2', '.xz', '.7z', '.rar',
    '.db', '.sqlite', '.sqlite3', '.mdb',
    '.iso', '.img', '.vmdk', '.qcow2',
    '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac',
    '.woff', '.woff2', '.ttf', '.eot',
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


def is_binary(filepath):
    """Check if a file is binary using extension and content heuristics."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext in BINARY_EXTENSIONS:
        return True

    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(8192)
            if b'\x00' in chunk:
                return True
    except (OSError, IOError):
        return True

    return False


def read_text_file(filepath):
    """Read a text file, returning None if it cannot be decoded."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='strict') as f:
            return f.read()
    except UnicodeDecodeError:
        # Try latin-1 as fallback (never fails but may produce garbage)
        try:
            with open(filepath, 'r', encoding='latin-1') as f:
                return f.read()
        except (OSError, IOError):
            return None
    except (OSError, IOError):
        return None


def _matches_any_pattern(filename, patterns):
    """Check if filename matches any of the given glob patterns."""
    for pattern in patterns:
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


def walk_evidence(folder, include_ext=None, exclude_ext=None,
                  include_name=None, exclude_name=None):
    """
    Walk an evidence folder recursively and yield (relative_path, content) tuples.

    Args:
        folder: Path to the evidence folder.
        include_ext: If set, only include files with these extensions (e.g. {'.py', '.sh', '.txt'}).
        exclude_ext: If set, skip files with these extensions.
        include_name: If set, only include files matching these glob patterns (e.g. ['sudoers', '*.conf']).
        exclude_name: If set, skip files matching these glob patterns.

    When both include_name and include_ext are specified, a file passes if it
    matches either filter (OR logic).

    Returns:
        list of (relative_path, content) tuples
        list of skipped file descriptions
    """
    results = []
    skipped = []

    folder = os.path.abspath(folder)

    for root, _dirs, files in os.walk(folder):
        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            relpath = os.path.relpath(filepath, folder)
            ext = os.path.splitext(filename)[1].lower()

            # Exclude by name pattern (always checked first)
            if exclude_name and _matches_any_pattern(filename, exclude_name):
                skipped.append(f"{relpath} (excluded by name filter)")
                continue

            # Include filtering: name patterns and/or extension
            if include_name and include_ext:
                # OR logic: pass if name matches OR extension matches
                name_ok = _matches_any_pattern(filename, include_name)
                ext_ok = ext in include_ext or (ext == '' and '' in include_ext)
                if not name_ok and not ext_ok:
                    skipped.append(f"{relpath} (excluded by filter)")
                    continue
            elif include_name:
                if not _matches_any_pattern(filename, include_name):
                    skipped.append(f"{relpath} (excluded by name filter)")
                    continue
            elif include_ext:
                if ext not in include_ext:
                    if ext != '' or '' not in include_ext:
                        skipped.append(f"{relpath} (excluded by filter)")
                        continue

            if exclude_ext and ext in exclude_ext:
                skipped.append(f"{relpath} (excluded by filter)")
                continue

            # Check file size
            try:
                size = os.path.getsize(filepath)
            except OSError:
                skipped.append(f"{relpath} (cannot read)")
                continue

            if size > MAX_FILE_SIZE:
                size_mb = size / (1024 * 1024)
                skipped.append(f"{relpath} (too large: {size_mb:.1f}MB)")
                logger.warning("Skipping large file (%0.1fMB): %s", size_mb, relpath)
                continue

            if size == 0:
                skipped.append(f"{relpath} (empty)")
                continue

            # Check if binary
            if is_binary(filepath):
                skipped.append(f"{relpath} (binary)")
                logger.debug("Skipping binary file: %s", relpath)
                continue

            # Read content
            content = read_text_file(filepath)
            if content is None:
                skipped.append(f"{relpath} (unreadable)")
                continue

            results.append((relpath, content))

    return results, skipped
