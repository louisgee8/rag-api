"""
Recursive character text splitter.

Why recursive (not fixed-size):
- Fixed-size cuts mid-sentence and mid-word, degrading retrieval quality.
- Recursive tries to split on the LARGEST semantic boundary that fits
  (paragraph -> line -> sentence -> word -> char), so chunks end on natural
  edges when possible.

Why overlap:
- A query about "API rate limit" might find a chunk ending "...the API has
  a rate limit of" with the answer "100 requests per minute" in the NEXT
  chunk. Overlap (~10% of chunk_size) repeats the prior tail so concepts
  don't get cleaved at boundaries.

Mirrors the behavior of LangChain's RecursiveCharacterTextSplitter for
portability without taking on a heavy dependency.
"""

import os

# Largest semantic unit first. Empty string is the last-resort char split.
DEFAULT_SEPARATORS = ["\n\n", "\n", ". ", " ", ""]


def recursive_split(
    text: str,
    chunk_size: int | None = None,
    chunk_overlap: int | None = None,
    separators: list[str] | None = None,
) -> list[str]:
    """
    Split `text` into chunks of <= chunk_size chars with chunk_overlap overlap.

    Defaults pulled from env (CHUNK_SIZE, CHUNK_OVERLAP). Pure function — no
    side effects, fully unit-testable.
    """
    if chunk_size is None:
        chunk_size = int(os.environ.get("CHUNK_SIZE", "500"))
    if chunk_overlap is None:
        chunk_overlap = int(os.environ.get("CHUNK_OVERLAP", "50"))
    if separators is None:
        separators = DEFAULT_SEPARATORS

    text = text.strip()
    if not text:
        return []
    if len(text) <= chunk_size:
        return [text]

    # Pick the first separator that actually appears in this text.
    # Empty-string separator (char split) always "appears" — last-resort fallback.
    sep = separators[-1]
    sep_idx = len(separators) - 1
    for i, candidate in enumerate(separators):
        if candidate == "" or candidate in text:
            sep = candidate
            sep_idx = i
            break

    # Split on the chosen separator.
    pieces = list(text) if sep == "" else text.split(sep)

    # For pieces still too long, recurse with finer separators.
    finer = separators[sep_idx + 1:]
    expanded: list[str] = []
    for piece in pieces:
        if not piece:
            continue
        if len(piece) <= chunk_size:
            expanded.append(piece)
        elif finer:
            expanded.extend(
                recursive_split(piece, chunk_size, chunk_overlap, finer)
            )
        else:
            # Truly nowhere left to split — hard char chop.
            expanded.extend(piece[i:i + chunk_size] for i in range(0, len(piece), chunk_size))

    # Greedy merge small pieces back up to ~chunk_size, carrying overlap.
    return _merge_with_overlap(expanded, sep, chunk_size, chunk_overlap)


def _merge_with_overlap(
    pieces: list[str],
    separator: str,
    chunk_size: int,
    chunk_overlap: int,
) -> list[str]:
    """
    Greedily concatenate adjacent pieces up to chunk_size, then start a new
    chunk seeded with the last chunk_overlap chars of the previous one.
    """
    chunks: list[str] = []
    current = ""
    # Glue is the separator we just split on (preserve original spacing).
    # If sep is "" (char-level), don't reinsert anything between pieces.
    glue = separator if separator else ""

    for piece in pieces:
        if not current:
            current = piece
            continue
        candidate = current + glue + piece
        if len(candidate) <= chunk_size:
            current = candidate
        else:
            chunks.append(current)
            tail = current[-chunk_overlap:] if chunk_overlap > 0 else ""
            current = (tail + glue + piece) if tail else piece

    if current:
        chunks.append(current)
    return chunks
