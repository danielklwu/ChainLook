"""Aggregation layer.

Combines scraped page content into a compact, high-signal text payload
for the Gemini prompt. Uses keyword-proximity scoring to surface the
most relevant sentences rather than naively truncating.
"""

from __future__ import annotations

import logging
import re
from typing import Sequence

from chaintrace.models import ScrapedPage

logger = logging.getLogger(__name__)

MAX_CHARS_PER_PAGE = 1_000

_LIFECYCLE_KEYWORDS = frozenset({
    "eol", "end-of-life", "end of life", "obsolete",
    "discontinued", "legacy", "last time buy", "not recommended for new designs",
})
_DATASHEET_KEYWORDS = frozenset({"datasheet", "technical reference", "product brief"})
_ORIGIN_KEYWORDS = frozenset({
    "manufacturer", "made in", "country of origin", "fabricated", "foundry", "fab ",
})


def aggregate(pages: Sequence[ScrapedPage], query: str = "") -> str:
    """Merge successful scrape results into one consolidated text block.

    Uses :func:`smart_extract` to surface the most relevant sentences
    per page, keeping the total prompt payload small.

    Args:
        pages: Scraped pages returned by :func:`~chaintrace.lookup.scraper.scrape`.
        query: Original component marking — used to score sentence relevance.

    Returns:
        A single string suitable for inclusion in the Gemini prompt.
    """
    query_tokens = [t for t in re.split(r"[\s\\n]+", query) if len(t) > 1]

    sections: list[str] = []
    for page in pages:
        if not page.success:
            continue
        body = smart_extract(page.text, query_tokens)
        sections.append(f"--- Source: {page.url} ---\n{body}")

    if not sections:
        logger.warning("No successful pages to aggregate.")
        return ""

    return "\n\n".join(sections)


def smart_extract(text: str, query_tokens: list[str], max_chars: int = MAX_CHARS_PER_PAGE) -> str:
    """Extract the highest-signal sentences from *text*.

    Sentences are scored by:
    - Query token hits  (+2 each)
    - Lifecycle keywords like EOL, obsolete  (+3)
    - Datasheet mentions  (+2)
    - Manufacturer/origin mentions  (+2)
    - URL presence  (+1)

    The top-scoring sentences are greedily selected until *max_chars* is reached.

    Args:
        text:         Plain text from a scraped page.
        query_tokens: Tokens derived from the component marking query.
        max_chars:    Character budget for the extracted output.

    Returns:
        A compact string of the most relevant content.
    """
    if not text:
        return ""

    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if len(s.strip()) >= 20]
    if not sentences:
        return text[:max_chars]

    scored: list[tuple[int, str]] = []
    for sentence in sentences:
        sent_lower = sentence.lower()
        score = 0

        for token in query_tokens:
            if token.lower() in sent_lower:
                score += 2

        if any(kw in sent_lower for kw in _LIFECYCLE_KEYWORDS):
            score += 3

        if any(kw in sent_lower for kw in _DATASHEET_KEYWORDS):
            score += 2

        if any(kw in sent_lower for kw in _ORIGIN_KEYWORDS):
            score += 2

        if "http" in sent_lower:
            score += 1

        scored.append((score, sentence))

    scored.sort(key=lambda x: x[0], reverse=True)

    result_parts: list[str] = []
    total_chars = 0
    for _, sentence in scored:
        if total_chars >= max_chars:
            break
        remaining = max_chars - total_chars
        if len(sentence) > remaining:
            if remaining > 60:
                result_parts.append(sentence[:remaining] + "…")
            break
        result_parts.append(sentence)
        total_chars += len(sentence) + 1

    return " ".join(result_parts) if result_parts else text[:max_chars]
