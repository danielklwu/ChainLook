"""Local cache manager.

Persists full lookup records to disk under ./cache/<normalized_part_number>.json
for research reproducibility.  Each entry stores raw scraped text, the Gemini
prompt, the Gemini response, and the final structured result.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

from chaintrace.models import CacheEntry, ComponentResult

logger = logging.getLogger(__name__)

DEFAULT_CACHE_DIR = Path("cache")


def get_cache_path(normalized_part_number: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> Path:
    """Return the file path for a given part number's cache entry.

    Args:
        normalized_part_number: Normalised part identifier used as filename.
        cache_dir:              Directory where cache files are stored.

    Returns:
        A :class:`~pathlib.Path` pointing to ``<cache_dir>/<part>.json``.
    """
    safe_name = re.sub(r"[^\w\-.]", "_", normalized_part_number)
    return cache_dir / f"{safe_name}.json"


def save(entry: CacheEntry, cache_dir: Path = DEFAULT_CACHE_DIR) -> Path:
    """Serialise *entry* to JSON and write it to the cache directory.

    Args:
        entry:     Full :class:`~chaintrace.models.CacheEntry` to persist.
        cache_dir: Target cache directory.

    Returns:
        The :class:`~pathlib.Path` of the written file.

    Raises:
        OSError: If the file cannot be written.
    """
    path = get_cache_path(entry.normalized_part_number, cache_dir)
    os.makedirs(cache_dir, exist_ok=True)

    data = {
        "query": entry.query,
        "normalized_part_number": entry.normalized_part_number,
        "search_results": [
            {"url": r.url, "title": r.title, "snippet": r.snippet}
            for r in entry.search_results
        ],
        "scraped_pages": [
            {"url": p.url, "text": p.text, "success": p.success, "error": p.error}
            for p in entry.scraped_pages
        ],
        "gemini_prompt": entry.gemini_prompt,
        "gemini_response": entry.gemini_response,
        "component_result": entry.component_result.to_dict(),
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

    logger.debug("Cached result to %s", path)
    return path


def load(normalized_part_number: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> ComponentResult | None:
    """Load a cached :class:`~chaintrace.models.ComponentResult` if it exists.

    Args:
        normalized_part_number: Part identifier to look up.
        cache_dir:              Directory to search for cached files.

    Returns:
        A :class:`~chaintrace.models.ComponentResult` if a cache hit is found,
        otherwise ``None``.
    """
    path = get_cache_path(normalized_part_number, cache_dir)
    if not path.exists():
        return None

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    cr = data["component_result"]
    return ComponentResult(
        input_query=cr["input_query"],
        normalized_part_number=cr["normalized_part_number"],
        component_type=cr["component_type"],
        manufacturer=cr["manufacturer"],
        manufacturer_country=cr["manufacturer_country"],
        datasheet_url=cr["datasheet_url"],
        description=cr["description"],
        risk_indicators=cr.get("risk_indicators", []),
        confidence_score=float(cr.get("confidence_score", 0.0)),
    )


def exists(normalized_part_number: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> bool:
    """Return ``True`` if a cache entry exists for *normalized_part_number*.

    Args:
        normalized_part_number: Part identifier to check.
        cache_dir:              Directory to search.
    """
    return get_cache_path(normalized_part_number, cache_dir).exists()
