"""Search API layer.

Uses SerpAPI's Google Light engine to retrieve the top N organic results
for a given component marking query.

Required environment variable:
    SERPAPI_KEY: Your SerpAPI private key.

Optional environment variable:
    CHAINTRACE_SEARCH_TOP_N: Override the default number of results (default 3).
"""

from __future__ import annotations

import logging
import os
import re

import requests
from dotenv import load_dotenv

from chaintrace.models import SearchResult

load_dotenv()

logger = logging.getLogger(__name__)

_SERPAPI_URL = "https://serpapi.com/search.json"

TOP_N = 3

_CONTEXT_KEYWORDS = "datasheet component IC"


def build_query(marking: str) -> str:
    """Normalise a board marking into a search-engine query string.

    Steps performed:
    1. Replace literal newlines and ``\\n`` sequences with a single space.
    2. Collapse runs of whitespace into a single space.
    3. Strip leading/trailing whitespace.
    4. Append :data:`_CONTEXT_KEYWORDS` to steer results toward datasheets.

    Args:
        marking: Raw multi-line component marking entered by the user.

    Returns:
        A cleaned, single-line query string suitable for a search API.

    Example:
        >>> build_query("DAC\\n32031\\nTI 69K\\nCJ22")
        'DAC 32031 TI 69K CJ22 datasheet component IC'
    """
    normalised = marking.replace("\\n", " ").replace("\n", " ")
    normalised = re.sub(r"\s+", " ", normalised).strip()
    return f"{normalised} {_CONTEXT_KEYWORDS}"


def search(query: str, top_n: int = TOP_N) -> list[SearchResult]:
    """Run a web search via SerpAPI (Google Light engine) and return the top N results.

    Args:
        query:  Search query string produced by :func:`build_query`.
        top_n:  Maximum number of results to return.

    Returns:
        A list of up to *top_n* :class:`~chaintrace.models.SearchResult` objects.

    Raises:
        RuntimeError: If ``SERPAPI_KEY`` is missing, the HTTP request fails,
            or SerpAPI returns an error payload.
    """
    api_key = os.getenv("SERPAPI_KEY")
    if not api_key:
        raise RuntimeError(
            "SERPAPI_KEY environment variable is not set. "
            "Copy .env.example to .env and add your key."
        )

    params = {
        "engine": "google_light",
        "q": query,
        "num": top_n,
        "api_key": api_key,
        "hl": "en",
        "gl": "us",
    }

    logger.debug("SerpAPI request: engine=google_light q=%r num=%d", query, top_n)

    try:
        response = requests.get(_SERPAPI_URL, params=params, timeout=30)
        response.raise_for_status()
    except requests.exceptions.Timeout as exc:
        raise RuntimeError(f"SerpAPI request timed out: {exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"SerpAPI HTTP error: {exc}") from exc

    data = response.json()

    if "error" in data:
        raise RuntimeError(f"SerpAPI returned an error: {data['error']}")

    organic = data.get("organic_results", [])
    if not organic:
        logger.warning("SerpAPI returned no organic results for query: %r", query)

    results: list[SearchResult] = []
    for item in organic[:top_n]:
        result = SearchResult(
            url=item.get("link", ""),
            title=item.get("title", ""),
            snippet=item.get("snippet", ""),
        )
        logger.debug("Result %d: %s", len(results) + 1, result.url)
        results.append(result)

    return results
