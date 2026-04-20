"""CLI entry point for ChainTrace.

Usage:
    chaintrace                  # interactive prompt
    chaintrace "DAC\\n32031\\nTI 69K\\nCJ22"   # inline query (literal \\n supported)

Supports multi-line input. Literal '\\n' sequences in the query string are
expanded to real newlines before processing.
"""

from __future__ import annotations

import argparse
import logging
import sys
import textwrap
from pathlib import Path

from chaintrace import __version__
from chaintrace import aggregator, cache, gemini, scraper, search, validator
from chaintrace.models import CacheEntry

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="chaintrace",
        description="ChainTrace — hardware component lookup and supply-chain risk analysis.\n\n"
                    "Provide a board QUERY string (supports literal \\\\n for multi-line markings), "
                    "or omit it to be prompted interactively.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "query",
        nargs="?",
        default=None,
        help="Component marking query string.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"chaintrace {__version__}",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        default=False,
        help="Skip the local cache and always perform a fresh lookup.",
    )
    parser.add_argument(
        "--cache-dir",
        default="cache",
        metavar="DIR",
        help="Directory used to store cached results. (default: cache)",
    )
    parser.add_argument(
        "--top-n",
        default=3,
        type=int,
        metavar="N",
        help="Number of search results to retrieve. (default: 3)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable verbose/debug logging.",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ------------------------------------------------------------------
    # 1. Collect input
    # ------------------------------------------------------------------
    query = _resolve_query(args.query)
    if not query:
        print("Error: empty query.", file=sys.stderr)
        sys.exit(1)

    print(f"[ChainTrace v{__version__}]")
    print(f"Query: {repr(query)}\n")

    # ------------------------------------------------------------------
    # 2. Cache check
    # ------------------------------------------------------------------
    cache_path = Path(args.cache_dir)

    # TODO: once cache.load() is implemented, check for a cache hit here
    # and return early when --no-cache is not set.

    # ------------------------------------------------------------------
    # 3. Search
    # ------------------------------------------------------------------
    print("Searching...")
    search_query = search.build_query(query)
    results = search.search(search_query, top_n=args.top_n)
    print(f"Found {len(results)} result(s).")
    for i in range(min(len(results), args.top_n)):
        print(f"   {i+1}. {results[i].title} ({results[i].url})")

    # ------------------------------------------------------------------
    # 4. Scrape
    # ------------------------------------------------------------------
    print("Scraping sources...")
    pages = scraper.scrape(results)
    successful = [p for p in pages if p.success]
    print(f"Scraped {len(successful)}/{len(pages)} page(s) successfully.")

    # ------------------------------------------------------------------
    # 5. Aggregate
    # ------------------------------------------------------------------
    aggregated_text = aggregator.aggregate(pages)

    # ------------------------------------------------------------------
    # 6. Gemini classification
    # ------------------------------------------------------------------
    print("Classifying with Gemini...")
    prompt = gemini.build_prompt(query, aggregated_text)
    raw_response = gemini.classify(prompt)

    # ------------------------------------------------------------------
    # 7. Validate and parse
    # ------------------------------------------------------------------
    component = validator.parse(raw_response)

    # ------------------------------------------------------------------
    # 8. Cache save
    # ------------------------------------------------------------------
    entry = CacheEntry(
        query=query,
        normalized_part_number=component.normalized_part_number,
        search_results=results,
        scraped_pages=pages,
        gemini_prompt=prompt,
        gemini_response=raw_response,
        component_result=component,
    )
    saved_path = cache.save(entry, cache_dir=cache_path)
    logger.debug("Cached result to %s", saved_path)

    # ------------------------------------------------------------------
    # 9. Display summary
    # ------------------------------------------------------------------
    _display_result(component)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_query(query: str | None) -> str:
    """Return the final query string.

    Expands literal ``\\n`` sequences to real newlines.
    """
    if query is None:
        print("Enter component marking (blank line to finish):")
        lines: list[str] = []
        while True:
            try:
                line = input()
            except EOFError:
                break
            if line == "":
                break
            lines.append(line)
        query = "\n".join(lines)
    else:
        # Expand literal \n sequences from shell-quoted strings.
        query = query.replace("\\n", "\n")

    return query.strip()


def _display_result(component) -> None:
    """Print a human-readable summary of *component* to stdout."""
    risk = ", ".join(component.risk_indicators) if component.risk_indicators else "None detected"
    datasheet = component.datasheet_url or "N/A"

    print("\n" + "─" * 50)
    print(f"Part:               {component.normalized_part_number}")
    print(f"Manufacturer:       {component.manufacturer}")
    print(f"Country:            {component.manufacturer_country or 'Unknown'}")
    print(f"Type:               {component.component_type}")
    print(f"Datasheet:          {datasheet}")
    print(f"Risk Indicators:    {risk}")
    print(f"Confidence:         {component.confidence_score:.2f}")

    desc = textwrap.fill(component.description, width=70)
    print(f"\nDescription:\n{desc}")
    print("─" * 50)


if __name__ == "__main__":
    main()
