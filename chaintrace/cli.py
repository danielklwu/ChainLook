"""CLI entry point for ChainTrace.

Usage:
    chaintrace                          # interactive prompt
    chaintrace "DAC\\n32031\\nTI 69K\\nCJ22"   # inline query (literal \\n supported)
    chaintrace -i input_example.txt     # batch lookup from file (one component per line)
    chaintrace -i components.txt -o run1  # batch with custom output directory name

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
                    "or omit it to be prompted interactively.\n"
                    "Use -i to process a file with one component marking per line.",
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
        "-i", "--input",
        metavar="FILE",
        default=None,
        help="Input file with one component marking per line (literal \\\\n supported).",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="NAME",
        default=None,
        help="Output directory name under cache dir for batch results. "
             "Defaults to the input filename stem.",
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

    # Mutual exclusion: -i and a positional query don't mix.
    if args.input and args.query:
        print("Error: provide either a query argument or -i FILE, not both.", file=sys.stderr)
        sys.exit(1)

    cache_path = Path(args.cache_dir)

    if args.input:
        _run_batch(args, cache_path)
    else:
        _run_single(args, cache_path)


# ---------------------------------------------------------------------------
# Single-query mode
# ---------------------------------------------------------------------------


def _run_single(args, cache_path: Path) -> None:
    query = _resolve_query(args.query)
    if not query:
        print("Error: empty query.", file=sys.stderr)
        sys.exit(1)

    print(f"[ChainTrace v{__version__}]")
    print(f"Query: {repr(query)}\n")

    # TODO: once cache.load() is implemented, check for a cache hit here
    # and return early when --no-cache is not set.

    component = _lookup(query, cache_path, args.top_n)
    if component is not None:
        _display_result(component)


# ---------------------------------------------------------------------------
# Batch mode (-i)
# ---------------------------------------------------------------------------


def _run_batch(args, cache_path: Path) -> None:
    input_file = Path(args.input)
    if not input_file.exists():
        print(f"Error: input file not found: {input_file}", file=sys.stderr)
        sys.exit(1)

    raw_lines = input_file.read_text(encoding="utf-8").splitlines()
    # Each non-empty line is one component marking; expand literal \n sequences.
    queries = [
        line.replace("\\n", "\n").strip()
        for line in raw_lines
        if line.strip()
    ]

    if not queries:
        print("Error: input file contains no component markings.", file=sys.stderr)
        sys.exit(1)

    output_name = args.output or input_file.stem
    batch_cache_dir = cache_path / output_name

    print(f"[ChainTrace v{__version__}] — batch mode")
    print(f"Input:      {input_file}")
    print(f"Components: {len(queries)}")
    print(f"Output dir: {batch_cache_dir}\n")

    successes: list[str] = []
    failures: list[tuple[str, str]] = []  # (query_repr, error message)

    for idx, query in enumerate(queries, start=1):
        label = repr(query) if len(query) < 40 else repr(query[:37] + "...")
        print(f"[{idx}/{len(queries)}] {label}")
        try:
            component = _lookup(query, batch_cache_dir, args.top_n)
            if component is not None:
                _display_result(component)
                successes.append(component.normalized_part_number)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            print(f"   ERROR: {msg}", file=sys.stderr)
            failures.append((label, msg))

    # Final summary
    print("\n" + "=" * 50)
    print(f"Batch complete: {len(successes)}/{len(queries)} succeeded")
    if successes:
        print("Saved:")
        for part in successes:
            print(f"   {batch_cache_dir / (part + '.json')}")
    if failures:
        print(f"Failed ({len(failures)}):")
        for label, msg in failures:
            print(f"   {label}: {msg}")
    print("=" * 50)


# ---------------------------------------------------------------------------
# Core lookup pipeline (shared by both modes)
# ---------------------------------------------------------------------------


def _lookup(query: str, cache_path: Path, top_n: int):
    """Run the full search → scrape → classify → save pipeline for one query.

    Returns the ComponentResult on success, or None if classification failed.
    Saves the cache entry to *cache_path*.
    """
    # Search
    print("   Searching...")
    search_query = search.build_query(query)
    results = search.search(search_query, top_n=top_n)
    print(f"   Found {len(results)} result(s).")
    for i in range(min(len(results), top_n)):
        print(f"      {i+1}. {results[i].title} ({results[i].url})")

    # Scrape
    print("   Scraping sources...")
    pages = scraper.scrape(results)
    successful = [p for p in pages if p.success]
    print(f"   Scraped {len(successful)}/{len(pages)} page(s) successfully.")

    # Aggregate
    aggregated_text = aggregator.aggregate(pages)

    # Classify
    print("   Classifying with Gemini...")
    prompt = gemini.build_prompt(query, aggregated_text)
    raw_response = gemini.classify(prompt)

    # Validate
    component = validator.parse(raw_response)

    # Cache save
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

    return component


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
