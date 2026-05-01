"""HBOM report generation.

Writes a flat JSON Hardware Bill of Materials and prints a formatted
CLI summary with per-component risk badges.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from chainlook.models import HBOMEntry

logger = logging.getLogger(__name__)

_CATEGORY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

_CATEGORY_BADGE = {
    "CRITICAL": "[CRITICAL]",
    "HIGH":     "[HIGH]    ",
    "MEDIUM":   "[MEDIUM]  ",
    "LOW":      "[LOW]     ",
}


def generate(entries: list[HBOMEntry], output_dir: Path) -> Path:
    """Write a flat JSON HBOM to *output_dir*/hbom.json.

    Args:
        entries:    All analysed components for this run.
        output_dir: Directory that already contains per-component cache files.

    Returns:
        Path of the written ``hbom.json`` file.
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = output_dir / "hbom.json"

    distribution: dict[str, int] = {cat: 0 for cat in _CATEGORY_ORDER}
    for entry in entries:
        distribution[entry.risk.category] = distribution.get(entry.risk.category, 0) + 1

    top_risk = sorted(entries, key=lambda e: e.risk.total, reverse=True)[:5]

    doc = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_components": len(entries),
            "risk_distribution": distribution,
            "highest_risk": [
                {
                    "part_number": e.component.normalized_part_number,
                    "manufacturer": e.component.manufacturer,
                    "risk_category": e.risk.category,
                    "risk_score": e.risk.total,
                }
                for e in top_risk
            ],
        },
        "components": [e.to_dict() for e in entries],
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)

    logger.debug("HBOM written to %s", output_path)
    return output_path


def print_summary(entries: list[HBOMEntry], hbom_path: Path | None = None) -> None:
    """Print a formatted HBOM risk summary to stdout.

    Args:
        entries:   All analysed components.
        hbom_path: Path of the written hbom.json file, if any.
    """
    distribution: dict[str, int] = {cat: 0 for cat in _CATEGORY_ORDER}
    for entry in entries:
        distribution[entry.risk.category] = distribution.get(entry.risk.category, 0) + 1

    print("\n" + "=" * 55)
    print("  HBOM RISK SUMMARY")
    print("=" * 55)
    print(f"  Components analysed: {len(entries)}")
    print()
    for cat in _CATEGORY_ORDER:
        count = distribution.get(cat, 0)
        bar = "█" * count
        print(f"  {_CATEGORY_BADGE[cat]}  {count:>3}  {bar}")

    flagged = [e for e in entries if e.risk.category in ("CRITICAL", "HIGH")]
    if flagged:
        flagged_sorted = sorted(flagged, key=lambda e: e.risk.total, reverse=True)
        print()
        print("  Flagged components:")
        for entry in flagged_sorted:
            badge = _CATEGORY_BADGE[entry.risk.category].strip()
            part = entry.component.normalized_part_number
            score = entry.risk.total
            indicators = ", ".join(entry.component.risk_indicators) or "—"
            cve_count = len(entry.risk.cves)
            cve_note = f"  {cve_count} CVE(s)" if cve_count else ""
            print(f"    {badge} {part:<20} score={score:.2f}  {indicators}{cve_note}")

    if hbom_path:
        print()
        print(f"  Report: {hbom_path}")
    print("=" * 55)
