"""Hardware Bill of Materials (HBOM) — risk analysis and report generation.

Submodules
----------
vulndb       NVD CVE lookup filtered for hardware-relevant vulnerabilities
risk_scorer  Weighted risk scoring (country, CVE, indicators, confidence)
report       Flat JSON report writer and CLI summary printer

Public API
----------
analyze(component)  -> HBOMEntry   run vuln lookup + score a single component
"""

from __future__ import annotations

from chainlook.hbom import report
from chainlook.hbom.risk_scorer import score
from chainlook.hbom.vulndb import search_cves
from chainlook.models import ComponentResult, HBOMEntry


def analyze(component: ComponentResult) -> HBOMEntry:
    """Run vulnerability lookup and risk scoring for *component*.

    Args:
        component: Identified component from the lookup pipeline.

    Returns:
        :class:`~chainlook.models.HBOMEntry` with component + risk score.
    """
    cves = search_cves(component.normalized_part_number, component.manufacturer)
    risk = score(component, cves)
    return HBOMEntry(component=component, risk=risk)


__all__ = ["analyze", "report"]
