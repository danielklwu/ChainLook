"""Risk scoring engine.

Combines four signals into a composite risk score (0.0 – 1.0) and
maps it to a categorical label for CLI display.

Signals and weights
-------------------
country_risk       0.35  Manufacturer country against BIS/OFAC high-risk list
cve_risk           0.30  CVE count × max CVSS score, normalised
indicator_risk     0.25  Gemini risk_indicators mapped to severity weights
confidence_penalty 0.10  (1 - confidence_score): penalises uncertain identifications

Thresholds
----------
< 0.25  LOW
< 0.55  MEDIUM
< 0.75  HIGH
≥ 0.75  CRITICAL
"""

from __future__ import annotations

from chainlook.models import ComponentResult, RiskScore, VulnEntry

# Countries flagged by BIS Entity List / OFAC sanctions (ISO 2-letter and common names).
_HIGH_RISK_COUNTRIES = frozenset({
    "cn", "china",
    "ru", "russia",
    "ir", "iran",
    "kp", "north korea",
})

# Maps substrings from Gemini risk_indicators to a severity weight.
_INDICATOR_SCORES: dict[str, float] = {
    "sanctioned": 1.0,
    "counterfeit": 0.7,
    "export control": 0.6,
    "manufacturing region": 0.5,
    "end-of-life": 0.3,
    "eol": 0.3,
    "obsolete": 0.25,
}

_WEIGHTS = {
    "country": 0.35,
    "cve": 0.30,
    "indicator": 0.25,
    "confidence": 0.10,
}

# Ordered highest → lowest so the first matching threshold wins.
_THRESHOLDS: list[tuple[float, str]] = [
    (0.75, "CRITICAL"),
    (0.55, "HIGH"),
    (0.25, "MEDIUM"),
    (0.0,  "LOW"),
]


def score(component: ComponentResult, cves: list[VulnEntry]) -> RiskScore:
    """Compute a :class:`~chainlook.models.RiskScore` for *component*.

    Args:
        component: Identified component with manufacturer/country metadata.
        cves:      Hardware-relevant CVEs from :mod:`chainlook.hbom.vulndb`.

    Returns:
        A fully populated :class:`~chainlook.models.RiskScore`.
    """
    country_risk = _country_risk(component.manufacturer_country)
    cve_risk = _cve_risk(cves)
    indicator_risk = _indicator_risk(component.risk_indicators)
    confidence_penalty = round(1.0 - min(max(component.confidence_score, 0.0), 1.0), 4)

    total = round(
        _WEIGHTS["country"] * country_risk
        + _WEIGHTS["cve"] * cve_risk
        + _WEIGHTS["indicator"] * indicator_risk
        + _WEIGHTS["confidence"] * confidence_penalty,
        4,
    )
    total = min(total, 1.0)

    category = next(cat for threshold, cat in _THRESHOLDS if total >= threshold)

    return RiskScore(
        total=total,
        category=category,
        country_risk=country_risk,
        cve_risk=cve_risk,
        indicator_risk=indicator_risk,
        confidence_penalty=confidence_penalty,
        cves=cves,
    )


def _country_risk(country: str | None) -> float:
    if not country:
        return 0.1  # unknown origin carries a small uncertainty penalty
    return 1.0 if country.strip().lower() in _HIGH_RISK_COUNTRIES else 0.0


def _cve_risk(cves: list[VulnEntry]) -> float:
    if not cves:
        return 0.0
    max_cvss = max(v.cvss_score for v in cves)
    # Count factor caps at 5 CVEs to avoid unbounded inflation.
    count_factor = min(len(cves) / 5.0, 1.0)
    return round(min((max_cvss / 10.0) * (0.7 + 0.3 * count_factor), 1.0), 4)


def _indicator_risk(indicators: list[str]) -> float:
    if not indicators:
        return 0.0
    worst = 0.0
    for indicator in indicators:
        ind_lower = indicator.lower()
        for keyword, weight in _INDICATOR_SCORES.items():
            if keyword in ind_lower:
                worst = max(worst, weight)
    return worst
