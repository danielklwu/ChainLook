"""NVD vulnerability database lookup.

Queries the NIST NVD CVE API v2 by part number + manufacturer keyword
and filters results to hardware-relevant entries.

Environment variable:
    NVD_API_KEY: Optional. Without it requests are rate-limited to
                 5/30s; with it the limit rises to 50/30s.
"""

from __future__ import annotations

import logging
import os

import requests
from dotenv import load_dotenv

from chainlook.models import VulnEntry

logger = logging.getLogger(__name__)

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_RESULTS_PER_PAGE = 20

# Descriptions containing any of these terms are considered hardware-relevant.
_HARDWARE_KEYWORDS = frozenset({
    "firmware",
    "hardware",
    "embedded",
    "supply chain",
    "physical access",
    "iot",
    "industrial control",
    "scada",
    "ics",
    "microcontroller",
    "processor",
    "chip",
    "semiconductor",
    "boot",
    "bootloader",
})


def search_cves(part_number: str, manufacturer: str) -> list[VulnEntry]:
    """Search NVD for hardware-relevant CVEs matching *part_number* and *manufacturer*.

    Args:
        part_number:  Normalised part number (e.g. ``"STM32F407"``).
        manufacturer: Manufacturer name (e.g. ``"STMicroelectronics"``).

    Returns:
        List of :class:`~chainlook.models.VulnEntry` filtered to hardware-
        relevant CVEs. Returns an empty list on API errors to avoid blocking
        the main pipeline.
    """
    load_dotenv()

    keyword = f"{manufacturer} {part_number}".strip()
    if not keyword:
        return []

    headers: dict[str, str] = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": _RESULTS_PER_PAGE,
    }

    try:
        response = requests.get(_NVD_URL, params=params, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        logger.warning("NVD API timed out for query: %r", keyword)
        return []
    except requests.exceptions.RequestException as exc:
        logger.warning("NVD API request failed: %s", exc)
        return []
    except ValueError as exc:
        logger.warning("NVD API returned invalid JSON: %s", exc)
        return []

    vulns: list[VulnEntry] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        desc_list = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in desc_list if d.get("lang") == "en"), ""
        )

        if not _is_hardware_relevant(description):
            continue

        cvss_score, severity = _extract_cvss(cve.get("metrics", {}))

        vulns.append(VulnEntry(
            cve_id=cve.get("id", "UNKNOWN"),
            description=description[:400],
            cvss_score=cvss_score,
            severity=severity,
            published=cve.get("published", "")[:10],
        ))

    logger.debug("NVD: %d hardware-relevant CVEs for %r", len(vulns), keyword)
    return vulns


def _is_hardware_relevant(description: str) -> bool:
    desc_lower = description.lower()
    return any(kw in desc_lower for kw in _HARDWARE_KEYWORDS)


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = float(cvss_data.get("baseScore", 0.0))
            severity = str(cvss_data.get("baseSeverity", "UNKNOWN")).upper()
            return score, severity
    return 0.0, "UNKNOWN"
