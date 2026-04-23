"""Data models for ChainTrace."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ComponentResult:
    """Structured output returned by Gemini after classification."""

    input_query: str
    normalized_part_number: str
    component_type: str
    manufacturer: str
    manufacturer_country: Optional[str]
    datasheet_url: Optional[str]
    description: str
    risk_indicators: list[str] = field(default_factory=list)
    confidence_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "input_query": self.input_query,
            "normalized_part_number": self.normalized_part_number,
            "component_type": self.component_type,
            "manufacturer": self.manufacturer,
            "manufacturer_country": self.manufacturer_country,
            "datasheet_url": self.datasheet_url,
            "description": self.description,
            "risk_indicators": self.risk_indicators,
            "confidence_score": self.confidence_score,
        }


@dataclass
class SearchResult:
    """A single search result returned by the search layer."""

    url: str
    title: str
    snippet: str


@dataclass
class ScrapedPage:
    """Raw text content scraped from a URL."""

    url: str
    text: str
    success: bool
    error: Optional[str] = None


@dataclass
class CacheEntry:
    """Full cache record stored per lookup."""

    query: str
    normalized_part_number: str
    search_results: list[SearchResult]
    scraped_pages: list[ScrapedPage]
    gemini_prompt: str
    gemini_response: str
    component_result: ComponentResult


@dataclass
class VulnEntry:
    """A single CVE entry returned by the vulnerability database."""

    cve_id: str
    description: str
    cvss_score: float
    severity: str  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    published: str  # ISO date string (YYYY-MM-DD)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "published": self.published,
        }


@dataclass
class RiskScore:
    """Composite risk score for a single component."""

    total: float       # 0.0 – 1.0
    category: str      # LOW | MEDIUM | HIGH | CRITICAL
    country_risk: float
    cve_risk: float
    indicator_risk: float
    confidence_penalty: float
    cves: list[VulnEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "category": self.category,
            "breakdown": {
                "country_risk": self.country_risk,
                "cve_risk": self.cve_risk,
                "indicator_risk": self.indicator_risk,
                "confidence_penalty": self.confidence_penalty,
            },
            "cves": [v.to_dict() for v in self.cves],
        }


@dataclass
class HBOMEntry:
    """One component row in the Hardware Bill of Materials."""

    component: ComponentResult
    risk: RiskScore

    def to_dict(self) -> dict:
        c = self.component
        return {
            "part_number": c.normalized_part_number,
            "manufacturer": c.manufacturer,
            "manufacturer_country": c.manufacturer_country,
            "component_type": c.component_type,
            "datasheet_url": c.datasheet_url,
            "description": c.description,
            "confidence_score": c.confidence_score,
            "risk_indicators": c.risk_indicators,
            "risk_score": self.risk.total,
            "risk_category": self.risk.category,
            "risk_breakdown": self.risk.to_dict()["breakdown"],
            "cves": [v.to_dict() for v in self.risk.cves],
        }
