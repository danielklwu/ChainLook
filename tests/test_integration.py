"""Integration tests for the HBOM analysis pipeline.

These tests exercise module boundaries together without mocking internal logic,
but do mock external network calls (NVD API).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chaintrace.hbom import analyze, report
from chaintrace.hbom import risk_scorer
from chaintrace.models import ComponentResult, HBOMEntry, RiskScore, VulnEntry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _component(
    part: str = "STM32F407",
    manufacturer: str = "STMicroelectronics",
    country: str | None = "IT",
    indicators: list[str] | None = None,
    confidence: float = 0.95,
) -> ComponentResult:
    return ComponentResult(
        input_query=part,
        normalized_part_number=part,
        component_type="Microcontroller",
        manufacturer=manufacturer,
        manufacturer_country=country,
        datasheet_url=None,
        description="ARM Cortex-M4 microcontroller.",
        risk_indicators=indicators or [],
        confidence_score=confidence,
    )


def _hw_cve(cve_id: str = "CVE-2023-1234", cvss: float = 9.8) -> VulnEntry:
    return VulnEntry(
        cve_id=cve_id,
        description="A firmware vulnerability in an embedded device.",
        cvss_score=cvss,
        severity="CRITICAL",
        published="2023-05-01",
    )


# ---------------------------------------------------------------------------
# TestAnalyze  (hbom.analyze + risk_scorer.score integrated)
# ---------------------------------------------------------------------------


class TestAnalyze:
    def test_returns_hbom_entry(self, mocker):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        entry = analyze(_component())
        assert isinstance(entry, HBOMEntry)

    def test_component_preserved(self, mocker):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        comp = _component()
        entry = analyze(comp)
        assert entry.component is comp

    def test_risk_score_is_risk_score_type(self, mocker):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        entry = analyze(_component())
        assert isinstance(entry.risk, RiskScore)

    def test_no_cves_produces_zero_cve_risk(self, mocker):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        entry = analyze(_component())
        assert entry.risk.cve_risk == pytest.approx(0.0)

    def test_cves_raise_cve_risk(self, mocker):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[_hw_cve(cvss=9.8)])
        entry = analyze(_component())
        assert entry.risk.cve_risk > 0.0
        assert len(entry.risk.cves) == 1

    def test_multiple_cves_attached(self, mocker):
        cves = [_hw_cve("CVE-2023-0001", 7.0), _hw_cve("CVE-2023-0002", 9.0)]
        mocker.patch("chaintrace.hbom.search_cves", return_value=cves)
        entry = analyze(_component())
        assert len(entry.risk.cves) == 2

    def test_chinese_manufacturer_raises_country_risk(self, mocker):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        entry = analyze(_component(country="cn"))
        assert entry.risk.country_risk == pytest.approx(1.0)

    def test_sanctioned_indicator_raises_indicator_risk(self, mocker):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        entry = analyze(_component(indicators=["sanctioned entity"]))
        assert entry.risk.indicator_risk == pytest.approx(1.0)

    def test_low_confidence_raises_penalty(self, mocker):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        entry = analyze(_component(confidence=0.0))
        assert entry.risk.confidence_penalty == pytest.approx(1.0)

    def test_search_cves_called_with_part_and_manufacturer(self, mocker):
        mock_search = mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        analyze(_component(part="STM32F407", manufacturer="STMicroelectronics"))
        mock_search.assert_called_once_with("STM32F407", "STMicroelectronics")

    def test_full_risk_pipeline_high_risk_component(self, mocker):
        cves = [_hw_cve(cvss=9.8)] * 5
        mocker.patch("chaintrace.hbom.search_cves", return_value=cves)
        entry = analyze(_component(
            country="cn",
            indicators=["sanctioned entity"],
            confidence=1.0,
        ))
        assert entry.risk.category == "CRITICAL"
        assert entry.risk.total >= 0.75


# ---------------------------------------------------------------------------
# TestReportPipeline  (analyze + report.generate integrated)
# ---------------------------------------------------------------------------


class TestReportPipeline:
    def test_generate_from_analyzed_entries(self, mocker, tmp_path):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        entries = [analyze(_component(f"PART{i}")) for i in range(3)]
        path = report.generate(entries, tmp_path)
        assert path.exists()

    def test_report_contains_all_analyzed_components(self, mocker, tmp_path):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        parts = ["STM32F407", "LM358", "ATmega328P"]
        entries = [analyze(_component(p)) for p in parts]
        path = report.generate(entries, tmp_path)
        doc = json.loads(path.read_text())
        assert doc["summary"]["total_components"] == 3
        reported_parts = {c["part_number"] for c in doc["components"]}
        assert reported_parts == set(parts)

    def test_report_risk_scores_match_analyzer_output(self, mocker, tmp_path):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[_hw_cve(cvss=9.0)])
        entry = analyze(_component("STM32F407", country="cn"))
        path = report.generate([entry], tmp_path)
        doc = json.loads(path.read_text())
        comp = doc["components"][0]
        assert comp["risk_score"] == pytest.approx(entry.risk.total, abs=1e-4)
        assert comp["risk_category"] == entry.risk.category

    def test_report_cves_round_trip(self, mocker, tmp_path):
        cves = [_hw_cve("CVE-2023-AAAA", 8.5)]
        mocker.patch("chaintrace.hbom.search_cves", return_value=cves)
        entry = analyze(_component())
        path = report.generate([entry], tmp_path)
        doc = json.loads(path.read_text())
        assert len(doc["components"][0]["cves"]) == 1
        assert doc["components"][0]["cves"][0]["cve_id"] == "CVE-2023-AAAA"

    def test_print_summary_and_generate_consistent_counts(self, mocker, tmp_path, capsys):
        mocker.patch("chaintrace.hbom.search_cves", return_value=[])
        entries = [analyze(_component(f"P{i}")) for i in range(4)]
        path = report.generate(entries, tmp_path)
        report.print_summary(entries, hbom_path=path)
        out = capsys.readouterr().out
        assert "4" in out

    def test_high_risk_components_appear_in_summary(self, mocker, tmp_path, capsys):
        cves = [_hw_cve(cvss=9.8)] * 5
        mocker.patch("chaintrace.hbom.search_cves", return_value=cves)
        entry = analyze(_component("DANGEROUS", country="cn", indicators=["sanctioned entity"]))
        report.print_summary([entry])
        out = capsys.readouterr().out
        assert "DANGEROUS" in out


# ---------------------------------------------------------------------------
# TestRiskScorerAggregation  (risk_scorer integration across multiple inputs)
# ---------------------------------------------------------------------------


class TestRiskScorerAggregation:
    def test_scoring_stable_for_identical_inputs(self):
        comp = _component(country="cn", indicators=["end-of-life"], confidence=0.8)
        cves = [_hw_cve(cvss=7.0)]
        r1 = risk_scorer.score(comp, cves)
        r2 = risk_scorer.score(comp, cves)
        assert r1.total == pytest.approx(r2.total)
        assert r1.category == r2.category

    def test_adding_cves_increases_total(self):
        comp = _component()
        no_cve = risk_scorer.score(comp, [])
        with_cve = risk_scorer.score(comp, [_hw_cve(cvss=9.8)])
        assert with_cve.total > no_cve.total

    def test_high_risk_country_dominates_low_confidence(self):
        # Even with zero confidence, Chinese manufacturer should produce MEDIUM+
        comp = _component(country="cn", confidence=0.0)
        result = risk_scorer.score(comp, [])
        assert result.category in ("MEDIUM", "HIGH", "CRITICAL")

    def test_all_four_signal_weights_contribute(self):
        comp_full = _component(country="cn", indicators=["sanctioned entity"], confidence=0.0)
        cves = [_hw_cve(cvss=10.0)] * 10
        result = risk_scorer.score(comp_full, cves)
        assert result.country_risk > 0
        assert result.cve_risk > 0
        assert result.indicator_risk > 0
        assert result.confidence_penalty > 0
