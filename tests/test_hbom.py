"""Unit tests for chaintrace.hbom: risk_scorer, vulndb, and report."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import requests

from chaintrace.hbom import report, risk_scorer, vulndb
from chaintrace.models import ComponentResult, HBOMEntry, RiskScore, VulnEntry


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_component(
    *,
    manufacturer_country: str | None = "US",
    risk_indicators: list[str] | None = None,
    confidence_score: float = 1.0,
    manufacturer: str = "ACME",
    part_number: str = "PART001",
) -> ComponentResult:
    return ComponentResult(
        input_query=part_number,
        normalized_part_number=part_number,
        component_type="IC",
        manufacturer=manufacturer,
        manufacturer_country=manufacturer_country,
        datasheet_url=None,
        description="A test component.",
        risk_indicators=risk_indicators or [],
        confidence_score=confidence_score,
    )


def _make_vuln(cvss: float = 9.8, severity: str = "CRITICAL") -> VulnEntry:
    return VulnEntry(
        cve_id="CVE-2023-9999",
        description="A firmware vulnerability in an embedded device.",
        cvss_score=cvss,
        severity=severity,
        published="2023-01-01",
    )


def _make_risk(
    total: float = 0.10,
    category: str = "LOW",
    cves: list[VulnEntry] | None = None,
) -> RiskScore:
    return RiskScore(
        total=total,
        category=category,
        country_risk=0.0,
        cve_risk=0.0,
        indicator_risk=0.0,
        confidence_penalty=total,
        cves=cves or [],
    )


def _make_hbom_entry(
    part_number: str = "PART001",
    country: str | None = "US",
    risk_total: float = 0.10,
    risk_category: str = "LOW",
    cves: list[VulnEntry] | None = None,
) -> HBOMEntry:
    return HBOMEntry(
        component=_make_component(
            part_number=part_number,
            manufacturer_country=country,
        ),
        risk=_make_risk(total=risk_total, category=risk_category, cves=cves),
    )


# ---------------------------------------------------------------------------
# TestCountryRisk
# ---------------------------------------------------------------------------


class TestCountryRisk:
    def test_china_returns_one(self):
        assert risk_scorer._country_risk("cn") == 1.0
        assert risk_scorer._country_risk("china") == 1.0

    def test_russia_returns_one(self):
        assert risk_scorer._country_risk("ru") == 1.0
        assert risk_scorer._country_risk("russia") == 1.0

    def test_iran_returns_one(self):
        assert risk_scorer._country_risk("ir") == 1.0
        assert risk_scorer._country_risk("iran") == 1.0

    def test_north_korea_returns_one(self):
        assert risk_scorer._country_risk("kp") == 1.0
        assert risk_scorer._country_risk("north korea") == 1.0

    def test_case_insensitive(self):
        assert risk_scorer._country_risk("CN") == 1.0
        assert risk_scorer._country_risk("China") == 1.0
        assert risk_scorer._country_risk("RUSSIA") == 1.0

    def test_us_returns_zero(self):
        assert risk_scorer._country_risk("US") == 0.0
        assert risk_scorer._country_risk("us") == 0.0

    def test_safe_country_returns_zero(self):
        assert risk_scorer._country_risk("de") == 0.0
        assert risk_scorer._country_risk("jp") == 0.0
        assert risk_scorer._country_risk("IT") == 0.0

    def test_none_returns_small_penalty(self):
        assert risk_scorer._country_risk(None) == pytest.approx(0.1)

    def test_empty_string_treated_as_unknown(self):
        assert risk_scorer._country_risk("") == pytest.approx(0.1)


# ---------------------------------------------------------------------------
# TestCveRisk
# ---------------------------------------------------------------------------


class TestCveRisk:
    def test_empty_list_returns_zero(self):
        assert risk_scorer._cve_risk([]) == 0.0

    def test_single_cve_score(self):
        cves = [_make_vuln(cvss=9.0)]
        # count_factor = min(1/5, 1) = 0.2
        # result = (9.0/10.0) * (0.7 + 0.3 * 0.2) = 0.9 * 0.76 = 0.684
        assert risk_scorer._cve_risk(cves) == pytest.approx(0.684, abs=1e-4)

    def test_five_cves_max_count_factor(self):
        cves = [_make_vuln(cvss=8.0)] * 5
        # count_factor = 1.0, result = (8/10) * (0.7 + 0.3) = 0.8
        assert risk_scorer._cve_risk(cves) == pytest.approx(0.8, abs=1e-4)

    def test_more_than_five_cves_capped(self):
        cves_five = [_make_vuln(cvss=8.0)] * 5
        cves_ten = [_make_vuln(cvss=8.0)] * 10
        assert risk_scorer._cve_risk(cves_five) == risk_scorer._cve_risk(cves_ten)

    def test_perfect_score_clamps_to_one(self):
        cves = [_make_vuln(cvss=10.0)] * 10
        assert risk_scorer._cve_risk(cves) == pytest.approx(1.0)

    def test_uses_max_cvss_not_average(self):
        cves = [_make_vuln(cvss=2.0), _make_vuln(cvss=9.5)]
        result = risk_scorer._cve_risk(cves)
        # max_cvss = 9.5, count_factor = 0.4
        expected = round(min((9.5 / 10.0) * (0.7 + 0.3 * 0.4), 1.0), 4)
        assert result == pytest.approx(expected, abs=1e-4)


# ---------------------------------------------------------------------------
# TestIndicatorRisk
# ---------------------------------------------------------------------------


class TestIndicatorRisk:
    def test_empty_list_returns_zero(self):
        assert risk_scorer._indicator_risk([]) == 0.0

    def test_sanctioned_returns_one(self):
        assert risk_scorer._indicator_risk(["sanctioned entity"]) == pytest.approx(1.0)

    def test_counterfeit_returns_point_seven(self):
        assert risk_scorer._indicator_risk(["counterfeit warning"]) == pytest.approx(0.7)

    def test_export_control_returns_point_six(self):
        assert risk_scorer._indicator_risk(["export control warning"]) == pytest.approx(0.6)

    def test_eol_returns_point_three(self):
        assert risk_scorer._indicator_risk(["end-of-life"]) == pytest.approx(0.3)
        assert risk_scorer._indicator_risk(["EOL"]) == pytest.approx(0.3)

    def test_obsolete_returns_point_two_five(self):
        assert risk_scorer._indicator_risk(["obsolete part"]) == pytest.approx(0.25)

    def test_multiple_indicators_returns_worst(self):
        result = risk_scorer._indicator_risk(["end-of-life", "sanctioned entity"])
        assert result == pytest.approx(1.0)

    def test_unknown_indicator_returns_zero(self):
        assert risk_scorer._indicator_risk(["low quality packaging"]) == 0.0

    def test_case_insensitive(self):
        assert risk_scorer._indicator_risk(["SANCTIONED"]) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# TestScore
# ---------------------------------------------------------------------------


class TestScore:
    def test_us_no_cves_no_indicators_high_confidence(self):
        component = _make_component(manufacturer_country="US", confidence_score=0.95)
        result = risk_scorer.score(component, [])
        assert result.category == "LOW"
        assert result.total < 0.25

    def test_china_no_cves_no_indicators_full_confidence(self):
        component = _make_component(manufacturer_country="cn", confidence_score=1.0)
        result = risk_scorer.score(component, [])
        # total = 0.35 * 1.0 = 0.35 → MEDIUM
        assert result.category == "MEDIUM"
        assert result.total == pytest.approx(0.35, abs=1e-4)

    def test_china_sanctioned_no_cves(self):
        component = _make_component(
            manufacturer_country="cn",
            risk_indicators=["sanctioned entity"],
            confidence_score=1.0,
        )
        result = risk_scorer.score(component, [])
        # 0.35*1.0 + 0.25*1.0 = 0.60 → HIGH
        assert result.category == "HIGH"
        assert result.total == pytest.approx(0.60, abs=1e-4)

    def test_critical_all_signals_maxed(self):
        component = _make_component(
            manufacturer_country="cn",
            risk_indicators=["sanctioned entity"],
            confidence_score=1.0,
        )
        cves = [_make_vuln(cvss=10.0)] * 10
        result = risk_scorer.score(component, cves)
        assert result.category == "CRITICAL"
        assert result.total >= 0.75

    def test_total_clamped_to_one(self):
        component = _make_component(
            manufacturer_country="cn",
            risk_indicators=["sanctioned entity"],
            confidence_score=0.0,
        )
        cves = [_make_vuln(cvss=10.0)] * 10
        result = risk_scorer.score(component, cves)
        assert result.total <= 1.0

    def test_unknown_country_incurs_penalty(self):
        with_country = _make_component(manufacturer_country="US", confidence_score=1.0)
        without_country = _make_component(manufacturer_country=None, confidence_score=1.0)
        assert risk_scorer.score(without_country, []).total > risk_scorer.score(with_country, []).total

    def test_cves_attached_to_risk_score(self):
        cves = [_make_vuln()]
        component = _make_component()
        result = risk_scorer.score(component, cves)
        assert result.cves == cves

    def test_returns_risk_score_dataclass(self):
        from chaintrace.models import RiskScore
        result = risk_scorer.score(_make_component(), [])
        assert isinstance(result, RiskScore)

    def test_confidence_zero_raises_penalty(self):
        component = _make_component(manufacturer_country="US", confidence_score=0.0)
        result = risk_scorer.score(component, [])
        assert result.confidence_penalty == pytest.approx(1.0, abs=1e-4)
        assert result.total == pytest.approx(0.10, abs=1e-4)

    @pytest.mark.parametrize("total,expected_cat", [
        (0.74, "HIGH"),
        (0.75, "CRITICAL"),
        (0.54, "MEDIUM"),
        (0.55, "HIGH"),
        (0.24, "LOW"),
        (0.25, "MEDIUM"),
        (0.0, "LOW"),
    ])
    def test_category_thresholds(self, total, expected_cat):
        # Build a component that produces a predictable total via confidence_penalty only.
        # confidence_penalty weight = 0.10, so total ≈ 0.10 * penalty
        # For boundary testing we use score directly and verify category logic.
        # We mock a RiskScore with known total and check the threshold mapping.
        rs = RiskScore(
            total=total,
            category="",
            country_risk=0.0,
            cve_risk=0.0,
            indicator_risk=0.0,
            confidence_penalty=0.0,
        )
        # Re-derive category from the module's threshold logic.
        from chaintrace.hbom.risk_scorer import _THRESHOLDS
        category = next(cat for threshold, cat in _THRESHOLDS if total >= threshold)
        assert category == expected_cat


# ---------------------------------------------------------------------------
# TestIsHardwareRelevant
# ---------------------------------------------------------------------------


class TestIsHardwareRelevant:
    @pytest.mark.parametrize("text", [
        "A firmware vulnerability in an embedded device allows...",
        "Hardware supply chain attack via modified chips.",
        "Physical access allows bypassing the bootloader.",
        "SCADA industrial control system affected.",
        "Microcontroller boot sequence vulnerability.",
        "Processor chip semiconductor issue.",
        "IoT device affected by this bug.",
    ])
    def test_hardware_keywords_match(self, text):
        assert vulndb._is_hardware_relevant(text) is True

    @pytest.mark.parametrize("text", [
        "A SQL injection vulnerability in a web application.",
        "Cross-site scripting in the login form.",
        "Buffer overflow in a network daemon.",
        "Path traversal in file upload handler.",
    ])
    def test_non_hardware_keywords_no_match(self, text):
        assert vulndb._is_hardware_relevant(text) is False

    def test_case_insensitive(self):
        assert vulndb._is_hardware_relevant("FIRMWARE bug") is True


# ---------------------------------------------------------------------------
# TestExtractCvss
# ---------------------------------------------------------------------------


class TestExtractCvss:
    def test_prefers_v31(self):
        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
            "cvssMetricV30": [{"cvssData": {"baseScore": 7.0, "baseSeverity": "HIGH"}}],
        }
        score, severity = vulndb._extract_cvss(metrics)
        assert score == pytest.approx(9.8)
        assert severity == "CRITICAL"

    def test_falls_back_to_v30(self):
        metrics = {
            "cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
        }
        score, severity = vulndb._extract_cvss(metrics)
        assert score == pytest.approx(7.5)
        assert severity == "HIGH"

    def test_falls_back_to_v2(self):
        metrics = {
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
        }
        score, severity = vulndb._extract_cvss(metrics)
        assert score == pytest.approx(5.0)
        assert severity == "MEDIUM"

    def test_empty_metrics_returns_defaults(self):
        score, severity = vulndb._extract_cvss({})
        assert score == 0.0
        assert severity == "UNKNOWN"

    def test_empty_metric_list_falls_through(self):
        metrics = {"cvssMetricV31": [], "cvssMetricV30": []}
        score, severity = vulndb._extract_cvss(metrics)
        assert score == 0.0
        assert severity == "UNKNOWN"


# ---------------------------------------------------------------------------
# TestSearchCves
# ---------------------------------------------------------------------------

_NVD_HARDWARE_HIT = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-1234",
                "descriptions": [
                    {"lang": "en", "value": "A firmware vulnerability in an embedded device allows remote code execution."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}},
                    ],
                },
                "published": "2023-05-01T00:00:00.000",
            }
        }
    ]
}

_NVD_NON_HARDWARE_HIT = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-5678",
                "descriptions": [
                    {"lang": "en", "value": "SQL injection in a web dashboard."},
                ],
                "metrics": {},
                "published": "2023-05-01T00:00:00.000",
            }
        }
    ]
}

_NVD_EMPTY = {"vulnerabilities": []}


def _mock_nvd(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = payload
    return resp


class TestSearchCves:
    def test_returns_hardware_relevant_cve(self, mocker):
        mocker.patch("chaintrace.hbom.vulndb.requests.get", return_value=_mock_nvd(_NVD_HARDWARE_HIT))
        cves = vulndb.search_cves("STM32F407", "STMicroelectronics")
        assert len(cves) == 1
        assert cves[0].cve_id == "CVE-2023-1234"
        assert cves[0].cvss_score == pytest.approx(9.8)
        assert cves[0].severity == "CRITICAL"

    def test_filters_non_hardware_cves(self, mocker):
        mocker.patch("chaintrace.hbom.vulndb.requests.get", return_value=_mock_nvd(_NVD_NON_HARDWARE_HIT))
        cves = vulndb.search_cves("PART001", "ACME")
        assert cves == []

    def test_empty_response_returns_empty_list(self, mocker):
        mocker.patch("chaintrace.hbom.vulndb.requests.get", return_value=_mock_nvd(_NVD_EMPTY))
        assert vulndb.search_cves("PART001", "ACME") == []

    def test_timeout_returns_empty_list(self, mocker):
        mocker.patch(
            "chaintrace.hbom.vulndb.requests.get",
            side_effect=requests.exceptions.Timeout("timed out"),
        )
        assert vulndb.search_cves("PART001", "ACME") == []

    def test_request_exception_returns_empty_list(self, mocker):
        mocker.patch(
            "chaintrace.hbom.vulndb.requests.get",
            side_effect=requests.exceptions.ConnectionError("refused"),
        )
        assert vulndb.search_cves("PART001", "ACME") == []

    def test_invalid_json_returns_empty_list(self, mocker):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.side_effect = ValueError("bad json")
        mocker.patch("chaintrace.hbom.vulndb.requests.get", return_value=resp)
        assert vulndb.search_cves("PART001", "ACME") == []

    def test_sends_api_key_header_when_set(self, mocker, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "test-nvd-key")
        mock_get = mocker.patch(
            "chaintrace.hbom.vulndb.requests.get", return_value=_mock_nvd(_NVD_EMPTY)
        )
        vulndb.search_cves("PART001", "ACME")
        _, kwargs = mock_get.call_args
        assert kwargs.get("headers", {}).get("apiKey") == "test-nvd-key"

    def test_empty_part_number_and_manufacturer_returns_empty(self, mocker):
        mock_get = mocker.patch("chaintrace.hbom.vulndb.requests.get")
        result = vulndb.search_cves("", "")
        assert result == []
        mock_get.assert_not_called()

    def test_description_truncated_to_400_chars(self, mocker):
        long_desc = "firmware " + "x" * 500
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-9999",
                        "descriptions": [{"lang": "en", "value": long_desc}],
                        "metrics": {},
                        "published": "2023-01-01T00:00:00.000",
                    }
                }
            ]
        }
        mocker.patch("chaintrace.hbom.vulndb.requests.get", return_value=_mock_nvd(payload))
        cves = vulndb.search_cves("PART", "MFG")
        assert len(cves[0].description) <= 400


# ---------------------------------------------------------------------------
# TestReportGenerate
# ---------------------------------------------------------------------------


class TestReportGenerate:
    def test_creates_hbom_json(self, tmp_path):
        entries = [_make_hbom_entry()]
        path = report.generate(entries, tmp_path)
        assert path.exists()
        assert path.name == "hbom.json"

    def test_returns_path_object(self, tmp_path):
        from pathlib import Path
        entries = [_make_hbom_entry()]
        path = report.generate(entries, tmp_path)
        assert isinstance(path, Path)

    def test_creates_output_dir_if_missing(self, tmp_path):
        nested = tmp_path / "a" / "b"
        entries = [_make_hbom_entry()]
        report.generate(entries, nested)
        assert nested.exists()

    def test_total_components_correct(self, tmp_path):
        entries = [_make_hbom_entry("P1"), _make_hbom_entry("P2"), _make_hbom_entry("P3")]
        path = report.generate(entries, tmp_path)
        doc = json.loads(path.read_text())
        assert doc["summary"]["total_components"] == 3

    def test_risk_distribution_counts(self, tmp_path):
        entries = [
            _make_hbom_entry("P1", risk_total=0.80, risk_category="CRITICAL"),
            _make_hbom_entry("P2", risk_total=0.60, risk_category="HIGH"),
            _make_hbom_entry("P3", risk_total=0.60, risk_category="HIGH"),
            _make_hbom_entry("P4", risk_total=0.30, risk_category="MEDIUM"),
            _make_hbom_entry("P5", risk_total=0.10, risk_category="LOW"),
        ]
        path = report.generate(entries, tmp_path)
        doc = json.loads(path.read_text())
        dist = doc["summary"]["risk_distribution"]
        assert dist["CRITICAL"] == 1
        assert dist["HIGH"] == 2
        assert dist["MEDIUM"] == 1
        assert dist["LOW"] == 1

    def test_highest_risk_sorted_by_score(self, tmp_path):
        entries = [
            _make_hbom_entry("PA", risk_total=0.10, risk_category="LOW"),
            _make_hbom_entry("PB", risk_total=0.80, risk_category="CRITICAL"),
            _make_hbom_entry("PC", risk_total=0.55, risk_category="HIGH"),
        ]
        path = report.generate(entries, tmp_path)
        doc = json.loads(path.read_text())
        highest = doc["summary"]["highest_risk"]
        assert highest[0]["part_number"] == "PB"
        assert highest[1]["part_number"] == "PC"

    def test_highest_risk_capped_at_five(self, tmp_path):
        entries = [_make_hbom_entry(f"P{i}", risk_total=float(i) / 10) for i in range(10)]
        path = report.generate(entries, tmp_path)
        doc = json.loads(path.read_text())
        assert len(doc["summary"]["highest_risk"]) == 5

    def test_components_list_length_matches(self, tmp_path):
        entries = [_make_hbom_entry(f"P{i}") for i in range(4)]
        path = report.generate(entries, tmp_path)
        doc = json.loads(path.read_text())
        assert len(doc["components"]) == 4

    def test_component_entry_has_expected_keys(self, tmp_path):
        entries = [_make_hbom_entry()]
        path = report.generate(entries, tmp_path)
        doc = json.loads(path.read_text())
        comp = doc["components"][0]
        for key in ("part_number", "manufacturer", "risk_score", "risk_category", "cves"):
            assert key in comp

    def test_generated_at_is_utc_iso(self, tmp_path):
        entries = [_make_hbom_entry()]
        path = report.generate(entries, tmp_path)
        doc = json.loads(path.read_text())
        # Basic ISO format check: contains "T" and ends with "+00:00"
        assert "T" in doc["generated_at"]
        assert "+00:00" in doc["generated_at"]


# ---------------------------------------------------------------------------
# TestPrintSummary
# ---------------------------------------------------------------------------


class TestPrintSummary:
    def test_prints_component_count(self, capsys):
        entries = [_make_hbom_entry("P1"), _make_hbom_entry("P2")]
        report.print_summary(entries)
        out = capsys.readouterr().out
        assert "2" in out

    def test_prints_hbom_path_when_provided(self, tmp_path, capsys):
        entries = [_make_hbom_entry()]
        report.print_summary(entries, hbom_path=tmp_path / "hbom.json")
        out = capsys.readouterr().out
        assert "hbom.json" in out

    def test_no_path_line_when_path_is_none(self, capsys):
        entries = [_make_hbom_entry()]
        report.print_summary(entries, hbom_path=None)
        out = capsys.readouterr().out
        assert "Report:" not in out

    def test_flagged_components_section_for_high(self, capsys):
        entries = [_make_hbom_entry("RISKY", risk_total=0.60, risk_category="HIGH")]
        report.print_summary(entries)
        out = capsys.readouterr().out
        assert "Flagged" in out
        assert "RISKY" in out

    def test_flagged_components_section_for_critical(self, capsys):
        entries = [_make_hbom_entry("DANGER", risk_total=0.85, risk_category="CRITICAL")]
        report.print_summary(entries)
        out = capsys.readouterr().out
        assert "DANGER" in out
        assert "CRITICAL" in out

    def test_low_risk_not_in_flagged(self, capsys):
        entries = [_make_hbom_entry("SAFE", risk_total=0.05, risk_category="LOW")]
        report.print_summary(entries)
        out = capsys.readouterr().out
        assert "Flagged" not in out

    def test_cve_count_shown_in_flagged(self, capsys):
        cves = [_make_vuln()]
        entries = [_make_hbom_entry("VULN", risk_total=0.60, risk_category="HIGH", cves=cves)]
        report.print_summary(entries)
        out = capsys.readouterr().out
        assert "CVE" in out

    def test_all_categories_present_in_output(self, capsys):
        entries = [
            _make_hbom_entry("P1", risk_total=0.85, risk_category="CRITICAL"),
            _make_hbom_entry("P2", risk_total=0.60, risk_category="HIGH"),
            _make_hbom_entry("P3", risk_total=0.35, risk_category="MEDIUM"),
            _make_hbom_entry("P4", risk_total=0.10, risk_category="LOW"),
        ]
        report.print_summary(entries)
        out = capsys.readouterr().out
        for cat in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert cat in out
