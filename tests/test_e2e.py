"""End-to-end tests for the ChainLook CLI.

All external network calls (SerpAPI, scraper, Gemini, NVD) are mocked.
Tests exercise main() with real argparse + pipeline code.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from chainlook.models import ScrapedPage, SearchResult


# ---------------------------------------------------------------------------
# Shared mock data
# ---------------------------------------------------------------------------

_FAKE_SEARCH_RESULTS = [
    SearchResult(
        url="https://example.com/stm32f407",
        title="STM32F407 Datasheet",
        snippet="ARM Cortex-M4 microcontroller by STMicroelectronics.",
    )
]

_FAKE_PAGES = [
    ScrapedPage(
        url="https://example.com/stm32f407",
        text="STM32F407 is an ARM Cortex-M4 microcontroller manufactured by STMicroelectronics.",
        success=True,
    )
]

_GEMINI_JSON = json.dumps({
    "input_query": "STM32F407",
    "normalized_part_number": "STM32F407VG",
    "component_type": "Microcontroller",
    "manufacturer": "STMicroelectronics",
    "manufacturer_country": "IT",
    "datasheet_url": None,
    "description": "ARM Cortex-M4 32-bit microcontroller.",
    "risk_indicators": [],
    "confidence_score": 0.95,
})

_GEMINI_JSON_CN = json.dumps({
    "input_query": "HI3559AV100",
    "normalized_part_number": "HI3559AV100",
    "component_type": "SoC",
    "manufacturer": "HiSilicon",
    "manufacturer_country": "CN",
    "datasheet_url": None,
    "description": "HiSilicon AI SoC.",
    "risk_indicators": ["manufacturing region"],
    "confidence_score": 0.88,
})


def _patch_pipeline(mocker, gemini_json: str = _GEMINI_JSON, cves: list | None = None):
    """Patch all external calls in the lookup + HBOM pipeline."""
    mocker.patch("chainlook.lookup.search.search", return_value=_FAKE_SEARCH_RESULTS)
    mocker.patch("chainlook.lookup.scraper.scrape", return_value=_FAKE_PAGES)
    mocker.patch("chainlook.lookup.gemini.classify", return_value=gemini_json)
    mocker.patch("chainlook.hbom.vulndb.search_cves", return_value=cves or [])


# ---------------------------------------------------------------------------
# TestSingleQueryMode
# ---------------------------------------------------------------------------


class TestSingleQueryMode:
    def test_single_query_prints_part_number(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        out = capsys.readouterr().out
        assert "STM32F407VG" in out

    def test_single_query_prints_manufacturer(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        out = capsys.readouterr().out
        assert "STMicroelectronics" in out

    def test_single_query_saves_cache_file(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) == 1

    def test_single_query_hbom_generates_report(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "--hbom", "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        assert (tmp_path / "hbom.json").exists()

    def test_single_query_hbom_prints_risk_summary(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "--hbom", "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        out = capsys.readouterr().out
        assert "HBOM RISK SUMMARY" in out

    def test_single_query_hbom_shows_risk_score(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "--hbom", "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        out = capsys.readouterr().out
        assert "Risk Score:" in out

    def test_single_query_hbom_flagged_high_risk(self, mocker, monkeypatch, tmp_path, capsys):
        from chainlook.models import VulnEntry
        cves = [
            VulnEntry("CVE-2023-9999", "firmware bug in embedded device", 9.8, "CRITICAL", "2023-01-01")
        ] * 5
        _patch_pipeline(mocker, gemini_json=_GEMINI_JSON_CN, cves=cves)
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "HI3559AV100", "--hbom", "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        out = capsys.readouterr().out
        assert "HI3559AV100" in out

    def test_no_hbom_flag_skips_report(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        assert not (tmp_path / "hbom.json").exists()

    def test_no_hbom_flag_omits_risk_score_line(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        out = capsys.readouterr().out
        assert "HBOM RISK SUMMARY" not in out

    def test_version_flag_prints_version(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["chainlook", "--version"])
        from chainlook.cli import main
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "chainlook" in out


# ---------------------------------------------------------------------------
# TestBatchMode
# ---------------------------------------------------------------------------


class TestBatchMode:
    def _write_input(self, tmp_path: Path, lines: list[str]) -> Path:
        f = tmp_path / "components.txt"
        f.write_text("\n".join(lines), encoding="utf-8")
        return f

    def test_batch_processes_all_lines(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        input_file = self._write_input(tmp_path, ["STM32F407", "LM358", "ATmega328P"])
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "-i", str(input_file),
            "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        out = capsys.readouterr().out
        assert "3/3" in out

    def test_batch_creates_cache_files(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        input_file = self._write_input(tmp_path, ["STM32F407", "STM32F407", "STM32F407"])
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "-i", str(input_file),
            "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        batch_dir = tmp_path / "components"
        json_files = list(batch_dir.glob("*.json"))
        assert len(json_files) >= 1

    def test_batch_hbom_generates_report(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        input_file = self._write_input(tmp_path, ["STM32F407", "LM358"])
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "-i", str(input_file), "--hbom",
            "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        batch_dir = tmp_path / "components"
        assert (batch_dir / "hbom.json").exists()

    def test_batch_hbom_report_has_all_components(self, mocker, monkeypatch, tmp_path, capsys):
        call_count = [0]
        gemini_jsons = [_GEMINI_JSON, _GEMINI_JSON_CN]

        def rotating_classify(prompt, model=None):
            idx = call_count[0] % len(gemini_jsons)
            call_count[0] += 1
            return gemini_jsons[idx]

        mocker.patch("chainlook.lookup.search.search", return_value=_FAKE_SEARCH_RESULTS)
        mocker.patch("chainlook.lookup.scraper.scrape", return_value=_FAKE_PAGES)
        mocker.patch("chainlook.lookup.gemini.classify", side_effect=rotating_classify)
        mocker.patch("chainlook.hbom.vulndb.search_cves", return_value=[])

        input_file = self._write_input(tmp_path, ["STM32F407", "HI3559AV100"])
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "-i", str(input_file), "--hbom",
            "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        batch_dir = tmp_path / "components"
        doc = json.loads((batch_dir / "hbom.json").read_text())
        assert doc["summary"]["total_components"] == 2

    def test_batch_hbom_prints_risk_summary(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        input_file = self._write_input(tmp_path, ["STM32F407"])
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "-i", str(input_file), "--hbom",
            "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        out = capsys.readouterr().out
        assert "HBOM RISK SUMMARY" in out

    def test_batch_custom_output_name(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        input_file = self._write_input(tmp_path, ["STM32F407"])
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "-i", str(input_file), "-o", "run1",
            "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        assert (tmp_path / "run1").exists()

    def test_batch_expands_literal_backslash_n(self, mocker, monkeypatch, tmp_path, capsys):
        _patch_pipeline(mocker)
        input_file = self._write_input(tmp_path, [r"DAC\n32031\nTI"])
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "-i", str(input_file),
            "--cache-dir", str(tmp_path)
        ])
        mock_classify = mocker.patch(
            "chainlook.lookup.gemini.classify", return_value=_GEMINI_JSON
        )
        from chainlook.cli import main
        main()
        prompt_arg = mock_classify.call_args[0][0]
        # The expanded query (with real newlines) should appear in the prompt.
        assert "DAC" in prompt_arg
        assert "32031" in prompt_arg


# ---------------------------------------------------------------------------
# TestErrorCases
# ---------------------------------------------------------------------------


class TestErrorCases:
    def test_query_and_input_file_mutually_exclusive(self, monkeypatch, tmp_path, capsys):
        input_file = tmp_path / "comps.txt"
        input_file.write_text("STM32F407")
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "-i", str(input_file)
        ])
        from chainlook.cli import main
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code != 0
        err = capsys.readouterr().err
        assert "not both" in err

    def test_missing_input_file_exits_with_error(self, monkeypatch, tmp_path, capsys):
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "-i", str(tmp_path / "nonexistent.txt")
        ])
        from chainlook.cli import main
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code != 0
        err = capsys.readouterr().err
        assert "not found" in err

    def test_empty_input_file_exits_with_error(self, monkeypatch, tmp_path, capsys):
        empty_file = tmp_path / "empty.txt"
        empty_file.write_text("\n\n")
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "-i", str(empty_file)
        ])
        from chainlook.cli import main
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code != 0
        err = capsys.readouterr().err
        assert "no component" in err.lower()

    def test_top_n_flag_respected(self, mocker, monkeypatch, tmp_path, capsys):
        mock_search = mocker.patch(
            "chainlook.lookup.search.search", return_value=_FAKE_SEARCH_RESULTS
        )
        mocker.patch("chainlook.lookup.scraper.scrape", return_value=_FAKE_PAGES)
        mocker.patch("chainlook.lookup.gemini.classify", return_value=_GEMINI_JSON)
        mocker.patch("chainlook.hbom.vulndb.search_cves", return_value=[])
        monkeypatch.setattr(sys, "argv", [
            "chainlook", "STM32F407", "--top-n", "5",
            "--cache-dir", str(tmp_path)
        ])
        from chainlook.cli import main
        main()
        _, kwargs = mock_search.call_args
        assert kwargs.get("top_n") == 5
