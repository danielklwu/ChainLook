"""Tests for chainlook.lookup.cache."""

from pathlib import Path

import pytest

from chainlook.lookup import cache
from chainlook.models import CacheEntry, ComponentResult, ScrapedPage, SearchResult

SAMPLE_COMPONENT = ComponentResult(
    input_query="DAC 32031 TI 69K CJ22",
    normalized_part_number="DAC32031",
    component_type="Digital-to-Analog Converter",
    manufacturer="Texas Instruments",
    manufacturer_country="US",
    datasheet_url="https://www.ti.com/lit/ds/symlink/dac32031.pdf",
    description="High-speed 16-bit DAC.",
    risk_indicators=[],
    confidence_score=0.92,
)

SAMPLE_ENTRY = CacheEntry(
    query="DAC 32031 TI 69K CJ22",
    normalized_part_number="DAC32031",
    search_results=[
        SearchResult(url="https://example.com", title="Example", snippet="snippet"),
    ],
    scraped_pages=[
        ScrapedPage(url="https://example.com", text="page text", success=True),
    ],
    gemini_prompt="prompt text",
    gemini_response='{"normalized_part_number": "DAC32031"}',
    component_result=SAMPLE_COMPONENT,
)


class TestGetCachePath:
    def test_returns_json_extension(self):
        path = cache.get_cache_path("DAC32031")
        assert path.suffix == ".json"

    def test_filename_contains_part_number(self):
        path = cache.get_cache_path("DAC32031")
        assert "DAC32031" in path.name

    def test_sanitises_slashes(self):
        path = cache.get_cache_path("PART/WITH/SLASH")
        assert "/" not in path.name
        assert "\\" not in path.name

    def test_sanitises_spaces(self):
        path = cache.get_cache_path("PART WITH SPACE")
        assert " " not in path.name

    def test_uses_provided_cache_dir(self, tmp_path):
        path = cache.get_cache_path("DAC32031", cache_dir=tmp_path)
        assert path.parent == tmp_path


class TestSaveAndLoad:
    def test_save_creates_file(self, tmp_path):
        saved = cache.save(SAMPLE_ENTRY, cache_dir=tmp_path)
        assert saved.exists()

    def test_save_returns_path(self, tmp_path):
        saved = cache.save(SAMPLE_ENTRY, cache_dir=tmp_path)
        assert isinstance(saved, Path)

    def test_save_creates_cache_dir_if_missing(self, tmp_path):
        nested = tmp_path / "a" / "b"
        cache.save(SAMPLE_ENTRY, cache_dir=nested)
        assert nested.exists()

    def test_load_returns_component_result(self, tmp_path):
        cache.save(SAMPLE_ENTRY, cache_dir=tmp_path)
        result = cache.load("DAC32031", cache_dir=tmp_path)

        assert result is not None
        assert result.normalized_part_number == "DAC32031"
        assert result.manufacturer == "Texas Instruments"
        assert result.confidence_score == pytest.approx(0.92)

    def test_load_returns_none_on_miss(self, tmp_path):
        result = cache.load("NONEXISTENT", cache_dir=tmp_path)
        assert result is None

    def test_roundtrip_preserves_all_fields(self, tmp_path):
        cache.save(SAMPLE_ENTRY, cache_dir=tmp_path)
        loaded = cache.load("DAC32031", cache_dir=tmp_path)

        assert loaded.input_query == SAMPLE_COMPONENT.input_query
        assert loaded.component_type == SAMPLE_COMPONENT.component_type
        assert loaded.manufacturer_country == SAMPLE_COMPONENT.manufacturer_country
        assert loaded.datasheet_url == SAMPLE_COMPONENT.datasheet_url
        assert loaded.risk_indicators == SAMPLE_COMPONENT.risk_indicators


class TestExists:
    def test_true_after_save(self, tmp_path):
        cache.save(SAMPLE_ENTRY, cache_dir=tmp_path)
        assert cache.exists("DAC32031", cache_dir=tmp_path) is True

    def test_false_before_save(self, tmp_path):
        assert cache.exists("DAC32031", cache_dir=tmp_path) is False
