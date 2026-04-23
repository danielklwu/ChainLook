"""Tests for chaintrace.lookup.search."""

from __future__ import annotations

import os
from unittest.mock import MagicMock

import pytest
import requests

from chaintrace.lookup import search
from chaintrace.models import SearchResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_ORGANIC = [
    {
        "position": 1,
        "title": "DAC32031 Datasheet – Texas Instruments",
        "link": "https://www.ti.com/product/DAC32031",
        "snippet": "High-speed 16-bit digital-to-analog converter.",
    },
    {
        "position": 2,
        "title": "DAC32031 PDF – AllDatasheet",
        "link": "https://www.alldatasheet.com/view.jsp?Searchword=DAC32031",
        "snippet": "Download the DAC32031 datasheet for free.",
    },
    {
        "position": 3,
        "title": "DAC32031 – DigiKey",
        "link": "https://www.digikey.com/en/products/detail/DAC32031",
        "snippet": "Buy DAC32031 in stock at DigiKey.",
    },
    {
        "position": 4,
        "title": "Extra result that should be trimmed",
        "link": "https://example.com/extra",
        "snippet": "Should not appear when top_n=3.",
    },
]


def _mock_response(organic: list[dict], error: str | None = None) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    payload: dict = {"organic_results": organic}
    if error:
        payload = {"error": error}
    mock_resp.json.return_value = payload
    return mock_resp


# ---------------------------------------------------------------------------
# TestBuildQuery
# ---------------------------------------------------------------------------


class TestBuildQuery:
    def test_single_line_query(self):
        result = search.build_query("DAC32031")
        assert "DAC32031" in result

    def test_multiline_real_newlines_collapsed(self):
        result = search.build_query("DAC\n32031\nTI 69K")
        assert "\n" not in result
        assert "DAC" in result
        assert "32031" in result
        assert "TI 69K" in result

    def test_multiline_escaped_newlines_collapsed(self):
        result = search.build_query("DAC\\n32031\\nCJ22")
        assert "\\n" not in result
        assert "DAC" in result
        assert "32031" in result
        assert "CJ22" in result

    def test_extra_whitespace_collapsed(self):
        result = search.build_query("  DAC   32031  ")
        assert "  " not in result

    def test_appends_context_keywords(self):
        result = search.build_query("DAC32031")
        assert "datasheet" in result
        assert "component" in result
        assert "IC" in result

    def test_returns_single_line(self):
        result = search.build_query("DAC\n32031\nTI 69K\nCJ22")
        assert "\n" not in result


# ---------------------------------------------------------------------------
# TestSearch
# ---------------------------------------------------------------------------


class TestSearch:
    def test_returns_top_n_results(self, mocker):
        mocker.patch("chaintrace.lookup.search.requests.get",
                     return_value=_mock_response(_FAKE_ORGANIC))
        mocker.patch.dict(os.environ, {"SERPAPI_KEY": "test-key"})

        results = search.search("DAC32031 datasheet component IC", top_n=3)

        assert len(results) == 3

    def test_returns_search_result_objects(self, mocker):
        mocker.patch("chaintrace.lookup.search.requests.get",
                     return_value=_mock_response(_FAKE_ORGANIC))
        mocker.patch.dict(os.environ, {"SERPAPI_KEY": "test-key"})

        results = search.search("DAC32031 datasheet component IC", top_n=3)

        for r in results:
            assert isinstance(r, SearchResult)

    def test_result_fields_populated(self, mocker):
        mocker.patch("chaintrace.lookup.search.requests.get",
                     return_value=_mock_response(_FAKE_ORGANIC))
        mocker.patch.dict(os.environ, {"SERPAPI_KEY": "test-key"})

        results = search.search("DAC32031 datasheet component IC", top_n=3)
        first = results[0]

        assert first.url == "https://www.ti.com/product/DAC32031"
        assert first.title == "DAC32031 Datasheet – Texas Instruments"
        assert "digital-to-analog" in first.snippet

    def test_top_n_respected_when_api_returns_more(self, mocker):
        mocker.patch("chaintrace.lookup.search.requests.get",
                     return_value=_mock_response(_FAKE_ORGANIC))
        mocker.patch.dict(os.environ, {"SERPAPI_KEY": "test-key"})

        results = search.search("DAC32031", top_n=2)
        assert len(results) == 2

    def test_empty_organic_returns_empty_list(self, mocker):
        mocker.patch("chaintrace.lookup.search.requests.get",
                     return_value=_mock_response([]))
        mocker.patch.dict(os.environ, {"SERPAPI_KEY": "test-key"})

        results = search.search("UNKNOWNPART9999", top_n=3)
        assert results == []

    def test_raises_when_serpapi_key_missing(self, mocker):
        mocker.patch("chaintrace.lookup.search.os.getenv", return_value=None)

        with pytest.raises(RuntimeError, match="SERPAPI_KEY"):
            search.search("DAC32031")

    def test_raises_on_serpapi_error_payload(self, mocker):
        mocker.patch("chaintrace.lookup.search.requests.get",
                     return_value=_mock_response([], error="Invalid API key."))
        mocker.patch.dict(os.environ, {"SERPAPI_KEY": "bad-key"})

        with pytest.raises(RuntimeError, match="SerpAPI returned an error"):
            search.search("DAC32031")

    def test_raises_on_http_error(self, mocker):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError("429 Too Many Requests")
        mocker.patch("chaintrace.lookup.search.requests.get", return_value=mock_resp)
        mocker.patch.dict(os.environ, {"SERPAPI_KEY": "test-key"})

        with pytest.raises(RuntimeError, match="HTTP error"):
            search.search("DAC32031")

    def test_raises_on_timeout(self, mocker):
        mocker.patch(
            "chaintrace.lookup.search.requests.get",
            side_effect=requests.exceptions.Timeout("Connection timed out"),
        )
        mocker.patch.dict(os.environ, {"SERPAPI_KEY": "test-key"})

        with pytest.raises(RuntimeError, match="timed out"):
            search.search("DAC32031")

    def test_uses_google_light_engine(self, mocker):
        mock_get = mocker.patch("chaintrace.lookup.search.requests.get",
                                return_value=_mock_response(_FAKE_ORGANIC))
        mocker.patch.dict(os.environ, {"SERPAPI_KEY": "test-key"})

        search.search("DAC32031")

        call_kwargs = mock_get.call_args
        params = call_kwargs[1].get("params") or call_kwargs[0][1]
        assert params["engine"] == "google_light"
