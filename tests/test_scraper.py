"""Tests for chaintrace.lookup.scraper."""

from unittest.mock import MagicMock

import pytest
import requests

from chaintrace.lookup import scraper
from chaintrace.models import ScrapedPage, SearchResult

FAKE_RESULT = SearchResult(
    url="https://example.com/datasheet",
    title="Example Datasheet",
    snippet="DAC32031 digital-to-analog converter.",
)

_HTML_WITH_NOISE = """\
<html>
<head><style>body { color: red; }</style></head>
<body>
<nav>Navigation links</nav>
<header>Site header</header>
<script>alert('xss')</script>
<p>DAC32031 is a 16-bit digital-to-analog converter.</p>
<footer>Footer content</footer>
</body>
</html>"""


def _mock_get(text: str = _HTML_WITH_NOISE, status_code: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.raise_for_status = MagicMock()
    return resp


class TestScrape:
    def test_successful_scrape_returns_text(self, mocker):
        mocker.patch("chaintrace.lookup.scraper.requests.get", return_value=_mock_get())

        pages = scraper.scrape([FAKE_RESULT])

        assert len(pages) == 1
        assert pages[0].success is True
        assert len(pages[0].text) > 0

    def test_failed_scrape_http_error_returns_error_page(self, mocker):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=MagicMock(status_code=403)
        )
        mocker.patch("chaintrace.lookup.scraper.requests.get", return_value=mock_resp)

        pages = scraper.scrape([FAKE_RESULT])

        assert len(pages) == 1
        assert pages[0].success is False
        assert pages[0].error is not None

    def test_timeout_returns_error_page(self, mocker):
        mocker.patch(
            "chaintrace.lookup.scraper.requests.get",
            side_effect=requests.exceptions.Timeout("timed out"),
        )

        pages = scraper.scrape([FAKE_RESULT])

        assert pages[0].success is False
        assert "timed out" in pages[0].error.lower()

    def test_all_pages_returned_even_on_partial_failure(self, mocker):
        good_result = SearchResult(url="https://good.com", title="Good", snippet="")
        bad_result = SearchResult(url="https://bad.com", title="Bad", snippet="")

        def side_effect(url, **kwargs):
            if "bad" in url:
                raise requests.exceptions.ConnectionError("refused")
            return _mock_get()

        mocker.patch("chaintrace.lookup.scraper.requests.get", side_effect=side_effect)

        pages = scraper.scrape([good_result, bad_result])

        assert len(pages) == 2
        assert pages[0].success is True
        assert pages[1].success is False

    def test_scrape_url_preserved(self, mocker):
        mocker.patch("chaintrace.lookup.scraper.requests.get", return_value=_mock_get())

        pages = scraper.scrape([FAKE_RESULT])

        assert pages[0].url == FAKE_RESULT.url

    def test_empty_results_returns_empty_list(self, mocker):
        pages = scraper.scrape([])
        assert pages == []


class TestExtractText:
    def test_strips_script_tags(self):
        html = "<html><body><script>alert('x')</script><p>Real content</p></body></html>"
        text = scraper.extract_text(html)
        assert "alert" not in text
        assert "Real content" in text

    def test_strips_style_tags(self):
        html = "<html><body><style>body{color:red}</style><p>Visible</p></body></html>"
        text = scraper.extract_text(html)
        assert "color" not in text
        assert "Visible" in text

    def test_strips_nav_header_footer(self):
        text = scraper.extract_text(_HTML_WITH_NOISE)
        assert "Navigation links" not in text
        assert "Site header" not in text
        assert "Footer content" not in text

    def test_collapses_whitespace(self):
        html = "<html><body><p>lots   of    spaces</p></body></html>"
        text = scraper.extract_text(html)
        assert "  " not in text

    def test_preserves_main_content(self):
        text = scraper.extract_text(_HTML_WITH_NOISE)
        assert "DAC32031" in text
        assert "digital-to-analog converter" in text
