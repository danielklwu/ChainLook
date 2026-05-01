"""Web scraper module.

Fetches and extracts visible text content from a list of URLs.
Handles common scraping obstacles gracefully and never raises silently.
"""

from __future__ import annotations

import logging
import re
from typing import Sequence

import requests
from bs4 import BeautifulSoup

from chainlook.models import ScrapedPage, SearchResult

logger = logging.getLogger(__name__)


def scrape(results: Sequence[SearchResult]) -> list[ScrapedPage]:
    """Scrape textual content from each URL in *results*.

    Args:
        results: Search results whose URLs will be fetched.

    Returns:
        A list of :class:`~chainlook.models.ScrapedPage` objects, one per
        URL.  Pages that could not be fetched are included with
        ``success=False`` and a descriptive ``error`` message.
    """
    pages: list[ScrapedPage] = []
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    }

    for result in results:
        url = result.url
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            text = extract_text(response.text)
            logger.debug("Scraped %s (%d chars)", url, len(text))
            pages.append(ScrapedPage(url=url, text=text, success=True))
        except requests.exceptions.Timeout:
            msg = "Request timed out"
            logger.warning("Scrape failed [%s]: %s", url, msg)
            pages.append(ScrapedPage(url=url, text="", success=False, error=msg))
        except requests.exceptions.HTTPError as exc:
            msg = f"HTTP {exc.response.status_code}"
            logger.warning("Scrape failed [%s]: %s", url, msg)
            pages.append(ScrapedPage(url=url, text="", success=False, error=msg))
        except requests.exceptions.RequestException as exc:
            msg = str(exc)
            logger.warning("Scrape failed [%s]: %s", url, msg)
            pages.append(ScrapedPage(url=url, text="", success=False, error=msg))

    return pages


def extract_text(html: str) -> str:
    """Extract clean, readable text from raw HTML.

    Args:
        html: Raw HTML source of a page.

    Returns:
        Plain text suitable for feeding into the LLM prompt.
    """
    soup = BeautifulSoup(html, "lxml")

    for tag in soup(["script", "style", "nav", "header", "footer", "aside"]):
        tag.decompose()

    text = soup.get_text(separator=" ")
    text = re.sub(r"\s+", " ", text).strip()
    return text
