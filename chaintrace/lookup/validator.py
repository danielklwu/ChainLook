"""JSON validator.

Parses and validates raw JSON returned by Gemini against the expected
ComponentResult schema, guaranteeing that downstream code always receives
well-formed data.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from chaintrace.models import ComponentResult

logger = logging.getLogger(__name__)

REQUIRED_KEYS = {
    "input_query",
    "normalized_part_number",
    "component_type",
    "manufacturer",
    "manufacturer_country",
    "datasheet_url",
    "description",
    "risk_indicators",
    "confidence_score",
}


def parse(raw_response: str) -> ComponentResult:
    """Parse and validate the raw Gemini response into a :class:`ComponentResult`.

    Args:
        raw_response: Raw text returned by :func:`~chaintrace.lookup.gemini.classify`.

    Returns:
        A validated :class:`~chaintrace.models.ComponentResult` instance.

    Raises:
        ValueError: If the response is not valid JSON or is missing required fields.
    """
    text = raw_response.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Gemini response is not valid JSON: {exc}\nRaw: {text[:500]}") from exc

    validate_schema(data)

    return ComponentResult(
        input_query=str(data["input_query"]),
        normalized_part_number=str(data["normalized_part_number"]),
        component_type=str(data["component_type"]),
        manufacturer=str(data["manufacturer"]),
        manufacturer_country=data["manufacturer_country"],
        datasheet_url=data["datasheet_url"],
        description=str(data["description"]),
        risk_indicators=list(data.get("risk_indicators") or []),
        confidence_score=float(data.get("confidence_score", 0.0)),
    )


def validate_schema(data: dict[str, Any]) -> None:
    """Assert that *data* contains all required keys.

    Args:
        data: Parsed dictionary from Gemini JSON response.

    Raises:
        ValueError: Listing every missing key.
    """
    missing = REQUIRED_KEYS - data.keys()
    if missing:
        raise ValueError(f"Gemini response missing required fields: {sorted(missing)}")
