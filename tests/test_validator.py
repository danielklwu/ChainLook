"""Tests for chainlook.lookup.validator."""

import pytest

from chainlook.lookup import validator
from chainlook.models import ComponentResult

VALID_JSON = """\
{
  "input_query": "DAC 32031 TI 69K CJ22",
  "normalized_part_number": "DAC32031",
  "component_type": "Digital-to-Analog Converter",
  "manufacturer": "Texas Instruments",
  "manufacturer_country": "US",
  "datasheet_url": "https://www.ti.com/lit/ds/symlink/dac32031.pdf",
  "description": "High-speed 16-bit DAC.",
  "risk_indicators": [],
  "confidence_score": 0.92
}"""

MISSING_KEY_JSON = """\
{
  "input_query": "DAC 32031 TI 69K CJ22",
  "normalized_part_number": "DAC32031"
}"""


class TestParse:
    def test_valid_json_returns_component_result(self):
        result = validator.parse(VALID_JSON)
        assert isinstance(result, ComponentResult)
        assert result.normalized_part_number == "DAC32031"
        assert result.manufacturer == "Texas Instruments"
        assert result.manufacturer_country == "US"
        assert result.datasheet_url == "https://www.ti.com/lit/ds/symlink/dac32031.pdf"
        assert result.confidence_score == pytest.approx(0.92)
        assert result.risk_indicators == []

    def test_strips_markdown_fences(self):
        fenced = f"```json\n{VALID_JSON}\n```"
        result = validator.parse(fenced)
        assert isinstance(result, ComponentResult)
        assert result.normalized_part_number == "DAC32031"

    def test_strips_markdown_fences_no_language(self):
        fenced = f"```\n{VALID_JSON}\n```"
        result = validator.parse(fenced)
        assert isinstance(result, ComponentResult)

    def test_raises_on_invalid_json(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            validator.parse("this is not json {{{")

    def test_raises_on_missing_keys(self):
        with pytest.raises(ValueError, match="missing required fields"):
            validator.parse(MISSING_KEY_JSON)

    def test_null_optional_fields_allowed(self):
        json_with_nulls = VALID_JSON.replace(
            '"manufacturer_country": "US"', '"manufacturer_country": null'
        ).replace(
            '"datasheet_url": "https://www.ti.com/lit/ds/symlink/dac32031.pdf"',
            '"datasheet_url": null',
        )
        result = validator.parse(json_with_nulls)
        assert result.manufacturer_country is None
        assert result.datasheet_url is None

    def test_risk_indicators_populated(self):
        json_with_risks = VALID_JSON.replace(
            '"risk_indicators": []',
            '"risk_indicators": ["EOL", "export control warning"]',
        )
        result = validator.parse(json_with_risks)
        assert "EOL" in result.risk_indicators
        assert len(result.risk_indicators) == 2

    def test_confidence_score_coerced_to_float(self):
        json_int_score = VALID_JSON.replace('"confidence_score": 0.92', '"confidence_score": 1')
        result = validator.parse(json_int_score)
        assert isinstance(result.confidence_score, float)
        assert result.confidence_score == 1.0
