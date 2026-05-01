"""Tests for chainlook.lookup.gemini."""

import os
from unittest.mock import MagicMock

import pytest

from chainlook.lookup import gemini

SAMPLE_QUERY = "DAC 32031 TI 69K CJ22"
SAMPLE_AGGREGATED = (
    "--- Source: https://example.com ---\n"
    "DAC32031 is a digital-to-analog converter by TI."
)
SAMPLE_JSON = '{"input_query": "DAC32031", "normalized_part_number": "DAC32031"}'


class TestBuildPrompt:
    def test_contains_query(self):
        prompt = gemini.build_prompt(SAMPLE_QUERY, SAMPLE_AGGREGATED)
        assert SAMPLE_QUERY in prompt

    def test_contains_output_schema(self):
        prompt = gemini.build_prompt(SAMPLE_QUERY, SAMPLE_AGGREGATED)
        assert "normalized_part_number" in prompt
        assert "confidence_score" in prompt

    def test_contains_aggregated_text(self):
        prompt = gemini.build_prompt(SAMPLE_QUERY, SAMPLE_AGGREGATED)
        assert SAMPLE_AGGREGATED in prompt

    def test_empty_aggregated_text_shows_placeholder(self):
        prompt = gemini.build_prompt(SAMPLE_QUERY, "")
        assert "no sources retrieved" in prompt

    def test_returns_string(self):
        assert isinstance(gemini.build_prompt(SAMPLE_QUERY, SAMPLE_AGGREGATED), str)


class TestClassify:
    def test_returns_raw_json_string(self, mocker):
        mock_response = MagicMock()
        mock_response.text = SAMPLE_JSON

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response

        mocker.patch("chainlook.lookup.gemini.genai.Client", return_value=mock_client)
        mocker.patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"})

        result = gemini.classify("some prompt")

        assert result == SAMPLE_JSON

    def test_raises_on_missing_api_key(self, mocker):
        mocker.patch.dict(os.environ, {"GOOGLE_API_KEY": ""})
        mocker.patch("chainlook.lookup.gemini.load_dotenv")

        with pytest.raises(RuntimeError, match="GOOGLE_API_KEY"):
            gemini.classify("some prompt")

    def test_raises_on_api_exception(self, mocker):
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = Exception("network failure")

        mocker.patch("chainlook.lookup.gemini.genai.Client", return_value=mock_client)
        mocker.patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"})

        with pytest.raises(RuntimeError, match="Gemini API error"):
            gemini.classify("some prompt")

    def test_calls_correct_model(self, mocker):
        mock_response = MagicMock()
        mock_response.text = SAMPLE_JSON

        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response

        mocker.patch("chainlook.lookup.gemini.genai.Client", return_value=mock_client)
        mocker.patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"})

        gemini.classify("some prompt", model="gemini-2.5-flash")

        call_kwargs = mock_client.models.generate_content.call_args
        assert call_kwargs.kwargs["model"] == "gemini-2.5-flash"
