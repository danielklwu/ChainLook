"""Gemini prompting engine.

Constructs a structured prompt from aggregated web content, calls the
Gemini API, and returns the raw JSON response string.
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from google import genai
from google.genai import types

logger = logging.getLogger(__name__)
# Silence Google GenAI SDK and HTTP library
logging.getLogger("google_genai").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)

# Gemini model identifier. Override via CHAINTRACE_GEMINI_MODEL env var.
DEFAULT_MODEL = "gemini-2.5-flash"

# JSON schema description embedded in the system prompt so Gemini returns
# deterministic structured output.
OUTPUT_SCHEMA = """\
{
  "input_query": "string",
  "normalized_part_number": "string",
  "manufacturer": "string",
  "manufacturer_country": "string | null",
  "component_type": "string",
  "description": "string",
  "datasheet_url": "string | null",
  "risk_indicators": ["string"],
  "confidence_score": 0.0
}"""

EXAMPLE_RESPONSE = """\
{
    "input_query": "DAC32031",
    "normalized_part_number": "DAC32031",
    "manufacturer": "Texas Instruments",
    "manufacturer_country": "USA",
    "component_type": "Digital-to-Analog Converter (DAC)",
    "description": "The DAC32031 is a high-speed, 16-bit digital-to-analog converter (DAC) from Texas Instruments. It features a sampling rate of up to 500 MSPS, low power consumption, and a wide supply voltage range. The DAC32031 is commonly used in applications such as communications, instrumentation, and signal generation.",
    "datasheet_url": "https://www.ti.com/lit/ds/symlink/dac32031.pdf",
    "risk_indicators": ["end-of-life (EOL)"],
    "confidence_score": 0.95
}"""


def build_prompt(query: str, aggregated_text: str) -> str:
    """Construct the full prompt sent to Gemini.

    The prompt instructs Gemini to:
      - Act as a hardware component identification expert.
      - Use only information present in the provided source text.
      - Cite the datasheet URL directly from the sources.
      - Return *only* valid JSON matching OUTPUT_SCHEMA.

    Args:
        query:           The original (normalised) user query.
        aggregated_text: Combined text from all scraped pages.

    Returns:
        A complete prompt string ready to be sent to the Gemini API.
    """
    return f"""\
Your task is to identify an electronic component from a PCB board marking and \
extract structured metadata from the provided source content.

## Rules
- Output ONLY a single valid JSON object. No markdown fences, no prose, no explanation.
- Use only information present in the SOURCE CONTENT below. Do not hallucinate.
- For `manufacturer_country`: infer from the manufacturer name or source text; null if unknown.
- For `description`: provide a concise summary of the component's function and key characteristics, based solely on the sources.
- For `datasheet_url`: use a URL that appears verbatim in the source content, or null if none found.
- For `risk_indicators`: list any of the following if explicitly mentioned in the sources:
  export control warnings, sanctioned entity, end-of-life (EOL), obsolete part,
  counterfeit warning, manufacturing region flagged in policy databases.
  If none found, use an empty array.
- For `confidence_score`: a float from 0.0 to 1.0 reflecting how certain you are in the
  identification, based on how clearly the sources match the marking.

## Output Schema
{OUTPUT_SCHEMA}

## Board Marking (user input)
{query}

## Source Content
{aggregated_text if aggregated_text else "(no sources retrieved)"}

## Example Response
{EXAMPLE_RESPONSE}
"""


def classify(prompt: str, model: str = DEFAULT_MODEL) -> str:
    """Send *prompt* to Gemini and return the raw response text.

    Args:
        prompt: Complete prompt built by :func:`build_prompt`.
        model:  Gemini model identifier.

    Returns:
        Raw text response from the API (expected to be JSON).

    Raises:
        RuntimeError: On API authentication failure, network error, or
            response timeout.
    """
    load_dotenv()

    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GOOGLE_API_KEY environment variable is not set. "
            "Copy .env.example to .env and add your key."
        )

    client = genai.Client(api_key=api_key)

    try:
        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction="You are an expert hardware component identification system.",
                response_mime_type= 'application/json',
            )
        )
    except Exception as exc:
        raise RuntimeError(f"Gemini API error: {exc}") from exc

    logger.debug("Gemini raw response: %s", response.text)
    return response.text
