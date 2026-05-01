# ChainLook

CLI tool for hardware component identification and supply-chain risk analysis.  
Accepts a PCB board marking, retrieves top web sources, uses Gemini to return structured component metadata, and optionally runs automated HBOM risk scoring against the NVD vulnerability database.

---

## Project Structure

```
chainlook/
├── __init__.py         # package version
├── cli.py              # CLI entry point (chainlook command)
├── models.py           # shared dataclasses (ComponentResult, RiskScore, HBOMEntry, …)
│
├── lookup/             # component identification pipeline
│   ├── search.py       # SerpAPI web search
│   ├── scraper.py      # URL fetching and text extraction
│   ├── aggregator.py   # keyword-proximity extraction for Gemini prompt
│   ├── gemini.py       # Gemini prompt construction and API call
│   ├── validator.py    # parse and validate Gemini JSON output
│   └── cache.py        # local result persistence (./cache/<part>.json)
│
├── hbom/               # Hardware Bill of Materials — risk analysis
│   ├── vulndb.py       # NVD CVE lookup filtered for hardware relevance
│   ├── risk_scorer.py  # 4-signal weighted risk scoring
│   └── report.py       # flat JSON report writer and CLI summary printer
│
└── providers/          # extensible manufacturer/registry data sources
    └── __init__.py     # BaseProvider abstract interface

tests/
├── test_search.py
├── test_scraper.py
├── test_gemini.py
├── test_validator.py
└── test_cache.py

cache/                  # git-ignored; created at runtime
.env.example            # copy to .env and add your API keys
pyproject.toml
```

---

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# 2. Install the package in editable mode (including dev extras)
pip install -e ".[dev]"

# 3. Configure API keys
cp .env.example .env
# edit .env and fill in GOOGLE_API_KEY, SERPAPI_KEY, and optionally NVD_API_KEY
```

---

## Usage

```bash
# Single component lookup (use literal \n for multi-line markings)
chainlook "DAC\n3203I\nTI 69K\nCJ22"

# Single lookup with HBOM risk report
chainlook "DAC3203I" --hbom

# Batch lookup from file (one component marking per line)
chainlook -i components.txt

# Batch with HBOM risk report written to cache/run1/hbom.json
chainlook -i components.txt -o run1 --hbom

# Skip local cache and force fresh lookup
chainlook --no-cache "DAC3203I"

# Verbose logging
chainlook -v "DAC3203I"
```

### Example output — single lookup

```
Part:               DAC3203I
Manufacturer:       Texas Instruments
Country:            USA
Type:               Digital-to-Analog Converter (DAC)
Datasheet:          https://www.ti.com/lit/ds/symlink/dac3203I.pdf
Risk Indicators:    end-of-life (EOL)
Confidence:         0.95
Risk Score:         0.38  [MEDIUM]

Description:
The DAC3203I is a high-speed 16-bit digital-to-analog converter from
Texas Instruments, used in communications and signal generation.
```

### Example output — HBOM summary (batch)

```
=======================================================
  HBOM RISK SUMMARY
=======================================================
  Components analysed: 5

  [CRITICAL]    1  █
  [HIGH]         1  █
  [MEDIUM]       2  ██
  [LOW]          1  █

  Flagged components:
    [CRITICAL] STM32F407           score=0.81  sanctioned entity
    [HIGH]     NRF52840            score=0.67  export control warning  2 CVE(s)

  Report: cache/run1/hbom.json
=======================================================
```

---

## Risk Scoring

The `--hbom` flag adds a risk score (0.0–1.0) per component, combining four signals:

| Signal | Weight | Source |
|---|---|---|
| Country risk | 35% | Manufacturer country vs. BIS/OFAC high-risk list (CN, RU, IR, KP) |
| CVE risk | 30% | NVD hardware-relevant CVEs × max CVSS score |
| Indicator risk | 25% | Gemini flags: sanctioned (1.0), counterfeit (0.7), export control (0.6), EOL (0.3) |
| Confidence penalty | 10% | `1 − confidence_score` — penalises uncertain identifications |

Categories: `LOW` < 0.25 · `MEDIUM` < 0.55 · `HIGH` < 0.75 · `CRITICAL` ≥ 0.75

---

## Running Tests

```bash
pytest
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GOOGLE_API_KEY` | Yes | Gemini API key |
| `SERPAPI_KEY` | Yes | SerpAPI key for web search |
| `NVD_API_KEY` | No | NVD API key — raises rate limit from 5 to 50 req/30s |
| `CHAINLOOK_GEMINI_MODEL` | No | Override Gemini model (default: `gemini-2.5-flash`) |
| `CHAINLOOK_CACHE_DIR` | No | Override cache directory (default: `cache/`) |
