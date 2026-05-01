# ChainLook

## Product Requirements Document (PRD)

---

# 1. Overview

**ChainLook** is a standalone CLI-based hardware component lookup and supply-chain risk analysis tool. It identifies electrical components from PCB board markings, extracts structured metadata (manufacturer, part type, datasheet, risk indicators), and optionally generates a Hardware Bill of Materials (HBOM) with automated risk scoring against the NVD vulnerability database.

The system accepts component markings via CLI argument or batch input file, retrieves relevant online sources, uses Gemini to classify and structure the results into deterministic JSON, and scores each component across four risk signals. Results are cached locally for reproducibility and future analysis.

---

# 2. Problem Statement

Hardware security research often requires identifying unknown components from PCB markings. Manual lookup is:

- Time-consuming
- Inconsistent
- Not reproducible
- Difficult to log for research validation

ChainLook automates component identification and supply-chain risk assessment to support:

- Hardware inspection workflows
- Firmware trust analysis preparation
- Supply chain research and HBOM generation

---

# 3. Goals

## Primary Goals (current)

- Accept a component marking as a CLI argument, or a batch file of markings.
- Search and retrieve top N relevant web sources via SerpAPI.
- Use keyword-proximity extraction to surface the most relevant content before passing to Gemini, minimising token usage.
- Use Gemini to:
  - Identify component type, manufacturer, and country
  - Provide datasheet URL
  - Provide brief description
  - Flag risk indicators (EOL, counterfeit, export control, sanctioned entity)
- Output deterministic structured JSON per component.
- Cache full pipeline artifacts locally for reproducibility.
- Optionally run HBOM analysis (`--hbom`):
  - Query NVD for hardware-relevant CVEs per component
  - Score each component across four weighted risk signals
  - Output a flat JSON HBOM report and a CLI risk summary

---

# 4. Non-Goals (Out of Scope)

- OCR / image processing
- Knowledge graph construction
- Fabrication plant geolocation inference
- Cloud deployment
- Deep supply-chain tracing
- Interactive / REPL input mode

---

# 5. User Persona

## Primary User

- Hardware security researcher
- Comfortable with CLI
- Running locally on Linux/macOS
- Needs reproducible research artifacts

---

# 6. User Flow

### Single lookup

```
chainlook "DAC\n32031\nTI 69K\nCJ22" [--hbom]
```

System:
1. Expands literal `\n` sequences; normalises whitespace
2. Builds search query and retrieves top N URLs via SerpAPI
3. Scrapes each URL; applies keyword-proximity extraction (~1,000 chars/page)
4. Feeds aggregated content to Gemini; receives structured JSON
5. Validates and saves result to `cache/<part>.json`
6. Displays summary in terminal
7. If `--hbom`: queries NVD, scores risk, writes `cache/hbom.json`, prints risk summary

### Batch lookup

```
chainlook -i components.txt [-o run1] [--hbom]
```

System: processes each line as a separate component, writes per-component cache files under `cache/<output_name>/`, then (if `--hbom`) writes `cache/<output_name>/hbom.json` and prints an aggregate risk summary.

---

# 7. Functional Requirements

## 7.1 Input

- Accept a single component marking as a positional CLI argument.
- Accept a batch file (`-i`) with one component marking per line.
- Support literal `\n` sequences in both modes for multi-line markings.
- Require at least one of: positional argument or `-i` flag. No interactive mode.

---

## 7.2 Web Retrieval

- Query SerpAPI (Google Light engine).
- Retrieve top N ranked links (default: 3, configurable via `--top-n`).
- Extract visible text; strip scripts, styles, nav, header, footer.
- Apply keyword-proximity scoring to extract the highest-signal sentences per page, capped at ~1,000 chars/page.
- Prefer manufacturer websites, datasheet repositories, distributor listings.

---

## 7.3 AI Classification (Gemini)

Gemini must output strict JSON matching this schema:

```json
{
  "input_query": "string",
  "normalized_part_number": "string",
  "component_type": "string",
  "manufacturer": "string",
  "manufacturer_country": "string | null",
  "datasheet_url": "string | null",
  "description": "string",
  "risk_indicators": ["string"],
  "confidence_score": 0.0
}
```

`risk_indicators` contains any of: export control warnings, sanctioned entity, end-of-life (EOL), obsolete part, counterfeit warning, manufacturing region flagged in policy databases. Empty array if none found.

---

## 7.4 HBOM Risk Analysis (`--hbom`)

### Vulnerability lookup

- Query NVD CVE API v2 by `{manufacturer} {part_number}` keyword.
- Filter results to hardware-relevant CVEs by checking description for: `firmware`, `hardware`, `embedded`, `supply chain`, `physical access`, `iot`, `industrial control`, `scada`, `ics`, `microcontroller`, `bootloader`.
- Gracefully degrade (empty CVE list) on API errors to avoid blocking the pipeline.

### Risk scoring

Four weighted signals combined into a `0.0–1.0` score:

| Signal | Weight | Source |
|---|---|---|
| Country risk | 35% | Manufacturer country vs. BIS/OFAC list (CN, RU, IR, KP) |
| CVE risk | 30% | `(max_cvss / 10) × (0.7 + 0.3 × min(count/5, 1))` |
| Indicator risk | 25% | Worst-case Gemini flag: sanctioned=1.0, counterfeit=0.7, export control=0.6, EOL=0.3 |
| Confidence penalty | 10% | `1 − confidence_score` |

Categories: `LOW` < 0.25 · `MEDIUM` < 0.55 · `HIGH` < 0.75 · `CRITICAL` ≥ 0.75

### HBOM report

Flat JSON written to `<output_dir>/hbom.json`:

```json
{
  "generated_at": "ISO timestamp",
  "summary": {
    "total_components": 5,
    "risk_distribution": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 1},
    "highest_risk": [...]
  },
  "components": [
    {
      "part_number": "...",
      "manufacturer": "...",
      "manufacturer_country": "...",
      "component_type": "...",
      "datasheet_url": "...",
      "confidence_score": 0.95,
      "risk_indicators": [...],
      "risk_score": 0.67,
      "risk_category": "HIGH",
      "risk_breakdown": {...},
      "cves": [...]
    }
  ]
}
```

---

## 7.5 Local Storage

Per-component cache files written to `./cache/<normalized_part_number>.json`, storing: scraped URLs, raw scraped text, Gemini prompt, Gemini response, and structured result.

HBOM report written to `./cache/<output_name>/hbom.json` when `--hbom` is used.

---

## 7.6 CLI Output

Single lookup display:

```
Part:               DAC3203I
Manufacturer:       Texas Instruments
Country:            USA
Type:               Digital-to-Analog Converter (DAC)
Datasheet:          https://...
Risk Indicators:    end-of-life (EOL)
Confidence:         0.95
Risk Score:         0.38  [MEDIUM]      ← only shown with --hbom
```

Batch HBOM summary appended after all components:

```
=======================================================
  HBOM RISK SUMMARY
=======================================================
  Components analysed: 5
  [CRITICAL]    1  █
  ...
  Flagged components:
    [CRITICAL] STM32F407  score=0.81  sanctioned entity
  Report: cache/run1/hbom.json
=======================================================
```

---

# 8. Non-Functional Requirements

| Requirement | Target |
|------------|--------|
| Runtime (single) | Under 60 seconds |
| Runtime (HBOM) | Under 90 seconds (adds NVD API call) |
| Environment | Local execution |
| User Scope | Single-user |
| Determinism | Structured JSON output |
| Logging | Full traceability |
| Failure Handling | Graceful error output; NVD failures degrade gracefully |

---

# 9. Architecture Overview

## Package Structure

```
chainlook/
├── cli.py              entry point and pipeline orchestration
├── models.py           shared dataclasses
├── lookup/             identification pipeline
│   ├── search.py
│   ├── scraper.py
│   ├── aggregator.py   keyword-proximity extraction
│   ├── gemini.py
│   ├── validator.py
│   └── cache.py
├── hbom/               risk analysis
│   ├── vulndb.py       NVD CVE lookup
│   ├── risk_scorer.py  4-signal weighted scoring
│   └── report.py       JSON writer + CLI summary
└── providers/          extensible manufacturer data sources
    └── __init__.py     BaseProvider abstract interface
```

## Pipeline Flow

```
CLI argument / input file
        ↓
   lookup pipeline
        ├── search.py     → top N URLs
        ├── scraper.py    → raw page text
        ├── aggregator.py → compact, high-signal text (~1k chars/page)
        ├── gemini.py     → structured JSON
        ├── validator.py  → ComponentResult
        └── cache.py      → ./cache/<part>.json

        ↓  (--hbom only)
   hbom pipeline
        ├── vulndb.py     → hardware-relevant CVEs from NVD
        ├── risk_scorer.py → RiskScore (0.0–1.0 + category)
        └── report.py     → hbom.json + CLI summary
```

---

# 10. Error Handling

Must handle:

- No search results returned
- Scraping blocked or timed out (partial results tolerated)
- Gemini timeout or API error
- Invalid JSON from Gemini
- Missing datasheet URL
- NVD API timeout or rate limit (degrades to zero CVEs, does not fail)

System must never crash silently.

---

# 11. Risks & Technical Challenges

- Scraping restrictions / bot detection
- Ambiguous chip markings → low confidence score → higher confidence penalty
- Gemini hallucination (mitigated by strict JSON schema and URL citation requirement)
- Incorrect datasheet matching
- Manufacturer country inference errors
- NVD keyword search may return low-relevance CVEs for common part number strings

Mitigation:
- Strict JSON validation
- URL citation requirement in prompt
- Hardware-keyword CVE filter
- Full artifact logging for auditability

---

# 12. Future Roadmap

- OCR from PCB images
- `providers/ti.py` — TI material content / lifecycle API integration
- `providers/nxp.py`, `providers/octopart.py` — additional data sources
- Knowledge graph of suppliers
- Integration with firmware trust analysis
- SBOM/CycloneDX output compatibility
- Fabrication plant geolocation inference

---

# 13. Design Decisions (Resolved)

| Decision | Resolution |
|---|---|
| Search API provider | SerpAPI (Google Light engine) |
| Scraping library | BeautifulSoup + lxml |
| Gemini prompt strategy | Compact extracted text (~1k chars/page) via keyword-proximity scoring |
| Confidence scoring | Gemini self-reported float 0.0–1.0, used as confidence penalty in risk score |
| Risk scoring approach | Hybrid: Gemini for part ID + NVD for CVEs + static BIS/OFAC country list |
| Input mode | Flag-only (positional arg or `-i`); no interactive mode |
| HBOM format | Flat JSON with per-component entries and board-level summary |
