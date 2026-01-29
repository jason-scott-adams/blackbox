# Black Box

Personal OSINT pattern detection system.

## Overview

Black Box gathers data from 7 public sources, runs 6 pattern detectors, and outputs JSON digests for downstream analysis — whether that's a personal AI assistant, a dashboard, or a script that reads JSON.

## Installation

```bash
uv sync
uv sync --extra ml   # for anomaly/broker/rhyme detectors (numpy, networkx)
cp .env.example .env # configure API keys
```

## Usage

```bash
# Sync data sources
uv run blackbox sync rss       # 32 RSS feeds
uv run blackbox sync hibp      # Have I Been Pwned
uv run blackbox sync nvd       # NVD CVE database
uv run blackbox sync github    # GitHub Security Advisories
uv run blackbox sync noaa      # NOAA weather (MO/KS)
uv run blackbox sync earnings  # Finnhub earnings calendar
uv run blackbox sync sec       # SEC EDGAR filings
uv run blackbox sync all       # All sources

# Run pattern detection
uv run blackbox detect all     # All 6 detectors

# Generate digest
uv run blackbox digest         # Write to inbox directory
uv run blackbox digest --dry-run

# System health
uv run blackbox check
uv run blackbox db status

# Run scheduler daemon
uv run blackbox serve
```

## Data Sources

| Source | Interval | Key Required |
|--------|----------|-------------|
| RSS | 30 min | No |
| HIBP | Daily | Yes |
| NVD | 4 hours | Yes (free) |
| GitHub Advisories | 6 hours | Yes (free) |
| NOAA | Hourly | No |
| Earnings (Finnhub) | 6 hours | Yes (free) |
| SEC EDGAR | 2 hours | No |

## Pattern Detectors

| Detector | What It Finds |
|----------|--------------|
| Silence | Expected activity that stopped |
| Earnings Proximity | Upcoming earnings for tracked positions |
| Anomaly | Statistical outliers in entity data |
| Cascade | Temporal chains across entities |
| Broker | Network centrality / information gatekeepers |
| Rhyme | Sequential patterns that preceded outcomes before |

## Configuration

Copy `.env.example` to `.env` and configure API keys. See `.env.example` for all options.

## Architecture

```
Clients (7 sources) → SQLite DB → Detectors (6) → Digest JSON → inbox/
```

Runs as `blackbox.service` via systemd.

## License

MIT
