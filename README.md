# hcli.sec — AI Bug Bounty Orchestrator

> **Production-ready, AI-automated penetration testing CLI for HackerOne bug bounty hunters.**  
> Multi-agent · SQLite state · DAG concurrency · Human-in-the-Loop safe mode

---

## Architecture

```
SupervisorAgent (AI decision loop)
├── ReconAgent       → subfinder + gau (parallel), httpx, katana
├── ExploitAgent     → nuclei, dalfox [HitL], sqlmap [HitL]
└── ReporterAgent    → JSON + Markdown findings report

StateDB (SQLite via aiosqlite)
├── hosts
├── endpoints
├── findings
└── cve_cache
```

---

## Quick Start

### 1. Install

```bash
git clone <repo>
cd hcli-sec
pip install -e .
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — set GEMINI_API_KEY (required)
```

### 3. Install security tools

The orchestrator wraps these binaries — install them separately:

| Tool | Install |
|------|---------|
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| httpx | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| dalfox | `go install github.com/hahwul/dalfox/v2@latest` |
| sqlmap | `pip install sqlmap` |
| trufflehog | `go install github.com/trufflesecurity/trufflehog/v3@latest` |

### 4. Verify

```bash
hcli.sec check-tools   # shows which binaries are found on PATH
hcli.sec check-config  # validates .env API keys
```

### 5. Hunt

```bash
hcli.sec hunt \
  --target example.com \
  --scope scope_example.txt \
  --max-loops 10 \
  --timeout 180
```

Add `--safe-mode` to require Human-in-the-Loop for every tool (not just exploits).

---

## CLI Reference

```
hcli.sec hunt --target <domain> --scope <file|domains> [options]

Options:
  --target / -t         Primary domain to hunt                [required]
  --scope / -s          Scope: comma-sep domains or .txt file [required]
  --output / -o         Report output directory               [default: reports/]
  --max-loops           Max agent decision loops              [default: 15]
  --timeout             Per-tool timeout (seconds)            [default: 180]
  --ai-provider         gemini | openai                       [default: gemini]
  --safe-mode           HitL on ALL tools                     [flag]
  --no-update-templates Skip nuclei -ut on startup            [flag]

hcli.sec check-tools   Show binary availability
hcli.sec check-config  Validate .env configuration
hcli.sec version       Show version
```

---

## Extending the Tool Registry

To add a new tool:

1. **`hcli/arsenal.py`** — add a `ToolSpec` entry to `TOOL_REGISTRY`:
```python
"mynewtool": ToolSpec(
    binary="mynewtool",
    base_cmd=["mynewtool", "--target", "{target}", "--json"],
    scope_flag="--target {target}",
    category="Recon",        # or VulnScan | Exploitation | Cloud
    parser="mynewtool",
    hitl_required=False,     # set True if it sends active payloads
    description="One-line description for the AI agent.",
),
```

2. **`hcli/utils/parsers.py`** — add `parse_mynewtool(output: str) -> list[dict]`.

3. Done. The Supervisor AI will automatically discover and use the new tool via the description string.

---

## Reports

Reports are saved to `reports/` after each hunt:

- `<target>_<timestamp>.json` — machine-readable, all findings, hosts, endpoints
- `<target>_<timestamp>.md` — human-readable, severity-grouped (Critical → Low) with reproducible steps

---

## Safety & Ethics

- **Scope is mandatory.** The `--scope` flag is required and enforced at every layer.
- **HitL by default for exploits.** `dalfox` and `sqlmap` always require `[Y/n]` confirmation.
- **Never run against out-of-scope assets.** You are responsible for HackerOne program compliance.

---

## License

MIT
