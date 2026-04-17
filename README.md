# GhillieSuite-EX — AI-Orchestrated Bug Bounty Pipeline

> A Python CLI that coordinates open-source security tools under an LLM-driven loop.  
> Built for personal bug bounty use. **Not a commercial or enterprise product.**

---

## What It Actually Does

GhillieSuite-EX wraps a set of well-known Go/Python security tools (subfinder, katana, nuclei, dalfox, sqlmap, etc.) and ties them together with:

1. **A Supervisor AI** — an LLM (OpenAI or Gemini) that decides which tool to run next based on what's been found so far.
2. **A SQLite state database** — stores discovered hosts, endpoints, and findings across loops so work isn't repeated.
3. **A ReconAgent** — runs the discovery pipeline sequentially and passes file-based output between tools.
4. **An ExploitAgent** — runs vuln-scan and exploitation tools, with mandatory human confirmation (HitL) before any active exploit tool fires.
5. **A ReporterAgent** — generates an HTML + JSON report from the state DB.

The tool does **not** replace manual testing. It automates the boring reconnaissance and scanning phases so you can focus on logic bugs and report writing.

---

## Architecture

```
SupervisorAgent  (LLM decision loop, max_loops iterations)
├── ReconAgent   → subfinder → dnsx → naabu → httpx → katana → gau → arjun
│                  All inter-tool handoffs via tmp/ files (no stdin piping)
├── ExploitAgent → nuclei → dalfox [HitL] → sqlmap [HitL] → ffuf
│                  + passive JS inspection, BOLA/GraphQL heuristics
└── ReporterAgent → reports/<target>_<ts>.html + .json

StateDB (SQLite @ ~/GhillieSuite-EX/ghilliesuite_state.db)
├── hosts      (domain, ip, status_code, title, tech_stack)
├── services   (host_id, port, proto)
├── endpoints  (url, params, source_tool)
├── findings   (severity, template_id, title, matched_url, evidence)
└── screenshots (optional, requires --screenshots + gowitness)
```

---

## Quick Start

### 1. Install

```bash
git clone <repo>
cd GhillieSuite-EX
python3 -m pip install -e .

# Optional: Katana headless mode for SPA targets (React/Vue/Next.js)
# python3 -m pip install playwright && playwright install chromium
```

### 2. Configure

```bash
cp .env.example .env
# Set GEMINI_API_KEY or OPENAI_API_KEY — provider auto-detected from key prefix
```

### 3. Install security tools

All tools below must be on `$PATH`. Install only the ones you need.

| Tool | Install |
|------|---------|
| subfinder | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| dnsx | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| naabu | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| httpx | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| arjun | `pip install arjun` |
| subzy | `go install github.com/lukasikic/subzy@latest` |
| gowitness | `go install github.com/sensepost/gowitness@latest` |
| nuclei | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| dalfox | `go install github.com/hahwul/dalfox/v2@latest` |
| sqlmap | `pip install sqlmap` |
| trufflehog | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| ffuf | `go install github.com/ffuf/ffuf/v2@latest` |

### 4. Verify

```bash
GhillieSuite-EX.sec check-tools   # shows which binaries are on PATH
GhillieSuite-EX.sec check-config  # validates .env + detected AI provider
```

### 5. Hunt

```bash
# Unauthenticated
GhillieSuite-EX.sec hunt \
  --target example.com \
  --scope scope_example.txt

# Authenticated — session cookie injected into httpx, katana, nuclei, dalfox, sqlmap
GhillieSuite-EX.sec hunt \
  --target app.example.com \
  --scope scope_example.txt \
  --cookies 'session=abc123; csrf=xyz' \
  --header 'Authorization: Bearer eyJhbGci...'
```

---

## CLI Reference

```
GhillieSuite-EX.sec hunt --target <domain> --scope <file|domains> [options]

Core:
  --target / -t         Primary domain to hunt                [required]
  --scope / -s          Scope: comma-sep domains or .txt file [required]
  --output / -o         Report output directory               [default: reports/]
  --evidence-dir        Evidence output directory             [default: evidence/]
  --max-loops           Max agent decision loops              [default: 15]
  --timeout             Per-tool subprocess timeout (seconds) [default: 180]

Nuclei tuning:
  --nuclei-timeout      Nuclei subprocess timeout (seconds)
  --nuclei-http-timeout Nuclei per-request timeout (seconds)
  --nuclei-rate-limit   Requests per second                   [default: 20]
  --nuclei-concurrency  Parallel template checks              [default: 10]

Execution control:
  --profile             vdp-safe | balanced | aggressive      [default: balanced]
  --stealth             Apply conservative rate limiting to all tools
  --disable-stealth     Ignore stealth signals (for lab testing)
  --force-auto          Bypass all HitL prompts (CI/CD / pre-authorised)
  --force-exploit       Skip AI filtering for exploit phase
  --safe-mode           Require HitL for every tool, including nuclei
  --allow-redirects     httpx follows HTTP redirects during recon

Auth & proxy:
  --cookie / --cookies  Session cookie string
  --header              Custom HTTP header (e.g. Authorization: Bearer ...)
  --proxy / -p          Global proxy for Python requests (http/socks5)

Optional:
  --screenshots         Enable gowitness screenshot capture
  --no-update-templates Skip nuclei -ut on startup

GhillieSuite-EX.sec check-tools   Show binary availability by profile
GhillieSuite-EX.sec check-config  Validate .env + show AI provider
GhillieSuite-EX.sec version       Show version
```

> **Note on `--proxy`:** The proxy flag is forwarded to Python's internal `httpx` calls and injected as `-proxy`/`--proxy` arguments into nuclei, katana, sqlmap, and dalfox subprocesses. It does **not** intercept traffic from tools that do not support a proxy flag natively.

---

## What Each Phase Does

### ReconAgent (always runs)

| Step | Tool | What it does |
|------|------|--------------|
| 1 | subfinder | Passive subdomain enumeration from crt.sh, VirusTotal, etc. |
| 2 | dnsx | DNS resolution — filters dead subdomains |
| 3 | naabu | Top-1000 port scan on live hosts |
| 4 | httpx | HTTP probe — status, title, tech stack detection. WAF-friendly flags (`-random-agent`, `-rl 15`) |
| 5 | katana | Web crawl — JSONL output, configurable depth. Concurrent targets via `asyncio.gather()` |
| 6 | gau | Historical URL lookup (Wayback Machine, CommonCrawl, URLScan) |
| 7 | arjun | Parameter discovery on high-value endpoints only |
| Optional | subzy | Subdomain takeover fingerprint checks |
| Optional | gowitness | Screenshot capture |

URL filtering: static assets (images, fonts, CSS, source maps) are dropped before storage. Only parameterised URLs and high-value paths (`/api/`, `/admin`, `/auth`, etc.) are kept.

### ExploitAgent

| Stage | Tool / Method | Notes |
|-------|---------------|-------|
| Vuln scan | nuclei | Severity: `medium,high,critical`. Tags: cve, sqli, xss, lfi, ssrf, rce, ssti, xxe, auth-bypass, misconfig, takeover, and more. `tech`/`disclosure` tags excluded as low-signal. |
| XSS | dalfox | Active exploitation — **always requires HitL** unless `--force-auto` |
| SQLi | sqlmap | Active exploitation — **always requires HitL** unless `--force-auto` |
| Directory fuzzing | ffuf | Runs in `balanced` and `aggressive` profiles with context-aware wordlists (PHP/Laravel, Java/Spring, Node.js) |
| JS inspection | regex | Scans crawled `.js` files for secret patterns (AWS keys, bearer tokens, GitHub tokens, etc.) and DOM-XSS sinks (`innerHTML`, `eval`, etc.) |
| Prototype pollution | regex | Passive scan of JS files for `__proto__` / `constructor.prototype` patterns. Generates an advisory finding, not a confirmed vulnerability. |
| GraphQL | introspection | Sends `__schema` query to detected `/graphql` endpoints. Reports exposed schema as informational. |
| BOLA/IDOR | httpx differential | Detects integer/UUID path segments and re-requests `id±1`. A significant response size change triggers a high-severity advisory. **This is a heuristic, not a confirmed finding.** |
| Info leak (React/Next.js) | HTTP probe | Sends `RSC: 1` header to applicable paths and checks for unexpected JSON payloads. Passive advisory only. |
| AI/LLM targets | advisory | When httpx detects AI-related tech in page title or stack, stores a prompt-injection advisory with example payloads. No automated exploitation. |
| Secret scanning | trufflehog | Scans GitHub org repositories. Runs in `balanced`/`aggressive` profiles only. |

### ReporterAgent

Generates two files in `reports/`:
- `<target>_<timestamp>.html` — HTML report with findings table, evidence excerpts, severity badges
- `<target>_<timestamp>.json` — machine-readable findings, hosts, endpoints

---

## Execution Profiles

| Profile | Active tools | Use case |
|---------|-------------|---------|
| `vdp-safe` | recon only (nuclei/dalfox/sqlmap/ffuf/trufflehog disabled) | Responsible disclosure programs with strict rules |
| `balanced` | recon + nuclei + dalfox + sqlmap + ffuf (directory) | Standard bug bounty — default |
| `aggressive` | all tools + broader ffuf coverage | VPS / pre-authorised targets |

---

## WAF / Rate-Limiting Behaviour

- **WAF cooldown:** If any tool's stdout/stderr contains a 403 Forbidden or 429 Too Many Requests string, the global executor pauses for 60 seconds before the next tool runs. This is a simple string-match heuristic, not deep traffic analysis.
- **`--stealth` mode:** Applies conservative overrides to nuclei (`-rl 15 -c 5`), sqlmap (`--delay=1 --threads=1`), ffuf (`-t 1`), and katana (`-rl 5 -delay 1`). Config values from `.env` always take final precedence over stealth overrides.
- **`--stealth` does not:** Rotate IPs, use Tor automatically, or spoof TLS fingerprints for subprocess tools.

---

## Nuclei Configuration

All nuclei flags are driven from config — nothing is hardcoded in the tool registry:

```bash
# .env overrides
NUCLEI_SEVERITY=medium,high,critical   # default (strips info/low BB noise)
NUCLEI_RATE_LIMIT=20                   # req/s
NUCLEI_CONCURRENCY=10                  # parallel templates
NUCLEI_HTTP_TIMEOUT=5                  # per-request timeout
NUCLEI_TAGS=cve,sqli,xss,...           # see config.py for full default list

# Profile overrides (applied automatically)
# vdp-safe  → severity: high,critical
# balanced  → severity: medium,high,critical (honours NUCLEI_SEVERITY)
# aggressive → severity: medium,high,critical (honours NUCLEI_SEVERITY)
```

---

## Katana Configuration

```bash
KATANA_MAX_TARGETS=10    # concurrent crawl targets (raise to 25+ on VPS)
KATANA_RATE_LIMIT=25     # req/s per target
KATANA_DEPTH=2           # crawl depth
KATANA_HEADLESS=0        # set to 1 for SPA/React targets (requires playwright)
```

Katana uses `asyncio.gather()` to crawl up to `KATANA_MAX_TARGETS` hosts concurrently, with each target writing to its own JSONL file to prevent output conflicts.

---

## Authenticated Scanning

`--cookie` and `--header` values are injected into:
- `httpx` via `-H`
- `katana` via `-H`  
- `nuclei` via `-H`
- `dalfox` via `-C` (cookie) / `-H` (header)
- `sqlmap` via `--cookie=`

Credentials are **never written to disk or `.env`**.

---

## Session Cookie Handling

Large cookie strings often contain shell-special characters. Pass them safely:

**Bash/Linux — use single quotes:**
```bash
GhillieSuite-EX.sec hunt \
  --target app.example.com \
  --scope scope.txt \
  --cookies 'session=abc123; cf_bm=...; __Host-csrf=...'
```

**PowerShell — assign to variable first:**
```powershell
$cookie = "session=abc123; cf_bm=...; __Host-csrf=..."
GhillieSuite-EX.sec hunt --target app.example.com --scope scope.txt --cookies $cookie
```

For short-lived tokens (Cloudflare, SSO), keep `--nuclei-rate-limit 3` to reduce session churn.

---

## Smart URL Filtering

`parse_katana()` and `parse_gau()` silently drop static assets and store only:
- URLs with query parameters (`?key=val`)
- High-value paths: `/api/`, `/admin`, `/auth`, `/login`, `/graphql`, `/user`, `/account`, `/upload`, `/webhook`, etc.
- `.js` files (kept for secret + sink inspection)

This avoids filling the state DB with image URLs and font requests.

---

## AI Provider

Set exactly one key — provider is auto-detected from the key prefix:

| Key prefix | Provider | Model used |
|---|---|---|
| `sk-...` | OpenAI | gpt-4o-mini |
| `AIza...` | Google Gemini | gemini-2.5-pro |

If both keys are set, OpenAI takes priority. The AI is used for:
- Supervisor planning (which agent / tool to run next)
- ExploitAgent pre-scan analysis (which URLs are worth targeting)
- Finding triage summaries in the report

AI is **not** required for the basic pipeline to run — if no key is set, the Supervisor falls back to a deterministic sequence.

---

## Extending the Tool Registry

1. **`arsenal.py`** — add a `ToolSpec` to `TOOL_REGISTRY`:

```python
"mytool": ToolSpec(
    binary="mytool",
    base_cmd=["mytool", "--target", "{target}", "--json"],
    scope_flag="--target {target}",
    category="Recon",        # Recon | VulnScan | Exploitation | Cloud
    parser="mytool",
    hitl_required=False,     # set True for anything that sends active payloads
    description="One-line description the Supervisor AI uses to decide when to run this.",
),
```

2. **`utils/parsers.py`** — add `parse_mytool(output: str, **kwargs) -> list[dict]`.

3. Register in `get_parser()` dict. Done — the Supervisor discovers it automatically.

**File I/O tools:** set `uses_output_file=True` and include `-o {output_file}` in `base_cmd`. Call `run_tool_to_file()` and pass `output_path=`. The parser receives `output_path: Path`.

---

## Safety & Ethics

- **Scope is mandatory.** `--scope` is required. Out-of-scope URLs are dropped at every layer.
- **HitL for active exploits.** `dalfox` and `sqlmap` always prompt `[Y/n]` before running. Bypass with `--force-auto` only on pre-authorised targets.
- **No automatic IP rotation.** The tool does not manage proxies, Tor circuits, or VPN switching.
- **Findings need manual verification.** BOLA diffs, prototype pollution hits, and AI advisory findings are heuristics — treat them as leads, not confirmed vulnerabilities.
- **You are responsible** for program compliance and legal authorisation before running any scan.

---

## Reports

Saved to `reports/` after each hunt:

- `<target>_<timestamp>.html` — HTML report: findings table with severity badges, evidence excerpts, host list, endpoint count, and screenshots if `--screenshots` was enabled.
- `<target>_<timestamp>.json` — all findings, hosts, and endpoints as JSON.

Evidence files (request/response captures) are saved to `evidence/` or the path set by `--evidence-dir`.

---

## License

MIT
