# GhillieSuite-EX — Advanced AI Pentesting Framework

> **AI-automated penetration testing CLI for HackerOne bug bounty hunters.**  
> Multi-agent · File I/O pipeline · Authenticated scanning · HTML Reporting · Anti-False Positives

---

## Architecture

```
SupervisorAgent (AI decision loop)
├── ReconAgent       → subfinder → [tmp/subfinder_out.txt] → httpx (File I/O)
│                      gau (parallel) · katana (crawl)
├── ExploitAgent     → nuclei · dalfox [HitL] · sqlmap [HitL]
│                      ffuf [HitL] · BOLA/IDOR advisor · AI Prompt Injection advisor
└── ReporterAgent    → HTML (Tailwind CSS) + JSON findings report

StateDB (SQLite via aiosqlite)
├── hosts      (domain, status, tech_stack, tags)
├── endpoints  (url, params — high-value only)
├── findings   (severity, title, reproducible_steps)
└── cve_cache
```

**Pipeline:** subfinder writes `tmp/subfinder_out.txt` → httpx reads it via `-l`, writes `tmp/httpx_out.json` → parsers read from file. No stdin piping.

---

## Quick Start

### 1. Install

```bash
git clone <repo>
cd GhillieSuite-EX
pip install -e .
```

### 2. Configure

```bash
cp .env.example .env
# Set GEMINI_API_KEY or OPENAI_API_KEY — provider is auto-detected by key prefix
```

### 3. Install security tools

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
| **ffuf** | `go install github.com/ffuf/ffuf/v2@latest` |

### 4. Verify

```bash
GhillieSuite-EX.sec check-tools   # binary availability
GhillieSuite-EX.sec check-config  # validates .env + shows detected AI provider
```

### 5. Hunt

```bash
# Standard (unauthenticated)
GhillieSuite-EX.sec hunt \
  --target example.com \
  --scope scope_example.txt

# Authenticated deep scan — injects session into ALL active tools
GhillieSuite-EX.sec hunt \
  --target app.example.com \
  --scope scope_example.txt \
  --cookie "session=abc123; csrf=xyz" \
  --header "Authorization: Bearer eyJhbGci..."
```

---

## CLI Reference

```
GhillieSuite-EX.sec hunt --target <domain> --scope <file|domains> [options]

Options:
  --target / -t         Primary domain to hunt                [required]
  --scope / -s          Scope: comma-sep domains or .txt file [required]
  --output / -o         Report output directory               [default: reports/]
  --max-loops           Max agent decision loops              [default: 15]
  --timeout             Per-tool timeout (seconds)            [default: 180]
  --safe-mode           HitL on ALL tools                     [flag]
  --force-auto          Bypass ALL HitL prompts (CI/CD mode)  [flag]
  --no-update-templates Skip nuclei -ut on startup            [flag]
  --cookie / -c         Session cookie string (authenticated scanning)
  --header              Custom HTTP header (e.g. Authorization: Bearer ...)

GhillieSuite-EX.sec check-tools   Show binary availability
GhillieSuite-EX.sec check-config  Validate .env + show detected AI provider
GhillieSuite-EX.sec version       Show version
```

---

## Attack Vectors (2026 Edition)

| Vector | Tool | HitL |
|--------|------|------|
| Subdomain enumeration | subfinder | — |
| Historical URL discovery | gau | — |
| Live host probing (JSON) | httpx | — |
| Web crawling (authenticated) | katana | — |
| CVE / misconfiguration scan | nuclei | Critical only |
| XSS exploitation | dalfox | ✅ Always |
| SQL injection | sqlmap | ✅ Always |
| **Directory brute-force** | **ffuf** | — (Auto) |
| **SSRF parameter fuzzing** | **ffuf** | **✅ Always** (unless `--force-auto`) |
| **BOLA / IDOR detection** | Active Differential Analysis | — |
| **AI/LLM Prompt Injection** | Passive advisor | — |
| Secret scanning | trufflehog | — |

### False Positive Suppression & HTTP Validation
All discovered findings pass through an `httpx` validation layer. 404 endpoints are downgraded to `info` (`[Historical/Inactive]`), and pages returning 200 OK with "Access Denied" or "Login Required" text in the body are flagged as `[False Positive / Fake 200]` to save triage time.

### BOLA/IDOR Detection (Differential Analysis)
The ExploitAgent scans endpoints for integer (`/user/123`) and UUID segments. When an integer ID is found, it performs active **Differential Analysis** using `httpx` to fuzz `id+1` and `id-1`. If the HTTP response length changes significantly, the finding is automatically elevated to a **HIGH CONFIDENCE** status.

### SSRF Parameter Fuzzing
Endpoints with SSRF-prone parameters (`url`, `path`, `redirect`, `next`, `dest`, `callback`, `proxy`, etc.) are automatically flagged. A **high** severity advisory is stored with cloud metadata endpoint payloads (AWS IMDS, GCP metadata, internal port scan).

### AI / LLM Prompt Injection
When httpx detects an AI/chatbot tech stack (`ChatGPT`, `LangChain`, `Copilot`, `llm`, etc.), the host is tagged and a **high** severity advisory is stored with 8 curated prompt injection payloads covering direct, indirect, and template-injection vectors.

---

## Smart URL Filtering

`parse_katana()` and `parse_gau()` drop static assets and store **only**:
- URLs with query parameters (`?key=val`)
- High-value paths: `/api/`, `/admin`, `/auth`, `/login`, `/graphql`, `/user`, `/account`, etc.

This preserves LLM token budget for real attack surface analysis.

---

## AI Provider (Auto-Detected)

No `AI_PROVIDER` env var needed. Set **one** key:

| Key prefix | Provider | Model |
|---|---|---|
| `sk-...` | OpenAI | gpt-4o-mini |
| `AIza...` | Google Gemini | gemini-2.5-pro |

If both are set, **OpenAI takes priority**.

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
    hitl_required=False,     # True if it sends active payloads
    description="One-line description for the AI supervisor.",
),
```

2. **`utils/parsers.py`** — add `parse_mytool(output: str) -> list[dict]`.

3. Done — the Supervisor AI auto-discovers it via the description string.

**File I/O tools:** set `uses_output_file=True` and include `-o {output_file}` in `base_cmd`. Call `run_tool_to_file()` from the agent and pass `output_path`. The parser receives `output_path: Path`.

---

## Safety & Ethics

- **Scope is mandatory.** `--scope` is required and enforced at every layer — out-of-scope URLs are silently dropped.
- **HitL by default for all active exploits.** `dalfox`, `sqlmap`, and `ffuf` SSRF testing always require `[Y/n]` human confirmation before firing. This can be completely bypassed by using the `--force-auto` CLI flag for headless CI/CD execution.
- **Passive and Active validation.** AI capabilities actively validate target endpoints natively using Python's `httpx` library, ensuring noise and false positives are aggressively reduced.
- **Auth credentials are session-only.** `--cookie` / `--header` values are never written to disk or `.env`.
- **You are responsible** for HackerOne program compliance and legal authorization.

---

## Reports

Saved to `reports/` after each hunt:

- `<target>_<timestamp>.html` — polished, automated Tailwind CSS dashboard with AI-generated plain-English translations.
- `<target>_<timestamp>.json` — machine-readable, all findings, hosts, endpoints.

---

## License

MIT
