# GhillieSuite-EX — Advanced AI Pentesting Framework

> **AI-automated penetration testing CLI for HackerOne bug bounty hunters.**  
> Multi-agent · WAF-Resilient · Crash-Proof 4-Day Pipeline · HTML Reporting · Anti-False Positives

---

## Architecture

```
SupervisorAgent (AI decision loop)
├── ReconAgent       → subfinder → dnsx → naabu → httpx → katana → gau → arjun
│                      (file-based handoffs; host:port aware probing)
├── ExploitAgent     ? nuclei (cves/) ? nuclei ? dalfox [HitL] ? sqlmap [HitL]
│                      ffuf [HitL] · BOLA/IDOR advisor · AI Prompt Injection advisor
└── ReporterAgent    → HTML (Tailwind CSS) + JSON findings report

StateDB (SQLite via aiosqlite @ ~/GhillieSuite-EX/ghilliesuite_state.db)
├── hosts      (domain, ip, status, tech_stack, tags)
├── services   (host_id, port, proto, source_tool)
├── endpoints  (url, params — high-value only)
├── findings   (severity, title, reproducible_steps)
└── cve_cache
```

**Pipeline:** subfinder writes `tmp/subfinder_out.txt` → dnsx resolves → naabu scans ports → httpx probes host:port targets and writes `tmp/httpx_out.json` → katana/gau/arjun enrich endpoints. No stdin piping.

---

## Quick Start

### 1. Install

```bash
git clone <repo>
cd GhillieSuite-EX
pip install -e .
playwright install chromium
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
| dnsx | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| naabu | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| httpx (optional) | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| arjun | `pip install arjun` |
| subzy | `go install github.com/lukasikic/subzy@latest` |
| gowitness | `go install github.com/sensepost/gowitness@latest` |
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
  --evidence-dir        Evidence output directory             [default: evidence/]
  --max-loops           Max agent decision loops              [default: 15]
  --timeout             Per-tool timeout (seconds)            [default: 180]
  --nuclei-timeout      Nuclei-only subprocess timeout (sec)
  --nuclei-http-timeout Nuclei per-request timeout (sec)
  --rate-limit          Nuclei requests per second
  --concurrency         Nuclei parallel template checks
  --fast-nuclei         Aggressive Nuclei speed + severity filters
  --safe-mode           HitL on ALL tools                     [flag]
  --force-auto          Bypass ALL HitL prompts (CI/CD mode)  [flag]
  --force-exploit       Bypass AI filtering for exploit tools [flag]
  --stealth             Enable rate limiting for WAF evasion  [flag]
  --disable-stealth     Ignore WAF/Commander stealth signals  [flag]
  --allow-redirects     httpx follows redirects during recon  [flag]
  --no-update-templates Skip nuclei -ut on startup            [flag]
  --cookie / -c         Session cookie string (authenticated scanning)
  --header              Custom HTTP header (e.g. Authorization: Bearer ...)
  --screenshots         Enable gowitness screenshots (optional)

GhillieSuite-EX.sec check-tools   Show binary availability
GhillieSuite-EX.sec check-config  Validate .env + show detected AI provider
GhillieSuite-EX.sec version       Show version
```

---

## Attack Vectors (2026 Edition)

| Vector | Tool | HitL |
|--------|------|------|
| Subdomain enumeration | subfinder | — |
| DNS resolution | dnsx | — |
| Port discovery | naabu | — |
| Historical URL discovery | gau | — |
| Live host probing (JSON) | httpx (WAF-Bypass flags) | — |
| Web crawling (authenticated) | katana | — |
| Parameter discovery | arjun | — |
| Subdomain takeover checks | subzy | — |
| Visual recon (screenshots) | gowitness | Optional |
| CVE / misconfiguration scan | nuclei (Targeted tags) | Critical only |
| **CVE Hunter (pre-fuzz)** | **nuclei (cves/ templates)** | Critical only |
| XSS exploitation | dalfox | ✅ Always |
| SQL injection | sqlmap | ✅ Always |
| **Directory brute-force** | **ffuf (Context-Aware)** | — (Auto) |
| **SSRF parameter fuzzing** | **ffuf** | **✅ Always** (unless `--force-auto`) |
| **Cloud Metadata SSRF** | **Active Param Fuzzing** | — |
| **Cache Poisoning** | **Unkeyed Header Probe** | — |
| **BOLA / IDOR detection** | Active Differential Analysis | — |
| **React 19 RSC Parsing** | Active Leak Discovery | — |
| **Prototype Pollution** | Playwright Sandbox Verification | — |
| **WebSocket Hijacking** | Active CSWSH Probing | — |
| **AI/LLM Prompt Injection** | Passive advisor | — |
| Secret scanning | trufflehog / Regex | — |

### False Positive Suppression & HTTP Validation
All discovered findings pass through an `httpx` validation layer. 404 endpoints are downgraded to `info` (`[Historical/Inactive]`), and pages returning 200 OK with "Access Denied" or "Login Required" text in the body are flagged as `[False Positive / Fake 200]` to save triage time.

### Context-Aware Orchestration (TechStackDetector)
`ffuf` is dynamically injected with smart wordlists based on the detected tech stack (`PHP/Laravel`, `Java/Spring`, `Node.js`), drastically optimizing the directory brute-force phase.

### Deep Research & Execution (Tier 0-9 Attacks)
- **4-Stage Crash-Proof Pipeline**: The `ExploitAgent` strictly executes Recon → VulnScan → Contextual Exploitation → Advanced Logic. Every stage is wrapped in a global exception handler, guaranteeing a 100% stable 4-day unattended run.
- **WAF Resilience**: Native execution of `httpx` and `nuclei` uses rotated user-agents, request retries, strict rate limits (`-rl 150`), and fast-fail request timeouts (`-timeout 5`) to bypass active WAFs and blocklisting. Use `--rate-limit`, `--concurrency`, and `--nuclei-http-timeout` to tune; add `--stealth` to apply conservative per-tool limits while keeping fast-fail timeouts (nuclei/sqlmap/ffuf).
- **Cloud Metadata SSRF**: SSRF-prone endpoints are dynamically injected with AWS/GCP/Azure payloads (e.g., `169.254.169.254/latest/meta-data`). Responses are flagged if they contain cloud credentials or IAM profiles.
- **Cache Poisoning**: Unkeyed headers (`X-Forwarded-Host`, `X-Host`) are sent with canary hostnames to verify reflection and edge cache pollution vulnerabilities.
- **Prototype Pollution 2.0**: JS sinks are dynamically tested in a headless `playwright` sandbox to actively verify standard payload injections via `Object.assign`. Successfully poisoned objects are auto-promoted to critical severity with a VERIFIED label.
- **React 19 / Next.js Flight**: Inspects `.json` paths and passes custom `RSC: 1` headers to intercept React Server Component leaks to decode hardcoded developer secrets and insecure prop drilling payloads.
- **WebSocket Piracy**: Analyzes discovered `ws://` / `wss://` sockets for unauthenticated event ingestion (`{event: "auth"}`) and Cross-Site WebSocket Hijacking (CSWSH) without SOP blocking.

### BOLA/IDOR Detection (Differential Analysis)
The ExploitAgent scans endpoints for integer (`/user/123`) and UUID segments. When an integer ID is found, it performs active **Differential Analysis** using `httpx` to fuzz `id+1` and `id-1`. If the HTTP response length changes significantly, the finding is automatically elevated to a **CRITICAL** status with a glowing red **VERIFIED** HTML badge.

### Smart Looping & Anti-Redundancy
- **AgentSwarm Pivot**: Tools are tracked globally for zero-finding returns. Three consecutive failures on specific endpoints result in an immediate pivot to a completely new attack vector, preventing infinite dead-end probing.
- **Recon Synergy**: `subfinder` execution is aborted for root domains natively crawled by `katana` within the same cycle.

### AI / LLM Prompt Injection
When httpx detects an AI/chatbot tech stack (`ChatGPT`, `LangChain`, `Copilot`, `llm`, etc.), the host is tagged and a **high** severity advisory is stored with 8 curated prompt injection payloads (direct/indirect/template).

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

- `<target>_<timestamp>.html` ? polished, automated Tailwind CSS dashboard with AI-generated plain-English translations. Features **Visual Evidence** (embedded screenshots when `--screenshots` is enabled), request/response evidence excerpts, and **Dynamic Severity** (auto-promotion of BOLA/GraphQL hits to `CRITICAL` with a glowing red `VERIFIED` badge).
- `<target>_<timestamp>.json` ? machine-readable, all findings, hosts, endpoints.

Evidence files (request/response captures) are saved to `evidence/` by default or the directory specified by `--evidence-dir`.

---

## License

MIT
