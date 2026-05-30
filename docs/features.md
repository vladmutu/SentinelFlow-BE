# SentinelFlow Features

## Typosquatting Detection

Typosquatting is the practice of publishing malicious packages with names nearly identical to popular ones (e.g., `lodahs` instead of `lodash`, `reqeusts` instead of `requests`).

SentinelFlow's typosquatting guard runs before any analysis:
- Compares each incoming package name against a curated list of popular packages using Levenshtein edit-distance similarity scoring
- Packages with a similarity score ≥ 0.85 to a known-good package but with a different name are flagged as potential typosquats
- Configurable threshold via `TYPOSQUAT_BLOCK_THRESHOLD` (default 0.85)
- Can be disabled entirely with `TYPOSQUAT_CHECK_ENABLED=false`

This is Layer 1 of the three-layer classification pipeline.

---

## Static AST and Entropy Analysis (Layer 2)

The static analysis layer downloads each package tarball and extracts Python and JavaScript source files for deep code analysis without executing the code.

### Shannon Entropy Analysis
Shannon entropy measures the randomness of byte sequences on a scale from 0 (completely uniform) to 8 bits/byte (maximum randomness). Legitimate source code typically has entropy below 5.5. High entropy (above 6.5) often indicates encrypted payloads, packed executables, or Base64-encoded content embedded in scripts — common in malware.

SentinelFlow computes:
- `max_entropy` — highest entropy across all files in the package
- `avg_entropy` — average entropy across all Python/JavaScript files
- `entropy_gap` — difference between max and average (large gap = outlier files)

### AST Feature Extraction
The code is parsed into an Abstract Syntax Tree (AST) and over 40 features are counted:

**Code execution signals:**
- `eval_count` — calls to `eval()` (executes arbitrary code strings)
- `exec_count` — calls to `exec()` (runs dynamic code)
- `high_entropy_eval_count` — eval calls with high-entropy argument strings
- `exec_eval_ratio` — ratio of exec/eval calls to total function calls

**Dynamic code generation:**
- `new_function_count` — `new Function(...)` calls (JavaScript runtime code generation)
- `base64_count` — imports or references to Base64 modules
- `base64_in_code_count` — Base64-encoded string literals embedded in code
- `hex_literal_count` — large hexadecimal literals (often obfuscated shellcode)
- `obfuscation_index` — composite score combining entropy, identifier length, and code structure anomalies

**Network activity:**
- `network_imports` — imports of network-capable modules (requests, http, socket, fetch, axios, etc.)
- `network_call_count` — explicit network function calls
- `unique_domains` — number of distinct domain names found as string literals
- `suspicious_tlds_count` — domains with rare or suspicious top-level domains
- `high_entropy_url_in_network_count` — URLs with high-entropy subdomains (DGA-generated domains)
- `network_exec_ratio` — network calls combined with process execution (shell download pattern)

**Process and file operations:**
- `child_process_count` — spawning subprocesses (subprocess, child_process)
- `child_process_exec_count` — subprocess calls that invoke a shell
- `buffer_count` — raw buffer manipulation
- `os_env_count` — access to environment variables
- `file_read_count` — file read operations
- `file_write_count` — file write operations
- `sensitive_path_access_count` — access to sensitive paths (/etc/passwd, ~/.ssh, crontab, etc.)

**Code obfuscation:**
- `high_entropy_literal_count` — string literals with unusually high entropy
- `high_entropy_identifier_count` — variable/function names with high entropy (randomized names)
- `identifier_entropy_sum` — sum of identifier entropy across the file
- `max_ast_depth` — maximum nesting depth of the AST (deep nesting can indicate obfuscation)
- `dead_code_indicators` — unreachable or conditionally-never-executed code blocks

### LightGBM Classifier
All extracted features are fed into a LightGBM gradient-boosted tree classifier trained on a labeled dataset of benign and malicious npm/PyPI packages. The output is a probability score from 0 to 1 (probability of being malicious). A configurable threshold converts this to a verdict (benign or malicious).

---

## Vulnerability Enrichment

SentinelFlow queries two industry-standard vulnerability databases for known CVEs:

### OSV (Open Source Vulnerabilities)
- API: `https://api.osv.dev/v1/query`
- Covers npm, PyPI, Go, Rust, Maven, and more
- Returns advisory IDs, affected version ranges, references, and severity

### NVD (National Vulnerability Database)
- API: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- NIST's authoritative CVE database with CVSS v3.1 scoring
- Results include CVE IDs, CVSS scores, CWE classifications, and descriptions

Results are cached in Redis to avoid redundant API calls (configurable TTL, default 15 minutes).

Each CVE finding shows:
- Advisory ID (OSV ID or CVE ID)
- Data source
- CVSS severity score (0–10)
- Short description
- Affected version range

---

## Reputation Scoring

Package reputation provides context about a package's trustworthiness beyond its code content. A package may be technically clean but still pose risk if it is brand-new, has a single maintainer, and has almost no downloads.

SentinelFlow queries **Libraries.io** for:
- `monthly_downloads` — average monthly download count from the registry
- `stars` — GitHub star count
- `forks` — GitHub fork count
- `package_age_days` — days since the package was first published
- `maintainer_count` — number of registered maintainers
- `source_rank` — Libraries.io SourceRank composite quality score

From these, SentinelFlow derives a **trust score** (0.0–1.0, displayed as 0–100%):
- High downloads + long age + multiple maintainers → higher trust
- Brand-new package + single maintainer + zero downloads → lower trust

Reputation results are cached (default 1-hour TTL).

---

## Dynamic Sandbox Analysis (Layer 3)

The dynamic analysis layer actually executes the package inside an isolated virtual machine and observes its runtime behavior. This catches threats that static analysis cannot see — encrypted payloads, network connections made at install time, file system modifications, and persistence mechanisms.

### Firecracker MicroVM
Each analysis runs in a Firecracker microVM — a lightweight KVM-based virtual machine developed by AWS. Key properties:
- Boots in under 1 second with a minimal Linux kernel
- Completely isolated from the host: no shared filesystem, no shared network namespace
- Destroyed after each analysis (disposable)
- Resource-constrained: 1 vCPU, 1.5 GB RAM

### Guest Agent and strace Tracing
A guest agent runs inside the VM. It:
1. Receives the package artifact via vsock (a host-guest communication channel)
2. Extracts the package to a temp directory
3. Installs the package under `strace` with a curated list of 47 high-signal syscalls
4. Runs post-install execution probes (import attempts, script entry points)
5. Runs extended ambient monitoring (watches for delayed callbacks or persistence installation)
6. Streams raw strace output back to the host via vsock

Traced syscall categories: process spawning (execve, clone, fork), network (socket, connect, sendto), filesystem modifications (rename, chmod, chown, symlink, mkdir, unlink), credential manipulation (setresuid, capset), and IPC.

### IOC Detection
The host-side IOC (Indicator of Compromise) detector analyzes the raw strace stream in real time:

| IOC Category | What it detects |
|-------------|----------------|
| **Network** | Connections to public IPs, suspicious ports (4444, 6667, 31337), non-registry destinations |
| **Process** | Shell download chains (wget/curl + chmod + execute), reverse shell patterns |
| **File** | Writes to sensitive paths (/etc/shadow, .ssh/authorized_keys, crontab files) |
| **DNS** | Long subdomain labels indicating DNS-based data exfiltration or DGA |
| **Crypto mining** | Known miner process names (xmrig), stratum+tcp:// pool connections |
| **Data staging** | tar+pipe+curl chains, base64 encoding of /etc/* content |
| **Persistence** | cron job installation, .bashrc/.profile modifications, SSH key injection |

CDN and registry IPs (PyPI CDN, npm CDN, Fastly, Cloudflare, Akamai) are whitelisted.

IOC detections are weighted by analysis phase: the install phase carries 1.5× weight (most dangerous), execution probes 1.0×, ambient monitoring 0.6×.

### Dynamic Risk Score
The dynamic sandbox produces a risk score (0.0–1.0) based on the number and severity of IOC detections. This score is combined with static analysis results in the overall composite risk score. When dynamic analysis runs, it overrides static signals with a weight of 0.45.

---

## Risk Scoring

SentinelFlow combines all analysis signals into a single composite **risk score** from 0 to 100.

### Signal Weights (default configuration)

| Signal source | Weight |
|--------------|--------|
| Static classifier (LightGBM probability) | 40% |
| Static AST features | 15% |
| Vulnerability severity (CVE findings) | 30% |
| Reputation (trust score, downloads, age) | 10% |
| Dynamic sandbox (when available) | 45% override |

When dynamic analysis runs, it is given a higher effective weight that partially overrides other signals — behavioral evidence is more definitive than static heuristics.

### Score Thresholds

| Score range | Status | Color |
|------------|--------|-------|
| 0–40 | Clean | Green |
| 41–69 | Suspicious | Amber |
| 70–100 | Malicious | Red |

Thresholds are configurable via environment variables.

### Low-Confidence Suppression
If the classifier probability is below the minimum confidence threshold (default 0.35), the risk score is capped at a lower ceiling to avoid false positives. This prevents the system from flagging obfuscated-but-benign minified JavaScript as malicious.

---

## Dependency Graph Visualization

The dependency graph shows the full transitive dependency tree for your repository.

- **Technology**: ReactFlow (XyFlow) with Dagre automatic layout
- **Layout**: Ranked top-to-bottom hierarchy
- **Node colors**: reflect the latest scan verdict (green/amber/red/gray)
- **Score display**: each analyzed node shows its risk score percentage
- **Compact mode**: for repositories with more than 80 packages, subtrees collapse by default — click a node to expand its branch
- **Mini-map**: for large trees, a mini-map appears in the corner for navigation
- **Caching**: graph layout is cached in the browser for 1 hour per repository to avoid recalculating the Dagre layout on every page load

---

## SBOM Generation

SentinelFlow generates Software Bills of Materials (SBOMs) combining:
- Full dependency tree (name, version, ecosystem, direct vs. transitive)
- Scan verdicts and risk scores
- License data (fetched from npm/PyPI registry metadata)
- CVE references

### Formats

**Native JSON SBOM** — SentinelFlow's own format with all analysis data included. Useful for internal tooling and custom reporting.

**CycloneDX 1.5** — The industry-standard SBOM format. Compatible with:
- SBOM analysis tools (Dependency-Track, OWASP CycloneDX tools)
- Compliance workflows (DORA, NIS2, US Executive Order 14028)
- Software supply chain security platforms

---

## AI Explainability Agent

The SentinelFlow AI Agent is a specialized cybersecurity assistant built into the platform.

- **Model**: Mistral 7B, running locally via Ollama (no data leaves your environment)
- **Knowledge**: Enhanced with RAG (Retrieval-Augmented Generation) over SentinelFlow platform documentation
- **Streaming**: Responses appear token-by-token (typewriter effect) via Server-Sent Events
- **Scope**: General cybersecurity, SentinelFlow features and usage, scan result interpretation

The agent receives optional context from the currently loaded scan when you ask about packages. When you click "Ask AI" on a package row or graph node, the full scan data for that package is injected as context before the explanation prompt is sent to the model.

---

## GitHub Webhook Integration

SentinelFlow installs as a GitHub App and can receive push event webhooks. When enabled:
- Any push that modifies `package.json`, `requirements.txt`, `pyproject.toml`, `setup.cfg`, `Pipfile`, or `yarn.lock` triggers an automatic scan
- Configurable per-ecosystem (npm, PyPI, or both)
- HMAC-SHA256 signature verification ensures events come from GitHub
- Webhook URL can be exposed via ngrok for local development (`WEBHOOK_NGROK_ENABLED=true`)
