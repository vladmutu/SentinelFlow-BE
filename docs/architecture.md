# SentinelFlow Architecture

## System Overview

SentinelFlow is a multi-service platform for dependency security analysis. It consists of five main services that work together to provide a three-layer malware detection pipeline.

```
User (Browser)
    │
    ▼
SentinelFlow-FE  (Next.js / React)          port 3000
    │
    ▼
SentinelFlow-BE  (FastAPI / PostgreSQL)     port 8000
    │
    ├──► ASTandEntropyClassificationModel Coordinator  port 8090
    │        │
    │        └──► RQ Worker containers (burst-scaled via Docker)
    │                   └──► Redis queue
    │
    └──► MicroVMService  (Firecracker microVMs)          port 8091
```

---

## Services

### SentinelFlow-FE (Frontend)
- **Technology**: Next.js 16, React 19, TypeScript, Tailwind CSS 4
- **Port**: 3000
- **Purpose**: Web UI for the platform
- **Key pages**: `/` (landing), `/login` (GitHub OAuth), `/dashboard` (repo list), `/dashboard/repo/[id]` (analysis workspace)
- **Authentication**: Initiates GitHub OAuth flow, receives JWT from backend, stores in session
- **Caching**: Browser-side IndexedDB cache with TTL for dashboard data, graph layouts, and scan results

### SentinelFlow-BE (Backend API)
- **Technology**: FastAPI, SQLAlchemy async ORM, PostgreSQL 15, asyncpg, Redis
- **Port**: 8000
- **Purpose**: Orchestrates all analysis, serves REST API to frontend, manages scan jobs
- **Database**: PostgreSQL — stores users, scan jobs, scan tasks, scan results, package source hashes
- **Key responsibilities**:
  - GitHub OAuth authentication and JWT issuance
  - Repository manifest fetching from GitHub API
  - Dependency tree resolution
  - Scan job lifecycle management
  - Calling the static analysis coordinator
  - Calling vulnerability APIs (OSV, NVD) and reputation API (Libraries.io)
  - Calling MicroVMService for dynamic analysis
  - Composite risk score calculation
  - SBOM generation
  - AI agent and explainability endpoints (Ollama/Mistral via RAG)
  - GitHub webhook processing

### ASTandEntropyClassificationModel (Static Analysis Service)
Two components:

**Coordinator** (port 8090):
- Technology: FastAPI, Redis, RQ (Redis Queue), Docker SDK
- Receives batch analysis requests from SentinelFlow-BE via `POST /jobs/{job_id}`
- Enqueues packages to Redis for worker processing
- Dynamically starts burst worker containers (up to 15 concurrent) using the Docker API
- Streams results back to SentinelFlow-BE as NDJSON

**Worker** (dynamic containers):
- Technology: Python, RQ consumer, LightGBM, esprima (JS parser), ast (Python parser)
- Downloads packages from npm registry or PyPI
- Extracts source files and computes entropy + AST features
- Runs LightGBM classifier to produce malware probability
- Posts result back to coordinator via callback URL

### MicroVMService (Dynamic Sandbox)
- **Technology**: FastAPI, Firecracker (KVM), PostgreSQL, Python
- **Port**: 8091
- **Purpose**: Layer 3 behavioral analysis — runs packages in isolated VMs and traces syscalls
- **Key components**:
  - REST API for submitting and polling analysis jobs
  - VM lifecycle manager (TAP networking, vsock CID allocation, sparse rootfs CoW copies)
  - Guest agent (runs inside VM: installs package under strace, streams telemetry)
  - IOC detector (analyzes strace output for malware indicators)
  - PostgreSQL for job/result persistence

---

## Three-Layer Classification Pipeline

Every package that SentinelFlow analyzes passes through up to three layers of analysis, each providing a different detection mechanism:

### Layer 1: Typosquatting Guard
- Runs in SentinelFlow-BE before any network I/O
- Edit-distance similarity check against popular package names
- Fast: no downloads, no API calls
- Catches: `reqeusts` (should be `requests`), `lodassh` (should be `lodash`)

### Layer 2: Static AST/Entropy Analysis
- Downloads the package tarball
- Extracts Python/JavaScript source files
- Computes 40+ features: Shannon entropy, AST call patterns, network/file/process access
- Runs LightGBM classifier: outputs malware probability 0–1
- Does NOT execute any code (static only)
- Catches: obfuscated payloads, base64-encoded shellcode, hardcoded C2 domain strings

### Layer 3: Dynamic Sandbox Analysis
- Only runs for packages flagged suspicious by Layer 2 (or when explicitly requested)
- Launches a Firecracker microVM with a minimal Linux kernel
- Installs and executes the package under strace inside the VM
- Traces 47 high-signal syscalls: process spawning, network connections, file modifications
- Host-side IOC detector analyzes the raw trace
- Catches: encrypted payloads that decrypt at runtime, network callbacks to attacker servers, post-install persistence scripts

---

## Data Flow: Full Scan

1. **User initiates scan**
   - Frontend: `POST /api/repos/{owner}/{repo}/scan` with `scan_mode=full`
   - Backend: receives request, validates auth, fetches `package.json`/`requirements.txt` from GitHub API

2. **Dependency resolution**
   - Backend resolves the full transitive dependency tree
   - Creates a `ScanJob` record (status: pending) and one `ScanTask` per package

3. **Typosquatting check**
   - Backend checks each package name against the known-good list
   - Flagged packages are marked immediately without further analysis

4. **Static analysis**
   - Backend sends all packages in a batch to the Coordinator: `POST /coordinator:8090/jobs/{job_id}`
   - Coordinator enqueues to Redis
   - Workers download packages, extract features, run classifier, callback results
   - Coordinator streams NDJSON results back to Backend
   - Backend stores results in `ScanResult` table

5. **Enrichment (parallel)**
   - Backend queries OSV + NVD for CVEs (each package in parallel, Redis-cached)
   - Backend queries Libraries.io for reputation data (parallel, Redis-cached)

6. **Dynamic analysis (conditional)**
   - For packages with malware probability above threshold (default 0.55) or with CVEs:
   - Backend posts `POST /microvm:8091/analyze` with package info
   - Polls `GET /microvm:8091/analyze/{job_id}/status` every 5 seconds
   - MicroVMService boots VM, runs package under strace, returns IOC verdict and scores

7. **Risk scoring**
   - Backend combines all signals with configured weights
   - Computes composite risk score (0–1), maps to risk status (clean/suspicious/malicious)
   - Stores final `ScanResult` with full `risk_assessment` JSON blob

8. **Frontend polling**
   - Frontend polls `GET /api/repos/{owner}/{repo}/scan/{job_id}` every 2 seconds
   - Receives live progress (processed/total packages, estimated time remaining)
   - When `status=completed`, displays results in tabs

---

## Authentication Flow

1. User clicks **Connect Your Repository** on the frontend
2. Frontend redirects to `GET /api/auth/github/login` on the backend
3. Backend redirects to GitHub OAuth authorization URL with `client_id` and `state` parameter
4. User authorizes on GitHub
5. GitHub redirects to `GET /api/auth/github/callback?code=X&state=Y`
6. Backend validates state, exchanges code for GitHub access token
7. Backend fetches GitHub user profile, creates/updates `User` record in database
8. Backend issues a JWT (HS256, configurable expiry)
9. Backend redirects to frontend with JWT in URL fragment
10. Frontend stores JWT in session, includes it as `Authorization: Bearer {jwt}` on all API calls

---

## AI Agent Architecture

The AI agent in the sidebar is backed by Mistral 7B running locally via Ollama.

### Retrieval-Augmented Generation (RAG)
At backend startup, SentinelFlow:
1. Loads documentation files from the `docs/` directory (user guide, features, score interpretation, architecture)
2. Chunks each file into semantically coherent sections (~300 tokens each)
3. Embeds each chunk using the `nomic-embed-text` model (also running locally via Ollama)
4. Stores embeddings in a ChromaDB vector store (persisted to disk, reloaded on restart)

At query time (each chat message):
1. Embeds the user's message with `nomic-embed-text`
2. Retrieves the top-3 most similar documentation chunks by cosine similarity
3. Injects the retrieved chunks into the Mistral prompt as a knowledge base section
4. Streams the response token-by-token via SSE back to the frontend

### Scope Constraints
The system prompt instructs Mistral to only answer questions about:
- General cybersecurity (CVEs, malware types, supply chain security, SAST/DAST, best practices)
- SentinelFlow platform capabilities and usage
- Scan result interpretation

Off-topic questions (cooking, sports, creative writing, etc.) are politely declined.

### Package Explanation
When the user clicks "Ask AI" on a package row or graph node, a structured prompt is built from that package's full scan data:
- Package name, version, ecosystem
- Malware verdict and probability
- Risk status and composite score
- Top static analysis features
- CVE findings (up to 8)
- Dynamic sandbox results (if available)
- Reputation metadata

Mistral interprets these signals and generates a plain-English explanation of the verdict.

---

## Database Schema Summary

### SentinelFlow-BE PostgreSQL

| Table | Purpose |
|-------|---------|
| `users` | GitHub OAuth users (github_id, username, email, avatar_url, access_token) |
| `scan_jobs` | Scan job lifecycle (owner, repo, ecosystem, mode, status, progress counters) |
| `scan_tasks` | Per-package task tracking (package, version, status, malware_score) |
| `scan_results` | Final per-package verdicts (malware_status, risk_assessment JSON, CVEs, advisory_references) |
| `repo_package_sources` | Manifest file cache with SHA-256 hash (deduplication for unchanged repos) |

### MicroVMService PostgreSQL

| Table | Purpose |
|-------|---------|
| `jobs` | Dynamic analysis jobs (package, status, risk_score) |
| `telemetry` | Per-job telemetry events from the VM guest |
| `logs` | Host and guest log lines for debugging |
| `verdicts` | IOC detection results (ioc_detail JSON) |

---

## Configuration Summary

Both services are configured via `.env` files. Key environment variables:

### SentinelFlow-BE
| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | PostgreSQL localhost:5433 | Database connection |
| `STATIC_ANALYSIS_REMOTE_URL` | http://localhost:8090 | Coordinator URL |
| `DYNAMIC_ANALYSIS_ENABLED` | false | Enable MicroVM sandbox |
| `DYNAMIC_ANALYSIS_REMOTE_URL` | http://localhost:8091 | MicroVMService URL |
| `OLLAMA_ENABLED` | true | Enable AI agent |
| `OLLAMA_BASE_URL` | http://localhost:11434 | Ollama server URL |
| `OLLAMA_MODEL` | mistral | LLM model name |
| `RAG_ENABLED` | true | Enable RAG documentation retrieval |
| `LIBRARIESIO_API_KEY` | (empty) | Required for reputation scoring |

### ASTandEntropyClassificationModel
| Variable | Default | Purpose |
|----------|---------|---------|
| `REDIS_URL` | redis://redis:6379 | Redis connection |
| `MAX_WORKERS` | 15 | Max burst worker containers |
| `JOB_TIMEOUT` | 180 | Per-package timeout (seconds) |
| `COORDINATOR_URL` | http://coordinator:8090 | Self URL for worker callbacks |
