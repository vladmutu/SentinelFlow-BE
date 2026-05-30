# SentinelFlow User Guide

## Getting Started

SentinelFlow is a dependency security analysis platform for npm and PyPI projects. It connects to your GitHub repositories and scans your dependencies for malware, vulnerabilities, and suspicious behavior.

### Connecting Your Repositories

1. Visit the SentinelFlow landing page and click **Connect Your Repository**.
2. You will be redirected to GitHub to authorize the SentinelFlow GitHub App.
3. Select which repositories you want to grant access to.
4. After authorization you are redirected back to the dashboard at `/dashboard`.
5. Your repositories appear as cards showing name, ecosystem (npm or PyPI), and risk score if previously scanned.

Authentication uses GitHub OAuth 2.0. Your session is stored as a JWT token that expires after 60 minutes by default.

---

## The Dashboard

The `/dashboard` page lists all repositories that the SentinelFlow GitHub App can access. Each card shows:
- Repository name and visibility (public or private)
- Primary ecosystem badge (npm or PyPI)
- Aggregate risk score from the most recent scan (if any)

Click any repository card to open the repository detail page.

---

## The Repository Detail Page

This is the main analysis workspace. It has several areas:

### Left Sidebar
- Account info and logout button
- Repository selector — switch between repositories without going back to the dashboard
- Back button (arrow icon in the header) to return to the repository list

### Dependency Graph Panel
An interactive node-link diagram showing the full dependency tree for npm and/or PyPI packages. Each node represents a package. Node color reflects the latest scan verdict:
- **Emerald/Green** — clean
- **Amber/Yellow** — suspicious
- **Red** — malicious
- **Slate/Gray** — not yet scanned

Features:
- Zoom and pan with scroll wheel and drag
- Mini-map in the corner for orientation in large trees
- Compact mode for repositories with more than 80 packages — click a node to expand its subtree
- Click any node to open its **detail panel** on the right side

### Node Detail Panel
Clicking a graph node opens a detail panel showing:
- Package name, version, ecosystem
- Malware verdict and probability score
- Risk status and composite risk score
- Static analysis features (top signals)
- CVE findings
- Dynamic sandbox results (if run)
- Reputation metadata (stars, downloads, trust score, maintainers)
- **Ask AI** button — sends this package directly to the AI agent sidebar for an explanation

---

## Running a Scan

### Scan Modes

Click **Run Scan** on the repository detail page. You can choose from five scan modes:

| Mode | What it runs | Speed |
|------|-------------|-------|
| **Full** | Typosquat guard + static AST/entropy classifier + CVE lookup + reputation scoring + dynamic Firecracker sandbox | Slowest — most thorough |
| **Static + Enrichment** | Static classifier + CVE lookup + reputation scoring. No sandbox. | Medium |
| **Static only** | Just the LightGBM static classifier. No CVE or reputation data. | Fast |
| **Lightweight** | CVE lookup + reputation scoring only. No classifier. | Fast |
| **Dynamic only** | Only sandbox analysis for packages already scanned statically. | Depends on sandbox |

The **Full** mode is the recommended default for an initial scan. Use **Lightweight** for quick reputation/CVE checks on large repositories.

You can also select specific packages to scan instead of the entire dependency tree.

### Scan Progress

While a scan runs you see a progress bar and live status. The page polls for updates every 2 seconds. Package status progresses through: pending → downloading → analyzing → classifying → done.

You can cancel a running scan with the **Cancel** button.

---

## Reading Scan Results

Results are organized into four tabs:

### Static Analysis Tab
Shows results from the LightGBM malware classifier. Each row shows:
- Package name and version
- Malware verdict (clean / suspicious / malicious)
- Malware probability (0–100%)
- Composite risk score (0–100)
- Risk status
- **Ask AI** button — opens the agent sidebar with a streaming explanation

Expand a row to see:
- Top static analysis features that drove the verdict
- CVE/vulnerability details with advisory IDs and CVSS scores
- Reputation metadata (downloads, stars, trust score, maintainers, age)

### Dynamic Analysis Tab
Shows results from the Firecracker microVM behavioral sandbox. Each row shows:
- Package name and version
- IOC verdict (malicious / suspicious / clean)
- Dynamic risk score
- VM evasion detected flag
- Sandbox timeout flag
- **Ask AI** button

Expand a row to see:
- Suspicious syscall count
- Network connections with destinations
- Sensitive file writes
- IOC details: network IOCs, process IOCs, file IOCs, DNS IOCs, crypto-miner signatures

### Lightweight Tab
Shows results from reputation and CVE lookups only (no classifier). Each row shows:
- Package name and version
- Risk status
- Risk score
- **Ask AI** button

Expand a row to see full vulnerability and reputation details.

### History Tab
Shows all past scans for this repository. Each row shows the scan date, mode, ecosystem, package counts, and status. Click **View** to load the full results of that past scan into the other tabs.

---

## AI Agent Sidebar

Click the **sparkle icon** (✦) in the top-right corner of the page to open the AI agent sidebar.

The sidebar is a streaming chat powered by Mistral 7B (via Ollama) enhanced with RAG over SentinelFlow documentation.

### What the agent can help with
- **General cybersecurity questions** — CVEs, malware types, supply chain attacks, SAST/DAST, best practices
- **SentinelFlow questions** — how features work, what scores mean, how to interpret results
- **Package explanations** — click **Ask AI** on any package row or graph node to send that package's full scan data to the agent for a plain-English explanation

### Resizing the sidebar
Drag the left edge of the sidebar to resize it. There is a maximum width limit so the main content area stays usable.

### Off-topic questions
The agent will politely decline questions unrelated to software security or SentinelFlow (e.g., cooking, sports, creative writing).

---

## SBOM Export

The **SBOM** (Software Bill of Materials) feature generates a machine-readable inventory of all your dependencies with their versions, licenses, and scan verdicts.

Two formats are available:
- **JSON SBOM** — SentinelFlow's native format with full scan data included
- **CycloneDX 1.5** — industry-standard format compatible with security tooling, DORA/NIS2 compliance workflows, and supply chain tools

Click **Generate SBOM** or **CycloneDX** on the repository detail page. The file downloads immediately.

---

## Dependency Management

The **Add Dependency** panel lets you:
1. Enter a package name, optional version, and ecosystem
2. Queue multiple proposed changes
3. Click **Check Compatibility** to validate version constraints against your existing dependency tree
4. Review the compatibility report before committing changes to your repository

---

## GitHub Webhook Integration

SentinelFlow can auto-trigger scans when you push changes to your repository. When the GitHub App detects a push that modifies `package.json`, `requirements.txt`, `pyproject.toml`, or other manifest files, it automatically queues a scan.

Auto-scan is configurable per ecosystem. Contact your SentinelFlow administrator to enable or configure webhook auto-scanning.
