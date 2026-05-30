# SentinelFlow Score and Status Interpretation

## Risk Score (0–100)

The **risk score** is the primary verdict for each package. It is a composite number from 0 to 100 that combines all available analysis signals.

| Score range | Status | Meaning |
|------------|--------|---------|
| 0–40 | **Clean** (green) | No significant risk signals. Package appears safe to use. |
| 41–69 | **Suspicious** (amber) | Some risk signals present — borderline classifier probability, low-severity CVEs, poor reputation, or ambiguous static features. Review before using. |
| 70–100 | **Malicious** (red) | Strong evidence of malicious intent — high classifier probability, confirmed IOCs from sandbox, critical CVEs, or a combination of multiple moderate signals. Do not use. |

A risk score of 0 means all layers found nothing concerning. A score of 100 means the dynamic sandbox observed confirmed attack behavior (reverse shells, data exfiltration, cryptocurrency mining, etc.).

---

## Malware Probability (0–100%)

The **malware probability** is the raw output of the LightGBM static classifier, expressed as a percentage. It answers: "Based on the package's code structure, how likely is it to be malicious?"

Examples:
- **5%** — code pattern is consistent with clean, typical packages
- **45%** — borderline; some suspicious patterns (e.g., eval calls, high entropy in one file) but not conclusive
- **92%** — strongly resembles known malicious packages in the training data

**Important**: malware probability is one input to the risk score, not the final verdict. A package with 60% malware probability might have a risk score of 35 if it has many downloads, long history, and no CVEs — the reputation signal pulls the score down.

---

## Malware Status

The **malware status** is derived from the classifier alone (before reputation and CVE signals are combined).

| Status | Meaning |
|--------|---------|
| **clean** | Classifier probability is below the suspicious threshold |
| **suspicious** | Classifier probability is in the borderline range — warrants review |
| **malicious** | Classifier probability is above the malicious threshold |
| **error** | The analysis failed (download error, parse error, timeout) |
| **unknown** | Analysis was not run for this package in this scan mode |

---

## Risk Status

The **risk status** is derived from the final composite risk score (incorporating all signals).

| Status | Score range | Meaning |
|--------|------------|---------|
| **clean** | 0–40 | Safe based on all available evidence |
| **suspicious** | 41–69 | Review recommended — moderate signals |
| **malicious** | 70–100 | Do not use — strong risk signals confirmed |

Risk status can differ from malware status. Example: a package with a clean classifier result but a critical unpatched CVE might have `malware_status: clean` and `risk_status: suspicious` because the CVE signals push the composite score above 40.

---

## Trust Score (0–100%)

The **trust score** reflects package ecosystem reputation, derived from Libraries.io data.

**Factors considered:**
- Package age: older packages with a long history score higher
- Monthly downloads: widely-used packages score higher
- Maintainer count: more maintainers generally = more trust (though single-maintainer packages can still be trusted if they are well-established)
- Stars and forks: community engagement signals
- SourceRank: Libraries.io's own composite quality metric

**Important nuance**: Trust score is NOT equivalent to safety. Examples:
- A package with trust score 100% can still have critical CVEs (e.g., log4j was widely trusted before CVE-2021-44228)
- A new legitimate package with 0 downloads will have a low trust score — this doesn't mean it is malicious
- Use trust score as one signal among many, not as a definitive verdict

---

## CVSS Score (0–10)

The **CVSS score** (Common Vulnerability Scoring System) is the industry standard for rating vulnerability severity.

| Score | Severity | Meaning |
|-------|---------|---------|
| 0.0 | None | Informational only |
| 0.1–3.9 | **Low** | Limited impact, often requires local access or specific conditions |
| 4.0–6.9 | **Medium** | Notable impact, may be exploitable remotely but with mitigating factors |
| 7.0–8.9 | **High** | Significant impact, often remotely exploitable |
| 9.0–10.0 | **Critical** | Maximum severity — remote code execution, no authentication required, full system compromise |

SentinelFlow displays CVSS v3.1 scores from NVD alongside OSV advisory IDs.

---

## Analysis Coverage

**Analysis coverage** tells you how completely a package was analyzed.

| Coverage | Meaning |
|---------|---------|
| **full** | All enabled analysis layers completed successfully |
| **partial** | Some layers failed or timed out — e.g., the dynamic sandbox timed out but static analysis ran, or the NVD API was unreachable |
| **none** | The package could not be analyzed (download failed, archive corrupted, etc.) |

Partial coverage still provides useful results — a partial scan that found a critical CVE is actionable even if the sandbox did not run.

---

## Scan Status

The **scan status** reflects the state of the overall scan job:

| Status | Meaning |
|--------|---------|
| **pending** | Queued but not yet started |
| **running** | Analysis in progress — packages are being downloaded and analyzed |
| **completed** | All packages were processed (some may have errored individually) |
| **failed** | The scan job itself failed (not individual packages) |
| **cancelled** | Manually cancelled by the user |

Individual packages within a completed scan can still have error status — the scan job completes as long as it processed each package (even if analysis errored on some).

---

## IOC Verdict (Dynamic Analysis)

The **IOC verdict** is determined by the host-side IOC detector after scanning all strace output and telemetry from the Firecracker sandbox.

| Verdict | Meaning |
|---------|---------|
| **malicious** | At least one high-confidence IOC was observed (reverse shell, data exfiltration, crypto miner, persistence mechanism) |
| **suspicious** | Moderate-confidence signals observed (unusual network connections, sensitive file reads) without definitive evidence |
| **clean** | No IOCs detected in the sandbox session |

---

## Scan Modes and What They Produce

| Mode | Produces |
|------|---------|
| **full** | malware_status, malware_score, risk_status, risk_score, CVE details, reputation metadata, dynamic IOC verdict |
| **static_enrichment** | malware_status, malware_score, risk_status, risk_score, CVE details, reputation metadata |
| **static** | malware_status, malware_score (risk_score uses classifier only, no CVE/reputation) |
| **lightweight** | risk_status, risk_score from CVE + reputation only (no classifier) |
| **dynamic** | dynamic IOC verdict, dynamic risk_score (supplements an existing static scan) |

---

## Static Analysis Feature Values

The static analysis tab can show individual feature values when you expand a package row. Here are the most important ones:

| Feature | What it means | High value suggests |
|---------|--------------|-------------------|
| `max_entropy` | Highest byte entropy across all files | Encrypted payload, obfuscated code |
| `eval_count` | Number of eval() calls | Dynamic code execution |
| `network_call_count` | Network function calls | Exfiltration, C2 communication |
| `child_process_exec_count` | Shell spawn calls | Executing downloaded payloads |
| `base64_in_code_count` | Base64 literals in code | Payload encoding |
| `sensitive_path_access_count` | Access to /etc/, .ssh/, cron paths | Credential theft, persistence |
| `obfuscation_index` | Composite obfuscation indicator | Deliberate code hiding |
| `unique_domains` | Distinct domain strings | C2 infrastructure, data exfiltration targets |

Feature values are on different scales — they are used as inputs to the LightGBM model which weights them appropriately. A high `eval_count` alone does not make a package malicious; it is the combination of signals that matters.
