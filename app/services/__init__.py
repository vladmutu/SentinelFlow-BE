"""
SentinelFlow Services

This package contains business logic services for the SentinelFlow backend.

Services:
- scanner_service: Malware detection and classification using ML models
- package_fetcher: Download package artifacts from npm / PyPI registries
- manifest_utils: Shared helpers for fetching and flattening dependency manifests
- scan_orchestrator: Background scan orchestration (parallel, per-package)
- job_runner: Swappable background-task executor
- vulnerability_service: OSV and NVD vulnerability intelligence
- dynamic_analysis_service: Remote sandbox boundary (Firecracker/generic)
- reputation_service: Package trust and reputation signal lookups
- sbom_service: SBOM generation and CycloneDX export
- typosquat_guard: Typosquatting validation for dependency-add workflow
"""
