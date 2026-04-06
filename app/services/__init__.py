"""
SentinelFlow Services

This package contains business logic services for the SentinelFlow backend.

Services:
- scanner_service: Malware detection and classification using ML models
- package_fetcher: Download package artifacts from npm / PyPI registries
- manifest_utils: Shared helpers for fetching and flattening dependency manifests
- scan_orchestrator: Background scan orchestration (parallel, per-package)
- job_runner: Swappable background-task executor
"""
