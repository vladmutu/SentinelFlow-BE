"""AI explainability service — builds prompts and calls the local Ollama instance."""

from __future__ import annotations

import logging

import httpx

from app.api.schemas.explain import ExplainPackageRequest, ExplainPackageResponse
from app.core.config import settings

logger = logging.getLogger(__name__)


class OllamaUnavailableError(Exception):
    """Raised when the Ollama service cannot be reached."""


class OllamaResponseError(Exception):
    """Raised when Ollama returns an unexpected or non-2xx response."""


def _fmt_score(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value * 100:.1f}%"


def build_prompt(request: ExplainPackageRequest) -> str:
    """Assemble a structured Mistral prompt from all available package analysis data."""
    lines: list[str] = []

    lines.append(
        "You are a software security analyst. A developer is reviewing automated scan "
        "results for a package in their project. Explain the verdict in 3 to 5 "
        "plain-English sentences. Point out the specific risk signals that drove the "
        "verdict. If you have general knowledge about this package (its purpose, whether "
        "it is widely trusted, known supply-chain incidents, or notable CVE history), "
        "include that context briefly. Keep technical jargon minimal; assume the "
        "audience is a developer, not a security expert. Do not repeat the raw numbers "
        "verbatim — interpret what they mean."
    )
    lines.append("")

    lines.append("=== Package ===")
    lines.append(f"Name:      {request.package_name}")
    lines.append(f"Version:   {request.package_version}")
    lines.append(f"Ecosystem: {request.ecosystem or 'unknown'}")
    lines.append("")

    lines.append("=== Verdict ===")
    lines.append(
        f"Malware Classifier: {request.malware_status or 'not run'}  "
        f"Score: {_fmt_score(request.malware_score)}"
    )
    lines.append(
        f"Risk Status:        {request.risk_status or 'unknown'}  "
        f"Score: {_fmt_score(request.risk_score)}"
    )
    lines.append("")

    # Static features — top 5 by value descending
    if request.static_features:
        top5 = sorted(request.static_features.items(), key=lambda kv: kv[1], reverse=True)[:5]
        lines.append("=== Static Analysis Features (top signals) ===")
        for name, val in top5:
            lines.append(f"  {name}: {val:.4g}")
        lines.append("")

    # CVE findings
    if request.vulnerability_details:
        lines.append("=== CVE Findings ===")
        for vuln in request.vulnerability_details[:8]:
            advisory = vuln.get("advisory_id") or vuln.get("id") or "unknown"
            source = vuln.get("source") or ""
            cvss = vuln.get("value")
            desc = str(vuln.get("details") or vuln.get("description") or "")[:120]
            cvss_str = f"CVSS {cvss:.1f}" if isinstance(cvss, (int, float)) else ""
            parts = [p for p in [advisory, source, cvss_str] if p]
            lines.append(f"  {' · '.join(parts)}: {desc}")
        lines.append("")

    # Dynamic sandbox
    dyn = request.dynamic_findings
    if isinstance(dyn, dict) and dyn.get("status") not in (None, "skipped", "not_run"):
        lines.append("=== Dynamic Sandbox ===")
        lines.append(f"  Coverage:         {dyn.get('coverage', 'unknown')}")
        lines.append(f"  IOC hit:          {dyn.get('ioc_hit', False)}")
        lines.append(f"  VM evasion:       {dyn.get('vm_evasion_observed', False)}")
        lines.append(f"  Timed out:        {dyn.get('sandbox_timed_out', False)}")
        dyn_score = dyn.get("risk_score")
        if dyn_score is not None:
            lines.append(f"  Dynamic score:    {_fmt_score(float(dyn_score))}")
        ioc_detail = dyn.get("ioc_detail")
        if isinstance(ioc_detail, dict) and ioc_detail.get("verdict"):
            lines.append(f"  IOC verdict:      {ioc_detail['verdict']}")
        lines.append("")

    # Reputation
    rep = request.reputation_metadata
    if isinstance(rep, dict) and rep:
        lines.append("=== Reputation ===")
        fields = [
            ("monthly_downloads", "Monthly downloads"),
            ("stars",             "Stars"),
            ("forks",             "Forks"),
            ("trust_score",       "Trust score"),
            ("package_age_days",  "Package age (days)"),
            ("maintainer_count",  "Maintainers"),
        ]
        for key, label in fields:
            val = rep.get(key)
            if val is not None:
                lines.append(f"  {label}: {val}")
        lines.append("")

    lines.append("=== Your Explanation ===")

    return "\n".join(lines)


async def call_ollama(prompt: str) -> str:
    """POST the prompt to the local Ollama generate endpoint and return the response text.

    Raises:
        OllamaUnavailableError: When Ollama cannot be reached (connect error or timeout).
        OllamaResponseError: When Ollama returns a non-2xx status or unexpected body.
    """
    timeout = httpx.Timeout(
        connect=5.0,
        read=float(settings.ollama_timeout_seconds),
        write=10.0,
        pool=5.0,
    )
    url = f"{settings.ollama_base_url.rstrip('/')}/api/generate"
    payload = {
        "model": settings.ollama_model,
        "prompt": prompt,
        "stream": False,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload)
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        raise OllamaUnavailableError(str(exc)) from exc
    except Exception as exc:
        raise OllamaUnavailableError(f"Unexpected error contacting Ollama: {exc}") from exc

    if response.is_error:
        raise OllamaResponseError(
            f"Ollama returned HTTP {response.status_code}: {response.text[:200]}"
        )

    try:
        body = response.json()
        text: str = body["response"]
    except Exception as exc:
        raise OllamaResponseError(f"Could not parse Ollama response: {exc}") from exc

    logger.info(
        "Ollama explained %s@%s via model=%s (%d chars)",
        "package",
        "version",
        settings.ollama_model,
        len(text),
    )
    return text


async def explain_package(request: ExplainPackageRequest) -> ExplainPackageResponse:
    """Build prompt, call Ollama, and return a structured explanation response."""
    prompt = build_prompt(request)
    text = await call_ollama(prompt)
    return ExplainPackageResponse(
        explanation=text.strip(),
        model=settings.ollama_model,
        package_name=request.package_name,
        package_version=request.package_version,
    )
