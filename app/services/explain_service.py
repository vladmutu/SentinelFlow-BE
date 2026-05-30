"""AI explainability service — builds prompts and calls the local Ollama instance."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator

import httpx

from app.api.schemas.explain import ExplainPackageRequest, ExplainPackageResponse
from app.core.config import settings
from app.services.rag_service import rag_service

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
            ("package_age_days",  "Package age (days)"),
            ("maintainer_count",  "Maintainers"),
        ]
        for key, label in fields:
            val = rep.get(key)
            if val is not None:
                lines.append(f"  {label}: {val}")
        # trust_score formatted as percentage (stored as 0.0–1.0 decimal)
        trust_val = rep.get("trust_score")
        if trust_val is not None:
            try:
                lines.append(f"  Trust score: {float(trust_val) * 100:.0f}%")
            except (TypeError, ValueError):
                lines.append(f"  Trust score: {trust_val}")
        lines.append("")

    lines.append("=== Your Explanation ===")

    return "\n".join(lines)


def build_chat_prompt(
    user_message: str,
    history: list[dict[str, str]],
    scan_context: dict[str, object] | None,
    retrieved_chunks: list[str] | None = None,
) -> str:
    """Assemble a Mistral prompt for the free-form agent chat endpoint."""
    lines: list[str] = []

    lines.append(
        "You are SentinelFlow Agent, an AI security assistant built into the "
        "SentinelFlow dependency analysis platform. You can help with:\n"
        "- General cybersecurity questions (CVEs, malware, supply chain attacks, "
        "SAST/DAST, dependency security, best practices)\n"
        "- Questions about SentinelFlow and how it works (static AST/entropy "
        "classifiers, dynamic microVM Firecracker sandbox, risk scoring, package "
        "reputation checks, SBOM generation)\n"
        "- Interpreting scan results, package verdicts, and risk signals for the "
        "current repository\n\n"
        "If the user asks about something completely unrelated to software security "
        "or this platform (e.g. cooking, sports, creative writing), politely explain "
        "that you are a specialized security assistant and redirect to security topics."
    )
    lines.append("")

    if retrieved_chunks:
        lines.append("=== SentinelFlow Knowledge Base (retrieved) ===")
        for i, chunk in enumerate(retrieved_chunks):
            lines.append(chunk.strip())
            if i < len(retrieved_chunks) - 1:
                lines.append("\n---")
        lines.append("")

    if scan_context:
        lines.append("=== Current Repository Scan Summary ===")
        repo = scan_context.get("repo_name") or "unknown"
        ecosystem = scan_context.get("ecosystem") or "unknown"
        lines.append(f"Repository: {repo}  Ecosystem: {ecosystem}")

        total = scan_context.get("total_packages")
        if total is not None:
            lines.append(f"Packages scanned: {total}")

        packages = scan_context.get("packages")
        if isinstance(packages, list) and packages:
            lines.append("Package risk summary (highest risk first):")
            for pkg in packages[:15]:
                name = pkg.get("name", "?")
                ver = pkg.get("version", "?")
                status = pkg.get("risk_status") or pkg.get("malware_status") or "unknown"
                score = pkg.get("risk_score")
                score_str = f" ({score * 100:.0f}%)" if isinstance(score, float) else ""
                lines.append(f"  {name}@{ver} — {status}{score_str}")
        lines.append("")

    if history:
        lines.append("=== Conversation History ===")
        for msg in history[:-1]:  # exclude the latest user message (added below)
            role_label = "User" if msg.get("role") == "user" else "Assistant"
            lines.append(f"{role_label}: {msg.get('content', '')}")
        lines.append("")

    lines.append(f"User: {user_message}")
    lines.append("Assistant:")

    return "\n".join(lines)


async def build_chat_prompt_with_rag(
    user_message: str,
    history: list[dict[str, str]],
    scan_context: dict[str, object] | None,
) -> str:
    """Retrieve relevant documentation chunks via RAG, then assemble the full prompt."""
    chunks: list[str] = []
    if settings.rag_enabled and settings.ollama_enabled:
        chunks = await rag_service.retrieve(
            query=user_message,
            top_k=settings.rag_top_k,
            embed_model=settings.ollama_embed_model,
            ollama_base_url=settings.ollama_base_url,
        )
    return build_chat_prompt(user_message, history, scan_context, chunks)


async def stream_ollama(prompt: str) -> AsyncGenerator[str, None]:
    """Stream tokens from Ollama's generate endpoint.

    Yields:
        str: Individual response tokens as they arrive.

    Raises:
        OllamaUnavailableError: When Ollama cannot be reached.
        OllamaResponseError: When Ollama returns a non-2xx response.
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
        "stream": True,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("POST", url, json=payload) as response:
                if response.is_error:
                    body = await response.aread()
                    raise OllamaResponseError(
                        f"Ollama returned HTTP {response.status_code}: {body[:200]}"
                    )
                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    token = chunk.get("response", "")
                    if token:
                        yield token
                    if chunk.get("done"):
                        return
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        raise OllamaUnavailableError(str(exc)) from exc
    except OllamaResponseError:
        raise
    except Exception as exc:
        raise OllamaUnavailableError(f"Unexpected error contacting Ollama: {exc}") from exc


async def explain_package(request: ExplainPackageRequest) -> ExplainPackageResponse:
    """Build prompt, stream from Ollama, and return the full concatenated explanation."""
    prompt = build_prompt(request)
    tokens: list[str] = []
    async for token in stream_ollama(prompt):
        tokens.append(token)
    text = "".join(tokens).strip()
    logger.info(
        "Explained %s@%s via model=%s (%d chars)",
        request.package_name,
        request.package_version,
        settings.ollama_model,
        len(text),
    )
    return ExplainPackageResponse(
        explanation=text,
        model=settings.ollama_model,
        package_name=request.package_name,
        package_version=request.package_version,
    )
