"""GitHub webhook endpoint — handles push and pull_request events.

Push events: detect manifest changes on the default branch and auto-trigger scans.
Pull-request events (opened/synchronize/reopened): scan the PR head branch, then post
a GitHub check run result and a PR comment with the findings.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from uuid import UUID

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas.webhook import WebhookResponse
from app.core.config import settings
from app.core.github_app import get_app_jwt
from app.db.session import AsyncSessionLocal, get_db
from app.models.scan import ScanJob, ScanResult
from app.services.job_runner import job_runner
from app.services.scan_orchestrator import run_scan_job

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Webhooks"])

_NPM_MANIFEST_FILES = {"package.json", "package-lock.json"}
_PYPI_MANIFEST_FILES = {"requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "Pipfile.lock"}

_STATUS_EMOJI = {
    "malicious": "🔴",
    "suspicious": "🟠",
    "clean": "🟢",
    "error": "⚪",
    "unknown": "⚪",
}


# ── Signature verification ────────────────────────────────────────────


def _verify_signature(payload_body: bytes, signature_header: str | None) -> bool:
    """Verify the GitHub webhook HMAC-SHA256 signature."""
    if not settings.github_webhook_secret or settings.github_webhook_secret.startswith("placeholder"):
        logger.warning("Webhook signature verification skipped: no real secret configured")
        return True

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected_signature = hmac.new(
        settings.github_webhook_secret.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected_signature}", signature_header)


# ── Ecosystem detection ───────────────────────────────────────────────


def _detect_manifest_changes(commits: list[dict]) -> set[str]:
    """Detect which ecosystems have manifest file changes in push commits."""
    changed_ecosystems: set[str] = set()

    for commit in commits:
        if not isinstance(commit, dict):
            continue
        changed_files: list[str] = []
        for key in ("added", "modified", "removed"):
            files = commit.get(key, [])
            if isinstance(files, list):
                changed_files.extend(f for f in files if isinstance(f, str))
        for filepath in changed_files:
            filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
            if filename in _NPM_MANIFEST_FILES:
                changed_ecosystems.add("npm")
            if filename in _PYPI_MANIFEST_FILES:
                changed_ecosystems.add("pypi")

    return changed_ecosystems


def _detect_pr_manifest_changes(pr_files: list[dict]) -> set[str]:
    """Detect which ecosystems have manifest file changes in a PR file list."""
    changed_ecosystems: set[str] = set()
    for f in pr_files:
        if not isinstance(f, dict):
            continue
        filepath = f.get("filename", "")
        filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
        if filename in _NPM_MANIFEST_FILES:
            changed_ecosystems.add("npm")
        if filename in _PYPI_MANIFEST_FILES:
            changed_ecosystems.add("pypi")
    return changed_ecosystems


# ── GitHub API helpers ────────────────────────────────────────────────


async def _get_installation_access_token(installation_id: int) -> str:
    """Create an installation access token for the GitHub App."""
    app_jwt = get_app_jwt()
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {app_jwt}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    logger.info("GitHub → POST /app/installations/%s/access_tokens (webhook)", installation_id)
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers=headers,
            json={},
        )
        if resp.is_error:
            logger.warning(
                "Failed to create installation token for installation_id=%s: HTTP %s",
                installation_id,
                resp.status_code,
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to create installation token: {resp.status_code}",
            )
        return resp.json().get("token", "")


async def _fetch_pr_changed_files(
    owner: str,
    repo: str,
    pr_number: int,
    access_token: str,
) -> list[dict]:
    """Return the list of files changed in a PR (up to 300 files)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    files: list[dict] = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        for page in range(1, 4):  # max 3 pages × 100 = 300 files
            resp = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files",
                headers=headers,
                params={"per_page": 100, "page": page},
            )
            if resp.is_error:
                logger.warning("Failed to fetch PR files: HTTP %s", resp.status_code)
                break
            page_files = resp.json()
            if not isinstance(page_files, list) or not page_files:
                break
            files.extend(page_files)
            if len(page_files) < 100:
                break
    return files


async def _create_check_run(
    owner: str,
    repo: str,
    head_sha: str,
    access_token: str,
    name: str,
) -> int | None:
    """Create an in-progress GitHub check run; returns its ID or None on failure."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/check-runs",
            headers=headers,
            json={"name": name, "head_sha": head_sha, "status": "in_progress"},
        )
        if resp.is_error:
            logger.warning("Failed to create check run: HTTP %s — %s", resp.status_code, resp.text[:200])
            return None
        return resp.json().get("id")


async def _update_check_run(
    owner: str,
    repo: str,
    check_run_id: int,
    access_token: str,
    conclusion: str,
    summary: str,
) -> None:
    """Update a GitHub check run to completed with the given conclusion and markdown summary."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    title = "SentinelFlow scan passed" if conclusion == "success" else "SentinelFlow scan detected issues"
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.patch(
            f"https://api.github.com/repos/{owner}/{repo}/check-runs/{check_run_id}",
            headers=headers,
            json={
                "status": "completed",
                "conclusion": conclusion,
                "output": {"title": title, "summary": summary},
            },
        )
        if resp.is_error:
            logger.warning("Failed to update check run %s: HTTP %s", check_run_id, resp.status_code)


async def _post_pr_comment(
    owner: str,
    repo: str,
    pr_number: int,
    body: str,
    access_token: str,
) -> None:
    """Post a comment on a pull request."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments",
            headers=headers,
            json={"body": body},
        )
        if resp.is_error:
            logger.warning("Failed to post PR comment: HTTP %s", resp.status_code)


# ── Scan report builder ───────────────────────────────────────────────


async def _build_scan_report(job_id: UUID) -> tuple[str, str]:
    """Query DB for scan results and return (conclusion, markdown_report).

    conclusion is "failure" if any package is malicious/suspicious, else "success".
    """
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(ScanResult)
                .where(ScanResult.job_id == job_id)
                .order_by(ScanResult.malware_score.desc().nullslast())
            )
        ).scalars().all()

    if not rows:
        return "neutral", "_No packages were analysed._"

    malicious = [r for r in rows if r.malware_status in {"malicious", "suspicious"}]
    clean = [r for r in rows if r.malware_status == "clean"]
    conclusion = "failure" if malicious else "success"

    header = (
        f"### SentinelFlow Dependency Scan\n\n"
        f"**{len(rows)} packages scanned** — "
        f"**{len(malicious)} issue(s) found**, {len(clean)} clean\n\n"
    )

    table_rows = [
        "| Package | Version | Status | Score |",
        "|---------|---------|--------|-------|",
    ]
    for r in rows:
        emoji = _STATUS_EMOJI.get(r.malware_status or "unknown", "⚪")
        score = f"{r.malware_score:.2f}" if r.malware_score is not None else "—"
        table_rows.append(f"| `{r.package_name}` | `{r.package_version}` | {emoji} {r.malware_status} | {score} |")

    return conclusion, header + "\n".join(table_rows)


# ── PR scan wrapper ───────────────────────────────────────────────────


async def run_pr_scan_job(
    job_id: UUID,
    owner: str,
    repo: str,
    ecosystem: str,
    access_token: str,
    head_sha: str,
    pr_number: int,
    check_run_id: int | None,
) -> None:
    """Run a full scan on the PR head branch, then post check run + PR comment."""
    try:
        await run_scan_job(
            job_id=job_id,
            owner=owner,
            repo=repo,
            ecosystem=ecosystem,
            access_token=access_token,
            scan_mode="full",
            ref=head_sha,
        )
    finally:
        conclusion, report = await _build_scan_report(job_id)
        if check_run_id is not None:
            await _update_check_run(owner, repo, check_run_id, access_token, conclusion, report)
        await _post_pr_comment(owner, repo, pr_number, report, access_token)


# ── Webhook endpoint ──────────────────────────────────────────────────


@router.post("/github", response_model=WebhookResponse)
async def handle_github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
    db: AsyncSession = Depends(get_db),
) -> WebhookResponse:
    """Receive GitHub webhook events and auto-trigger scans on push or pull_request."""
    body = await request.body()

    if not _verify_signature(body, x_hub_signature_256):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid webhook signature",
        )

    event_type = (x_github_event or "").lower()
    logger.info("Received webhook event=%s delivery=%s", event_type, x_github_delivery or "unknown")

    if event_type == "ping":
        return WebhookResponse(status="ok", message="pong")

    if event_type in {"installation", "installation_repositories"}:
        logger.info("Installation event received: %s", event_type)
        return WebhookResponse(status="ok", message=f"Installation event acknowledged: {event_type}")

    # ── Parse JSON body (shared by push + pull_request handlers) ─────
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return WebhookResponse(status="error", message="Invalid JSON payload")

    if not isinstance(payload, dict):
        return WebhookResponse(status="error", message="Invalid payload format")

    # ── Push ──────────────────────────────────────────────────────────
    if event_type == "push":
        if not settings.webhook_auto_scan_enabled:
            return WebhookResponse(status="ok", message="Auto-scan disabled")

        repo_data = payload.get("repository", {})
        if not isinstance(repo_data, dict):
            return WebhookResponse(status="ok", message="No repository data")

        repo_name = repo_data.get("name", "")
        owner_data = repo_data.get("owner", {})
        owner = owner_data.get("login", "") if isinstance(owner_data, dict) else ""

        if not owner or not repo_name:
            return WebhookResponse(status="ok", message="Missing repository identity")

        commits = payload.get("commits", [])
        if not isinstance(commits, list):
            commits = []

        changed_ecosystems = _detect_manifest_changes(commits)
        configured = {e.strip().lower() for e in settings.webhook_auto_scan_ecosystems.split(",") if e.strip()}
        ecosystems_to_scan = changed_ecosystems & configured

        if not ecosystems_to_scan:
            return WebhookResponse(status="ok", message="No relevant manifest changes detected")

        installation = payload.get("installation", {})
        installation_id = installation.get("id") if isinstance(installation, dict) else None

        if not installation_id:
            return WebhookResponse(status="error", message="No installation context in webhook payload")

        try:
            access_token = await _get_installation_access_token(installation_id)
        except Exception as exc:
            logger.exception("Failed to get installation token for webhook auto-scan")
            return WebhookResponse(status="error", message=f"Failed to get installation token: {exc}")

        job_ids: list[str] = []
        for ecosystem in ecosystems_to_scan:
            job = ScanJob(owner=owner, repo_name=repo_name, ecosystem=ecosystem, status="pending")
            db.add(job)
            await db.commit()
            await db.refresh(job)

            job_runner.submit(
                run_scan_job(
                    job_id=job.id,
                    owner=owner,
                    repo=repo_name,
                    ecosystem=ecosystem,
                    access_token=access_token,
                )
            )
            job_ids.append(str(job.id))
            logger.info("Auto-scan triggered: %s/%s ecosystem=%s job_id=%s", owner, repo_name, ecosystem, job.id)

        return WebhookResponse(
            status="ok",
            message=f"Auto-scan triggered for ecosystems: {', '.join(ecosystems_to_scan)}",
            scan_triggered=True,
            job_id=job_ids[0] if len(job_ids) == 1 else ",".join(job_ids),
        )

    # ── Pull request ──────────────────────────────────────────────────
    if event_type == "pull_request":
        if not settings.webhook_pr_scan_enabled:
            return WebhookResponse(status="ok", message="PR scan disabled")

        action = payload.get("action", "")
        if action not in {"opened", "synchronize", "reopened"}:
            return WebhookResponse(status="ok", message=f"PR action '{action}' not tracked")

        pr = payload.get("pull_request", {})
        if not isinstance(pr, dict):
            return WebhookResponse(status="error", message="Missing pull_request object")

        head = pr.get("head", {})
        base = pr.get("base", {})
        head_sha = head.get("sha", "")
        pr_number = pr.get("number", 0)

        base_repo = base.get("repo", {})
        owner_data = base_repo.get("owner", {})
        owner = owner_data.get("login", "") if isinstance(owner_data, dict) else ""
        repo_name = base_repo.get("name", "")

        installation = payload.get("installation", {})
        installation_id = installation.get("id") if isinstance(installation, dict) else None

        if not all([owner, repo_name, head_sha, pr_number, installation_id]):
            return WebhookResponse(status="error", message="Incomplete PR payload")

        try:
            access_token = await _get_installation_access_token(installation_id)
        except Exception as exc:
            logger.exception("Failed to get installation token for PR scan")
            return WebhookResponse(status="error", message=f"Failed to get installation token: {exc}")

        pr_files = await _fetch_pr_changed_files(owner, repo_name, pr_number, access_token)
        changed_ecosystems = _detect_pr_manifest_changes(pr_files)

        configured = {e.strip().lower() for e in settings.webhook_auto_scan_ecosystems.split(",") if e.strip()}
        ecosystems_to_scan = changed_ecosystems & configured

        if not ecosystems_to_scan:
            return WebhookResponse(status="ok", message="No manifest changes in PR")

        job_ids_pr: list[str] = []
        for ecosystem in ecosystems_to_scan:
            job = ScanJob(owner=owner, repo_name=repo_name, ecosystem=ecosystem, status="pending")
            db.add(job)
            await db.commit()
            await db.refresh(job)

            check_run_id = await _create_check_run(
                owner, repo_name, head_sha, access_token,
                name=f"SentinelFlow / {ecosystem}",
            )

            job_runner.submit(
                run_pr_scan_job(
                    job_id=job.id,
                    owner=owner,
                    repo=repo_name,
                    ecosystem=ecosystem,
                    access_token=access_token,
                    head_sha=head_sha,
                    pr_number=pr_number,
                    check_run_id=check_run_id,
                )
            )
            job_ids_pr.append(str(job.id))
            logger.info(
                "PR scan triggered: %s/%s PR#%s ecosystem=%s job_id=%s",
                owner, repo_name, pr_number, ecosystem, job.id,
            )

        return WebhookResponse(
            status="ok",
            message=f"PR scan triggered for ecosystems: {', '.join(ecosystems_to_scan)}",
            scan_triggered=True,
            job_id=job_ids_pr[0] if len(job_ids_pr) == 1 else ",".join(job_ids_pr),
        )

    # Unhandled event types — acknowledge
    return WebhookResponse(status="ok", message=f"Event type '{event_type}' not handled")
