"""GitHub webhook endpoint for receiving push events and triggering auto-scans.

Handles:
- ``push`` events: detect manifest changes and auto-trigger scans.
- ``installation`` events: log for tracking.
- All other events: acknowledge with 200.
"""

from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas.webhook import WebhookPushEvent, WebhookResponse
from app.core.config import settings
from app.core.github_app import get_app_jwt
from app.db.session import get_db
from app.models.scan import ScanJob
from app.services.job_runner import job_runner
from app.services.scan_orchestrator import run_scan_job

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Webhooks"])

# Manifest files that trigger auto-scans per ecosystem
_NPM_MANIFEST_FILES = {"package.json", "package-lock.json"}
_PYPI_MANIFEST_FILES = {"requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "Pipfile.lock"}


def _verify_signature(payload_body: bytes, signature_header: str | None) -> bool:
    """Verify the GitHub webhook HMAC-SHA256 signature."""
    if not settings.github_webhook_secret or settings.github_webhook_secret.startswith("placeholder"):
        # Skip verification if no real secret is configured
        logger.warning("Webhook signature verification skipped: no real secret configured")
        return True

    if not signature_header:
        return False

    if not signature_header.startswith("sha256="):
        return False

    expected_signature = hmac.new(
        settings.github_webhook_secret.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        f"sha256={expected_signature}",
        signature_header,
    )


def _detect_manifest_changes(commits: list[dict]) -> set[str]:
    """Detect which ecosystems have manifest file changes in the push commits."""
    changed_ecosystems: set[str] = set()
    all_manifest_files = _NPM_MANIFEST_FILES | _PYPI_MANIFEST_FILES

    for commit in commits:
        if not isinstance(commit, dict):
            continue

        changed_files: list[str] = []
        for key in ("added", "modified", "removed"):
            files = commit.get(key, [])
            if isinstance(files, list):
                changed_files.extend(f for f in files if isinstance(f, str))

        for filepath in changed_files:
            # Check just the filename (basename)
            filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath

            if filename in _NPM_MANIFEST_FILES:
                changed_ecosystems.add("npm")
            if filename in _PYPI_MANIFEST_FILES:
                changed_ecosystems.add("pypi")

    return changed_ecosystems


async def _get_installation_access_token(installation_id: int) -> str:
    """Create an installation access token for the GitHub App."""
    import httpx

    app_jwt = get_app_jwt()
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {app_jwt}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers=headers,
            json={},
        )
        if resp.is_error:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to create installation token: {resp.status_code}",
            )
        return resp.json().get("token", "")


@router.post(
    "/github",
    response_model=WebhookResponse,
)
async def handle_github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None, alias="X-GitHub-Event"),
    x_hub_signature_256: str | None = Header(default=None, alias="X-Hub-Signature-256"),
    x_github_delivery: str | None = Header(default=None, alias="X-GitHub-Delivery"),
    db: AsyncSession = Depends(get_db),
) -> WebhookResponse:
    """Receive GitHub webhook events and auto-trigger scans on push.

    Args:
        request: Raw HTTP request for body access.
        x_github_event: GitHub event type header.
        x_hub_signature_256: HMAC-SHA256 signature header.
        x_github_delivery: Unique delivery ID.
        db: Database session.

    Returns:
        WebhookResponse: Acknowledgement with optional scan job ID.
    """
    body = await request.body()

    # Verify signature
    if not _verify_signature(body, x_hub_signature_256):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid webhook signature",
        )

    event_type = (x_github_event or "").lower()
    logger.info(
        "Received webhook event=%s delivery=%s",
        event_type,
        x_github_delivery or "unknown",
    )

    # Handle ping
    if event_type == "ping":
        return WebhookResponse(status="ok", message="pong")

    # Handle installation events
    if event_type in {"installation", "installation_repositories"}:
        logger.info("Installation event received: %s", event_type)
        return WebhookResponse(status="ok", message=f"Installation event acknowledged: {event_type}")

    # Handle push events
    if event_type == "push":
        if not settings.webhook_auto_scan_enabled:
            return WebhookResponse(status="ok", message="Auto-scan disabled")

        try:
            payload = await request.json()
        except Exception:
            # Body already read above, parse from bytes
            import json
            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return WebhookResponse(status="error", message="Invalid JSON payload")

        if not isinstance(payload, dict):
            return WebhookResponse(status="error", message="Invalid payload format")

        # Extract repository info
        repo_data = payload.get("repository", {})
        if not isinstance(repo_data, dict):
            return WebhookResponse(status="ok", message="No repository data")

        repo_name = repo_data.get("name", "")
        owner_data = repo_data.get("owner", {})
        owner = owner_data.get("login", "") if isinstance(owner_data, dict) else ""

        if not owner or not repo_name:
            return WebhookResponse(status="ok", message="Missing repository identity")

        # Only trigger on the default branch
        default_branch = repo_data.get("default_branch", "main")
        ref = payload.get("ref", "")
        if ref != f"refs/heads/{default_branch}":
            return WebhookResponse(
                status="ok",
                message=f"Push not on default branch ({default_branch}), skipping",
            )

        # Detect which ecosystems have manifest changes
        commits = payload.get("commits", [])
        if not isinstance(commits, list):
            commits = []

        changed_ecosystems = _detect_manifest_changes(commits)

        # Filter by configured ecosystems
        configured = {
            e.strip().lower()
            for e in settings.webhook_auto_scan_ecosystems.split(",")
            if e.strip()
        }
        ecosystems_to_scan = changed_ecosystems & configured

        if not ecosystems_to_scan:
            return WebhookResponse(
                status="ok",
                message="No relevant manifest changes detected",
            )

        # Get installation access token
        installation = payload.get("installation", {})
        installation_id = installation.get("id") if isinstance(installation, dict) else None

        if not installation_id:
            return WebhookResponse(
                status="error",
                message="No installation context in webhook payload",
            )

        try:
            access_token = await _get_installation_access_token(installation_id)
        except Exception as exc:
            logger.exception("Failed to get installation token for webhook auto-scan")
            return WebhookResponse(
                status="error",
                message=f"Failed to get installation token: {exc}",
            )

        # Trigger scans for each changed ecosystem
        job_ids: list[str] = []
        for ecosystem in ecosystems_to_scan:
            job = ScanJob(
                owner=owner,
                repo_name=repo_name,
                ecosystem=ecosystem,
                status="pending",
            )
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

            logger.info(
                "Auto-scan triggered: %s/%s ecosystem=%s job_id=%s",
                owner,
                repo_name,
                ecosystem,
                job.id,
            )

        return WebhookResponse(
            status="ok",
            message=f"Auto-scan triggered for ecosystems: {', '.join(ecosystems_to_scan)}",
            scan_triggered=True,
            job_id=job_ids[0] if len(job_ids) == 1 else ",".join(job_ids),
        )

    # Unhandled event types — acknowledge
    return WebhookResponse(status="ok", message=f"Event type '{event_type}' not handled")
