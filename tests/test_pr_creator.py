"""Service-level tests for dependency PR creation helpers."""

from __future__ import annotations

import base64
import subprocess
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from app.api.schemas.dependency import DependencySpec
from app.services import pr_creator
from app.services.pr_creator import PullRequestResult


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | list | None = None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

    def json(self):
        return self._payload


@pytest.mark.asyncio
async def test_create_branch_with_retry_skips_existing_branch():
    client = MagicMock()
    client.get = AsyncMock(
        side_effect=[
            _FakeResponse(200, {"object": {"sha": "abc"}}),  # attempt 0 exists
            _FakeResponse(404, {}),  # attempt 1 does not exist
        ]
    )
    client.post = AsyncMock(return_value=_FakeResponse(201, {}))

    branch = await pr_creator._create_branch_with_retry(
        client=client,
        owner="octo",
        repo_name="repo",
        preferred_branch="sentinelflow/deps/lodash",
        base_sha="abc123",
        headers={"Authorization": "Bearer token"},
        max_attempts=3,
    )

    assert branch.startswith("sentinelflow/deps/lodash")
    assert branch != "sentinelflow/deps/lodash"
    client.post.assert_awaited_once()


@pytest.mark.asyncio
async def test_commit_file_update_maps_sha_conflict_to_409():
    client = MagicMock()
    client.put = AsyncMock(return_value=_FakeResponse(409, {}))

    with pytest.raises(HTTPException) as exc:
        await pr_creator._commit_file_update(
            client=client,
            owner="octo",
            repo_name="repo",
            path="package.json",
            branch="feature",
            previous_sha="oldsha",
            new_content="{}\n",
            commit_message="update",
            headers={"Authorization": "Bearer token"},
        )

    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_commit_file_update_422_is_ok_when_content_already_matches():
    current_content = "{\"name\": \"repo\"}\n"
    encoded = base64.b64encode(current_content.encode("utf-8")).decode("ascii")

    client = MagicMock()
    client.put = AsyncMock(return_value=_FakeResponse(422, {"message": "Validation Failed"}))
    client.get = AsyncMock(return_value=_FakeResponse(200, {"sha": "abc", "content": encoded}))

    await pr_creator._commit_file_update(
        client=client,
        owner="octo",
        repo_name="repo",
        path="package.json",
        branch="feature",
        previous_sha="oldsha",
        new_content=current_content,
        commit_message="update",
        headers={"Authorization": "Bearer token"},
    )

    client.get.assert_awaited_once()


@pytest.mark.asyncio
async def test_commit_file_update_422_raises_409_when_content_differs():
    encoded = base64.b64encode("{}\n".encode("utf-8")).decode("ascii")

    client = MagicMock()
    client.put = AsyncMock(return_value=_FakeResponse(422, {"message": "Validation Failed"}))
    client.get = AsyncMock(return_value=_FakeResponse(200, {"sha": "abc", "content": encoded}))

    with pytest.raises(HTTPException) as exc:
        await pr_creator._commit_file_update(
            client=client,
            owner="octo",
            repo_name="repo",
            path="package.json",
            branch="feature",
            previous_sha="oldsha",
            new_content="{\"name\": \"repo\"}\n",
            commit_message="update",
            headers={"Authorization": "Bearer token"},
        )

    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_get_repo_default_branch_maps_403():
    client = MagicMock()
    client.get = AsyncMock(return_value=_FakeResponse(403, {}))

    with pytest.raises(HTTPException) as exc:
        await pr_creator._get_repo_default_branch(
            client=client,
            owner="octo",
            repo_name="repo",
            headers={"Authorization": "Bearer token"},
        )

    assert exc.value.status_code == 403


def test_lockfile_consistency_missing_dependency_raises():
    parsed_lock = {
        "packages": {
            "": {
                "dependencies": {
                    "react": "^19.0.0",
                }
            }
        }
    }
    deps = [DependencySpec(name="lodash", version="^4.17.21")]

    with pytest.raises(HTTPException) as exc:
        pr_creator._ensure_lockfile_contains_requested_direct_deps(parsed_lock, deps)

    assert exc.value.status_code == 400
    assert "lodash" in str(exc.value.detail)


def test_lockfile_consistency_exact_version_mismatch_raises():
    parsed_lock = {
        "packages": {
            "": {
                "dependencies": {
                    "lodash": "4.17.20",
                }
            }
        }
    }
    deps = [DependencySpec(name="lodash", version="4.17.21")]

    with pytest.raises(HTTPException) as exc:
        pr_creator._ensure_lockfile_contains_requested_direct_deps(parsed_lock, deps)

    assert exc.value.status_code == 400
    assert "expected 4.17.21" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_idempotency_returns_existing_open_pr_without_writes(monkeypatch):
    async def _default_branch(*args, **kwargs):
        return "main"

    async def _branch_sha(*args, **kwargs):
        return "abc123"

    async def _existing_pr(*args, **kwargs):
        return PullRequestResult(
            pr_url="https://github.com/octo/repo/pull/42",
            pr_number=42,
            branch_name="sentinelflow/deps/lodash-123",
        )

    monkeypatch.setattr(pr_creator, "_get_repo_default_branch", _default_branch)
    monkeypatch.setattr(pr_creator, "_get_branch_sha", _branch_sha)
    monkeypatch.setattr(pr_creator, "_find_open_pull_request_for_head", _existing_pr)

    # Guard: these should never be called in this fast-path.
    should_not_call = AsyncMock(side_effect=AssertionError("unexpected write path"))
    monkeypatch.setattr(pr_creator, "_branch_exists", should_not_call)

    result = await pr_creator.create_npm_dependency_pr(
        client=MagicMock(),
        owner="octo",
        repo_name="repo",
        headers={"Authorization": "Bearer token"},
        dependencies=[DependencySpec(name="lodash", version="^4.17.21")],
        updated_package_lock_json=None,
        idempotency_key="retry-key-1234",
        generate_lockfile_server_side=True,
    )

    assert result.pr_number == 42
    assert result.pr_url.endswith("/pull/42")


def test_build_updated_requirements_txt_updates_and_appends_entries():
    existing = "requests==2.30.0\n# comment\nflask==3.0.0\n"
    deps = [
        DependencySpec(name="requests", version="2.31.0"),
        DependencySpec(name="httpx", version=">=0.27.0"),
    ]

    updated = pr_creator._build_updated_requirements_txt(existing, deps)

    assert "requests==2.31.0" in updated
    assert "httpx>=0.27.0" in updated
    assert "# comment" in updated


def test_build_updated_package_json_preserves_caret_constraint_when_safe():
    package_json = '{"dependencies":{"lodash":"^4.17.20"}}'
    deps = [DependencySpec(name="lodash", version="4.17.21")]

    updated = pr_creator._build_updated_package_json(package_json, deps)

    assert '"lodash": "^4.17.21"' in updated


def test_build_updated_package_json_rejects_major_breaking_update():
    package_json = '{"dependencies":{"lodash":"^4.17.20"}}'
    deps = [DependencySpec(name="lodash", version="5.0.0")]

    with pytest.raises(HTTPException) as exc:
        pr_creator._build_updated_package_json(package_json, deps)

    assert exc.value.status_code == 400
    assert "Unsafe npm update" in str(exc.value.detail)


def test_build_updated_requirements_txt_preserves_tilde_equal_constraint():
    existing = "requests~=2.30.0\n"
    deps = [DependencySpec(name="requests", version="2.31.0")]

    updated = pr_creator._build_updated_requirements_txt(existing, deps)

    assert "requests~=2.31.0" in updated


def test_build_updated_requirements_txt_rejects_upper_bound_break():
    existing = "requests>=2.30,<3.0\n"
    deps = [DependencySpec(name="requests", version="3.1.0")]

    with pytest.raises(HTTPException) as exc:
        pr_creator._build_updated_requirements_txt(existing, deps)

    assert exc.value.status_code == 400
    assert "Unsafe PyPI update" in str(exc.value.detail)


@pytest.mark.asyncio
async def test_create_pypi_dependency_pr_returns_existing_pr_for_idempotency(monkeypatch):
    async def _default_branch(*args, **kwargs):
        return "main"

    async def _branch_sha(*args, **kwargs):
        return "abc123"

    async def _create_or_reuse(*args, **kwargs):
        return "sentinelflow/deps-pypi/requests", PullRequestResult(
            pr_url="https://github.com/octo/repo/pull/77",
            pr_number=77,
            branch_name="sentinelflow/deps-pypi/requests",
        )

    monkeypatch.setattr(pr_creator, "_get_repo_default_branch", _default_branch)
    monkeypatch.setattr(pr_creator, "_get_branch_sha", _branch_sha)
    monkeypatch.setattr(pr_creator, "_create_or_reuse_branch", _create_or_reuse)

    result = await pr_creator.create_pypi_dependency_pr(
        client=MagicMock(),
        owner="octo",
        repo_name="repo",
        headers={"Authorization": "Bearer token"},
        dependencies=[DependencySpec(name="requests", version="2.31.0")],
        idempotency_key="pypi-retry-0001",
    )

    assert result.pr_number == 77
    assert result.pr_url.endswith("/pull/77")


@pytest.mark.asyncio
async def test_create_pull_request_invalid_payload_raises_502():
    client = MagicMock()
    client.post = AsyncMock(return_value=_FakeResponse(201, {"number": 0, "html_url": ""}))

    with pytest.raises(HTTPException) as exc:
        await pr_creator._create_pull_request(
            client=client,
            owner="octo",
            repo_name="repo",
            head_branch="feature/test",
            base_branch="main",
            title="test",
            body="body",
            headers={"Authorization": "Bearer token"},
        )

    assert exc.value.status_code == 502


@pytest.mark.asyncio
async def test_generate_lockfile_server_side_uses_subprocess_run(monkeypatch):
    monkeypatch.setattr(pr_creator.settings, "npm_lockfile_generation_enabled", True)

    def _fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(pr_creator.subprocess, "run", _fake_run)

    result = await pr_creator._generate_lockfile_server_side(
        '{"name":"demo"}\n',
        '{"lockfileVersion":3}\n',
    )

    assert '{"lockfileVersion":3}' in result


# ── Endpoint integration tests ─────────────────────────────────────────


@pytest.fixture
def mock_pr_user():
    user = MagicMock()
    user.id = uuid.uuid4()
    user.access_token = "ghp_test_token"
    user.username = "testuser"
    return user


@pytest.fixture
def mock_pr_db():
    db = AsyncMock()
    db.commit = AsyncMock()
    db.add = MagicMock()
    return db


@pytest.fixture
def pr_endpoint_app(mock_pr_user, mock_pr_db):
    from app.main import create_app
    from app.api.deps import get_current_user, get_db

    _app = create_app()
    _app.dependency_overrides[get_current_user] = lambda: mock_pr_user

    async def _override_db():
        yield mock_pr_db

    _app.dependency_overrides[get_db] = _override_db
    yield _app
    _app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_add_dependency_triggers_scan(pr_endpoint_app, mock_pr_db):
    """After PR creation, a ScanJob with scan_mode='static_dynamic' is created and submitted."""
    from app.models.scan import ScanJob

    captured = {}

    def _capture_add(obj):
        if isinstance(obj, ScanJob):
            captured["scan_job"] = obj

    mock_pr_db.add = MagicMock(side_effect=_capture_add)

    async def _fake_refresh(obj):
        if isinstance(obj, ScanJob) and (not hasattr(obj, "id") or obj.id is None):
            obj.id = uuid.uuid4()

    mock_pr_db.refresh = AsyncMock(side_effect=_fake_refresh)

    dummy_pr = PullRequestResult(
        pr_url="https://github.com/owner/repo/pull/1",
        pr_number=1,
        branch_name="sentinelflow/deps/lodash",
    )

    with (
        patch(
            "app.services.typosquat_guard.validate_packages",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.endpoints.repos._get_installation_token_for_repo",
            side_effect=HTTPException(status_code=404),
        ),
        patch(
            "app.services.pr_creator.create_npm_dependency_pr",
            new_callable=AsyncMock,
            return_value=dummy_pr,
        ),
        patch("app.api.endpoints.repos.job_runner") as mock_runner,
    ):
        def _submit_and_close(coro):
            coro.close()
            return MagicMock()

        mock_runner.submit = MagicMock(side_effect=_submit_and_close)

        async with AsyncClient(
            transport=ASGITransport(app=pr_endpoint_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/repos/owner/repo/dependencies/add",
                json={
                    "ecosystem": "npm",
                    "dependencies": [{"name": "lodash", "version": "^4.17.21"}],
                },
            )

    assert resp.status_code == 202
    body = resp.json()

    scan_job = captured.get("scan_job")
    assert scan_job is not None, "ScanJob was not created"
    assert scan_job.scan_mode == "static_dynamic"
    assert scan_job.owner == "owner"
    assert scan_job.repo_name == "repo"

    mock_runner.submit.assert_called_once()
    assert body.get("scan_job_id") is not None


@pytest.mark.asyncio
async def test_add_dependency_scan_failure_does_not_block_pr(pr_endpoint_app, mock_pr_db):
    """PR creation returns 202 even when scan job DB commit raises."""
    mock_pr_db.commit = AsyncMock(side_effect=Exception("DB connection lost"))

    dummy_pr = PullRequestResult(
        pr_url="https://github.com/owner/repo/pull/2",
        pr_number=2,
        branch_name="sentinelflow/deps/lodash-v2",
    )

    with (
        patch(
            "app.services.typosquat_guard.validate_packages",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "app.api.endpoints.repos._get_installation_token_for_repo",
            side_effect=HTTPException(status_code=404),
        ),
        patch(
            "app.services.pr_creator.create_npm_dependency_pr",
            new_callable=AsyncMock,
            return_value=dummy_pr,
        ),
        patch("app.api.endpoints.repos.job_runner") as mock_runner,
    ):
        mock_runner.submit = MagicMock()

        async with AsyncClient(
            transport=ASGITransport(app=pr_endpoint_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/repos/owner/repo/dependencies/add",
                json={
                    "ecosystem": "npm",
                    "dependencies": [{"name": "lodash", "version": "^4.17.21"}],
                },
            )

    assert resp.status_code == 202
    body = resp.json()
    assert body.get("pr_number") == 2
    assert body.get("scan_job_id") is None
    mock_runner.submit.assert_not_called()
