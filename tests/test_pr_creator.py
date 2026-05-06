"""Service-level tests for dependency PR creation helpers."""

from __future__ import annotations

import base64
import subprocess
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

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
