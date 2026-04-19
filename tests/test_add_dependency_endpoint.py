"""Tests for dependency-add pull request endpoint."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from app.api.deps import get_current_user, require_authenticated_token
from app.main import create_app
from app.services.pr_creator import PullRequestResult


@pytest.fixture
def mock_user():
    user = MagicMock()
    user.id = uuid.uuid4()
    user.access_token = "ghp_test_token"
    user.username = "testuser"
    user.email = "test@example.com"
    return user


@pytest.fixture
def app(mock_user):
    _app = create_app()
    _app.dependency_overrides[get_current_user] = lambda: mock_user
    _app.dependency_overrides[require_authenticated_token] = lambda: mock_user.id
    yield _app
    _app.dependency_overrides.clear()


@pytest.fixture
def unauth_app():
    _app = create_app()
    yield _app


def _valid_payload() -> dict:
    return {
        "ecosystem": "npm",
        "dependencies": [
            {"name": "lodash", "version": "^4.17.21"},
        ],
        "updated_package_lock_json": "{\"name\":\"demo\",\"lockfileVersion\":3,\"packages\":{}}",
    }


@pytest.mark.asyncio
async def test_add_dependency_pr_returns_202(app):
    with patch("app.api.endpoints.repos._get_installation_token_for_repo", new=AsyncMock(return_value="ghs_install")):
        with patch(
            "app.api.endpoints.repos.pr_creator.create_npm_dependency_pr",
            new=AsyncMock(
                return_value=PullRequestResult(
                    pr_url="https://github.com/octo/repo/pull/123",
                    pr_number=123,
                    branch_name="sentinelflow/deps/lodash",
                )
            ),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                resp = await client.post(
                    "/api/repos/octo/repo/dependencies/add",
                    json=_valid_payload(),
                )

    assert resp.status_code == 202
    body = resp.json()
    assert body["pr_url"].endswith("/pull/123")
    assert body["pr_number"] == 123
    assert body["branch_name"] == "sentinelflow/deps/lodash"


@pytest.mark.asyncio
async def test_add_dependency_pr_requires_auth(unauth_app):
    async with AsyncClient(
        transport=ASGITransport(app=unauth_app),
        base_url="http://test",
    ) as client:
        resp = await client.post(
            "/api/repos/octo/repo/dependencies/add",
            json=_valid_payload(),
        )

    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_add_dependency_pr_rejects_non_npm_ecosystem(app):
    payload = _valid_payload()
    payload["ecosystem"] = "cargo"

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.post(
            "/api/repos/octo/repo/dependencies/add",
            json=payload,
        )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_add_dependency_pr_routes_to_pypi_service(app):
    payload = {
        "ecosystem": "pypi",
        "dependencies": [{"name": "requests", "version": "2.31.0"}],
        "idempotency_key": "pypi-retry-0001",
    }

    with patch("app.api.endpoints.repos._get_installation_token_for_repo", new=AsyncMock(return_value="ghs_install")):
        with patch(
            "app.api.endpoints.repos.pr_creator.create_pypi_dependency_pr",
            new=AsyncMock(
                return_value=PullRequestResult(
                    pr_url="https://github.com/octo/repo/pull/200",
                    pr_number=200,
                    branch_name="sentinelflow/deps-pypi/requests",
                )
            ),
        ) as mocked_pypi:
            with patch(
                "app.api.endpoints.repos.pr_creator.create_npm_dependency_pr",
                new=AsyncMock(side_effect=AssertionError("npm flow should not be called")),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app),
                    base_url="http://test",
                ) as client:
                    resp = await client.post(
                        "/api/repos/octo/repo/dependencies/add",
                        json=payload,
                    )

    assert resp.status_code == 202
    kwargs = mocked_pypi.await_args.kwargs
    assert kwargs["idempotency_key"] == "pypi-retry-0001"


@pytest.mark.asyncio
async def test_add_dependency_pr_requires_lockfile_payload_or_generation(app):
    payload = _valid_payload()
    payload.pop("updated_package_lock_json")

    with patch("app.api.endpoints.repos._get_installation_token_for_repo", new=AsyncMock(return_value="ghs_install")):
        with patch(
            "app.api.endpoints.repos.pr_creator.create_npm_dependency_pr",
            new=AsyncMock(
                side_effect=HTTPException(
                    status_code=400,
                    detail="updated_package_lock_json is required unless generate_lockfile_server_side=true",
                )
            ),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                resp = await client.post(
                    "/api/repos/octo/repo/dependencies/add",
                    json=payload,
                )

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_add_dependency_pr_accepts_server_side_generation_and_idempotency(app):
    payload = _valid_payload()
    payload.pop("updated_package_lock_json")
    payload["generate_lockfile_server_side"] = True
    payload["idempotency_key"] = "retry-key-1234"

    with patch("app.api.endpoints.repos._get_installation_token_for_repo", new=AsyncMock(return_value="ghs_install")):
        with patch(
            "app.api.endpoints.repos.pr_creator.create_npm_dependency_pr",
            new=AsyncMock(
                return_value=PullRequestResult(
                    pr_url="https://github.com/octo/repo/pull/124",
                    pr_number=124,
                    branch_name="sentinelflow/deps/lodash-abc",
                )
            ),
        ) as mocked_create:
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                resp = await client.post(
                    "/api/repos/octo/repo/dependencies/add",
                    json=payload,
                )

    assert resp.status_code == 202
    kwargs = mocked_create.await_args.kwargs
    assert kwargs["idempotency_key"] == "retry-key-1234"
    assert kwargs["generate_lockfile_server_side"] is True


@pytest.mark.asyncio
async def test_add_dependency_pr_bubbles_service_http_errors(app):
    with patch("app.api.endpoints.repos._get_installation_token_for_repo", new=AsyncMock(return_value="ghs_install")):
        with patch(
            "app.api.endpoints.repos.pr_creator.create_npm_dependency_pr",
            new=AsyncMock(side_effect=HTTPException(status_code=400, detail="updated_package_lock_json must be valid JSON")),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
            ) as client:
                resp = await client.post(
                    "/api/repos/octo/repo/dependencies/add",
                    json=_valid_payload(),
                )

    assert resp.status_code == 400
    assert "updated_package_lock_json" in resp.text


@pytest.mark.asyncio
async def test_search_packages_proxy_npm_returns_results(app):
    mocked_results = [
        {
            "ecosystem": "npm",
            "name": "lodasb",
            "version": "1.0.0",
            "description": "suspicious package",
            "homepage": None,
            "registry_url": "https://www.npmjs.com/package/lodasb",
            "score": 0.12,
            "monthly_downloads": 4,
            "typosquat": {
                "is_suspected": True,
                "confidence": 0.8,
                "levenshtein_distance": 1,
                "edit_distance": 1,
                "normalized_conflict": False,
                "reasons": ["one edit away from query"],
            },
        }
    ]

    with patch(
        "app.api.endpoints.repos.package_fetcher.search_npm_packages",
        new=AsyncMock(return_value=mocked_results),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(
                "/api/repos/packages/search",
                params={"ecosystem": "npm", "q": "lodash", "limit": 5},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ecosystem"] == "npm"
    assert body["query"] == "lodash"
    assert body["total"] == 1
    assert body["results"][0]["name"] == "lodasb"
    assert body["results"][0]["monthly_downloads"] == 4
    assert body["results"][0]["typosquat"]["is_suspected"] is True
    assert body["results"][0]["typosquat"]["levenshtein_distance"] == 1
    assert body["did_you_mean"] is None


@pytest.mark.asyncio
async def test_search_packages_proxy_pypi_routes_to_pypi_search(app):
    mocked_results = [
        {
            "ecosystem": "pypi",
            "name": "requests",
            "version": "2.32.0",
            "description": "HTTP for Humans.",
            "homepage": None,
            "registry_url": "https://pypi.org/project/requests/",
            "score": None,
            "monthly_downloads": 1385411770,
            "typosquat": {
                "is_suspected": False,
                "confidence": 0.0,
                "levenshtein_distance": 0,
                "edit_distance": 0,
                "normalized_conflict": False,
                "reasons": [],
            },
        }
    ]

    with patch(
        "app.api.endpoints.repos.package_fetcher.search_pypi_packages",
        new=AsyncMock(return_value=mocked_results),
    ) as mocked_search:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(
                "/api/repos/packages/search",
                params={"ecosystem": "pypi", "q": "requests"},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ecosystem"] == "pypi"
    assert body["total"] == 1
    assert body["results"][0]["monthly_downloads"] == 1385411770
    assert body["did_you_mean"] is None
    mocked_search.assert_awaited_once()


@pytest.mark.asyncio
async def test_search_packages_proxy_rejects_invalid_ecosystem(app):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/api/repos/packages/search",
            params={"ecosystem": "cargo", "q": "serde"},
        )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_search_packages_proxy_requires_auth(unauth_app):
    async with AsyncClient(
        transport=ASGITransport(app=unauth_app),
        base_url="http://test",
    ) as client:
        resp = await client.get(
            "/api/repos/packages/search",
            params={"ecosystem": "npm", "q": "react", "limit": 5},
        )

    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_search_packages_proxy_whitespace_query_returns_empty(app):
    with patch(
        "app.api.endpoints.repos.package_fetcher.search_npm_packages",
        new=AsyncMock(side_effect=AssertionError("upstream should not be called")),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(
                "/api/repos/packages/search",
                params={"ecosystem": "npm", "q": "   ", "limit": 5},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == ""
    assert body["total"] == 0
    assert body["results"] == []
    assert body["did_you_mean"] is None


@pytest.mark.asyncio
async def test_search_packages_proxy_returns_did_you_mean_for_typo(app):
    with patch(
        "app.api.endpoints.repos.package_fetcher.search_pypi_packages",
        new=AsyncMock(return_value=[]),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(
                "/api/repos/packages/search",
                params={"ecosystem": "pypi", "q": "rpequests", "limit": 10},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["did_you_mean"] == "requests"


@pytest.mark.asyncio
async def test_search_packages_proxy_returns_did_you_mean_for_npm_typo(app):
    mocked_results = [
        {
            "ecosystem": "npm",
            "name": "lodash",
            "version": "4.17.21",
            "description": "Lodash modular utilities.",
            "homepage": "https://lodash.com",
            "registry_url": "https://www.npmjs.com/package/lodash",
            "score": 0.98,
            "monthly_downloads": 580261537,
            "typosquat": {
                "is_suspected": False,
                "confidence": 0.0,
                "levenshtein_distance": 1,
                "edit_distance": 1,
                "normalized_conflict": False,
                "reasons": [],
            },
        }
    ]

    with patch(
        "app.api.endpoints.repos.package_fetcher.search_npm_packages",
        new=AsyncMock(return_value=mocked_results),
    ):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(
                "/api/repos/packages/search",
                params={"ecosystem": "npm", "q": "lodahs"},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["did_you_mean"] == "lodash"


@pytest.mark.asyncio
async def test_get_package_versions_proxy_npm_returns_versions(app):
    payload = {
        "ecosystem": "npm",
        "package_name": "lodash",
        "latest_version": "4.17.21",
        "versions": ["4.17.20", "4.17.21"],
    }

    with patch(
        "app.api.endpoints.repos.package_fetcher.list_npm_package_versions",
        new=AsyncMock(return_value=payload),
    ) as mocked_versions:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(
                "/api/repos/packages/versions",
                params={"ecosystem": "npm", "name": "lodash"},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["latest_version"] == "4.17.21"
    mocked_versions.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_package_versions_proxy_pypi_returns_versions(app):
    payload = {
        "ecosystem": "pypi",
        "package_name": "requests",
        "latest_version": "2.32.0",
        "versions": ["2.31.0", "2.32.0"],
    }

    with patch(
        "app.api.endpoints.repos.package_fetcher.list_pypi_package_versions",
        new=AsyncMock(return_value=payload),
    ) as mocked_versions:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            resp = await client.get(
                "/api/repos/packages/versions",
                params={"ecosystem": "pypi", "name": "requests"},
            )

    assert resp.status_code == 200
    body = resp.json()
    assert body["package_name"] == "requests"
    mocked_versions.assert_awaited_once()
