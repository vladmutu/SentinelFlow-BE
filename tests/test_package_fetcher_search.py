"""Tests for registry package search and typosquatting signals."""

from __future__ import annotations

import json

import httpx
import pytest

from app.services import package_fetcher


@pytest.mark.asyncio
async def test_search_npm_packages_parses_registry_payload():
    payload = {
        "objects": [
            {
                "package": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "description": "Lodash modular utilities.",
                    "links": {
                        "npm": "https://www.npmjs.com/package/lodash",
                        "homepage": "https://lodash.com",
                    },
                },
                "score": {"final": 0.98},
            },
            {
                "package": {
                    "name": "lodasb",
                    "version": "1.0.0",
                    "description": "Suspicious clone.",
                    "links": {
                        "npm": "https://www.npmjs.com/package/lodasb",
                    },
                },
                "score": {"final": 0.12},
            },
        ]
    }

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/-/v1/search"):
            return httpx.Response(200, content=json.dumps(payload), headers={"Content-Type": "application/json"})
        if request.url.path.endswith("/downloads/point/last-month/lodash"):
            return httpx.Response(200, content=json.dumps({"downloads": 580261537}), headers={"Content-Type": "application/json"})
        if request.url.path.endswith("/downloads/point/last-month/lodasb"):
            return httpx.Response(200, content=json.dumps({"downloads": 4}), headers={"Content-Type": "application/json"})
        return httpx.Response(404, content="{}", headers={"Content-Type": "application/json"})

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        results = await package_fetcher.search_npm_packages("lodash", client=client)

    assert len(results) == 2
    assert results[0]["name"] == "lodash"
    assert results[0]["monthly_downloads"] == 580261537
    assert results[0]["typosquat"]["is_suspected"] is False
    assert results[0]["typosquat"]["levenshtein_distance"] == 0
    assert results[1]["name"] == "lodasb"
    assert results[1]["monthly_downloads"] == 4
    assert results[1]["typosquat"]["is_suspected"] is True
    assert results[1]["typosquat"]["levenshtein_distance"] == 1


@pytest.mark.asyncio
async def test_search_npm_packages_uses_page_and_limit():
    payload = {
        "objects": [
            {
                "package": {
                    "name": "lodash",
                    "version": "4.17.21",
                    "description": "Lodash modular utilities.",
                    "links": {
                        "npm": "https://www.npmjs.com/package/lodash",
                        "homepage": "https://lodash.com",
                    },
                },
                "score": {"final": 0.98},
            }
        ]
    }

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/-/v1/search"):
            assert request.url.params["size"] == "5"
            assert request.url.params["from"] == "5"
            return httpx.Response(200, content=json.dumps(payload), headers={"Content-Type": "application/json"})
        if request.url.path.endswith("/downloads/point/last-month/lodash"):
            return httpx.Response(200, content=json.dumps({"downloads": 580261537}), headers={"Content-Type": "application/json"})
        return httpx.Response(404, content="{}", headers={"Content-Type": "application/json"})

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        results = await package_fetcher.search_npm_packages("lodash", page=2, limit=5, client=client)

    assert len(results) == 1
    assert results[0]["name"] == "lodash"


@pytest.mark.asyncio
async def test_search_pypi_packages_parses_html_results():
    html = """
    <a class="package-snippet" href="/project/requests/">
      <span class="package-snippet__name">requests</span>
      <span class="package-snippet__version">2.32.0</span>
      <p class="package-snippet__description">HTTP for Humans.</p>
    </a>
    <a class="package-snippet" href="/project/requests2/">
      <span class="package-snippet__name">requests2</span>
      <span class="package-snippet__version">0.1.0</span>
      <p class="package-snippet__description">Unofficial variant.</p>
    </a>
    """

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/search/":
            return httpx.Response(200, text=html, headers={"Content-Type": "text/html"})
        if request.url.path == "/api/search":
            return httpx.Response(200, content="[]", headers={"Content-Type": "application/json"})
        if request.url.path == "/api/packages/requests/recent":
            return httpx.Response(200, content=json.dumps({"data": {"last_month": 1385411770}}), headers={"Content-Type": "application/json"})
        if request.url.path == "/api/packages/requests2/recent":
            return httpx.Response(200, content=json.dumps({"data": {"last_month": 120}}), headers={"Content-Type": "application/json"})
        return httpx.Response(404, content="{}", headers={"Content-Type": "application/json"})

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        results = await package_fetcher.search_pypi_packages("requests", client=client)

    assert len(results) == 2
    assert results[0]["name"] == "requests"
    assert results[0]["monthly_downloads"] == 1385411770
    assert results[0]["registry_url"] == "https://pypi.org/project/requests/"
    assert results[1]["name"] == "requests2"
    assert results[1]["monthly_downloads"] == 120


def test_typosquat_signal_detects_separator_variation():
    signal = package_fetcher._typosquat_signal("python-dateutil", "python_dateutil")

    assert signal["is_suspected"] is True
    assert signal["normalized_conflict"] is True
    assert signal["confidence"] >= 0.9
    assert signal["levenshtein_distance"] == 1


@pytest.mark.asyncio
async def test_list_npm_package_versions_returns_versions():
    payload = {
        "name": "lodash",
        "dist-tags": {"latest": "4.17.21"},
        "versions": {
            "4.17.20": {},
            "4.17.21": {},
        },
    }

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/lodash")
        return httpx.Response(200, content=json.dumps(payload), headers={"Content-Type": "application/json"})

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await package_fetcher.list_npm_package_versions("lodash", client=client)

    assert result["ecosystem"] == "npm"
    assert result["package_name"] == "lodash"
    assert result["latest_version"] == "4.17.21"
    assert "4.17.20" in result["versions"]
    assert "4.17.21" in result["versions"]


@pytest.mark.asyncio
async def test_list_pypi_package_versions_returns_versions():
    payload = {
        "info": {"name": "requests", "version": "2.32.0"},
        "releases": {
            "2.31.0": [{"filename": "requests-2.31.0.tar.gz"}],
            "2.32.0": [{"filename": "requests-2.32.0.tar.gz"}],
        },
    }

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/requests/json")
        return httpx.Response(200, content=json.dumps(payload), headers={"Content-Type": "application/json"})

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await package_fetcher.list_pypi_package_versions("requests", client=client)

    assert result["ecosystem"] == "pypi"
    assert result["package_name"] == "requests"
    assert result["latest_version"] == "2.32.0"
    assert "2.31.0" in result["versions"]
    assert "2.32.0" in result["versions"]


@pytest.mark.asyncio
async def test_search_pypi_packages_falls_back_to_exact_json_lookup():
    html_without_cards = "<html><body><h1>Search</h1><p>No cards rendered</p></body></html>"
    json_payload = {
        "info": {
            "name": "requests",
            "version": "2.32.0",
            "summary": "HTTP for Humans.",
            "home_page": "https://requests.readthedocs.io",
        }
    }

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/search/":
            return httpx.Response(200, text=html_without_cards, headers={"Content-Type": "text/html"})
        if request.url.path.endswith("/requests/json"):
            return httpx.Response(200, content=json.dumps(json_payload), headers={"Content-Type": "application/json"})
        if request.url.path == "/api/packages/requests/recent":
            return httpx.Response(200, content=json.dumps({"data": {"last_month": 1385411770}}), headers={"Content-Type": "application/json"})
        return httpx.Response(404, content="{}", headers={"Content-Type": "application/json"})

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        results = await package_fetcher.search_pypi_packages("requests", client=client)

    assert len(results) == 1
    assert results[0]["name"] == "requests"
    assert results[0]["version"] == "2.32.0"
    assert results[0]["monthly_downloads"] == 1385411770


@pytest.mark.asyncio
async def test_search_pypi_packages_uses_page_and_limit():
    libraries_payload = [
        {
            "name": "requests",
            "latest_release_number": "2.32.0",
            "description": "HTTP for Humans.",
            "homepage": "https://requests.readthedocs.io",
        }
        for _ in range(8)
    ]

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/search":
            assert request.url.params["page"] == "3"
            assert request.url.params["per_page"] == "8"
            return httpx.Response(200, content=json.dumps(libraries_payload), headers={"Content-Type": "application/json"})
        if request.url.path == "/api/pypi/requests":
            return httpx.Response(200, content=json.dumps(libraries_payload[0]), headers={"Content-Type": "application/json"})
        if request.url.path == "/api/packages/requests/recent":
            return httpx.Response(200, content=json.dumps({"data": {"last_month": 1385411770}}), headers={"Content-Type": "application/json"})
        return httpx.Response(404, content="{}", headers={"Content-Type": "application/json"})

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        results = await package_fetcher.search_pypi_packages("requests", page=3, limit=8, client=client)

    assert len(results) == 8
    assert results[0]["name"] == "requests"


@pytest.mark.asyncio
async def test_search_pypi_packages_falls_back_to_simple_index_contains(monkeypatch):
    html_without_cards = "<html><body>No package cards</body></html>"
    simple_index_html = """
    <html><body>
      <a href="/simple/requests/">requests</a>
      <a href="/simple/redis/">redis</a>
      <a href="/simple/httpx/">httpx</a>
    </body></html>
    """

    libraries_payload = [
        {
            "name": "requests",
            "latest_release_number": "2.32.0",
            "description": "HTTP for Humans.",
            "homepage": "https://requests.readthedocs.io",
        },
        {
            "name": "redis",
            "latest_release_number": "5.0.4",
        },
    ]

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/search/":
            return httpx.Response(200, text=html_without_cards, headers={"Content-Type": "text/html"})
        if request.url.path.endswith("/re/json"):
            return httpx.Response(404, content="{}", headers={"Content-Type": "application/json"})
        if request.url.path == "/simple/":
            return httpx.Response(200, text=simple_index_html, headers={"Content-Type": "text/html"})
        if request.url.path == "/api/pypi/requests":
            return httpx.Response(200, content=json.dumps(libraries_payload[0]), headers={"Content-Type": "application/json"})
        if request.url.path == "/api/pypi/redis":
            return httpx.Response(200, content=json.dumps(libraries_payload[1]), headers={"Content-Type": "application/json"})
        if request.url.path == "/api/packages/requests/recent":
            return httpx.Response(200, content=json.dumps({"data": {"last_month": 1385411770}}), headers={"Content-Type": "application/json"})
        if request.url.path == "/api/packages/redis/recent":
            return httpx.Response(200, content=json.dumps({"data": {"last_month": 8012345}}), headers={"Content-Type": "application/json"})
        return httpx.Response(404, content="{}", headers={"Content-Type": "application/json"})

    transport = httpx.MockTransport(_handler)
    monkeypatch.setattr(package_fetcher.settings, "librariesio_api_key", "test-key")
    async with httpx.AsyncClient(transport=transport) as client:
        results = await package_fetcher.search_pypi_packages("re", client=client)

    names = [item["name"] for item in results]
    assert "requests" in names
    assert "redis" in names
    requests_item = next(item for item in results if item["name"] == "requests")
    assert requests_item["version"] == "2.32.0"
    assert requests_item["monthly_downloads"] == 1385411770


def test_suggest_package_name_returns_requests_for_common_typo():
    suggestion = package_fetcher.suggest_package_name("pypi", "rpequests", [])

    assert suggestion == "requests"


def test_suggest_package_name_returns_lodash_for_npm_typo():
    results = [
        {
            "name": "lodash",
            "typosquat": {
                "is_suspected": False,
            },
        }
    ]

    suggestion = package_fetcher.suggest_package_name("npm", "lodahs", results)

    assert suggestion == "lodash"
