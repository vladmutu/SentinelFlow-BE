"""Tests for manifest workload helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.manifest_utils import build_npm_scan_workload, resolve_npm_dependency_tree, build_pypi_dependency_tree_deep
from app.services import manifest_utils


def test_build_npm_scan_workload_uses_tree_counts_not_packages_map():
    """Tree-derived counts should be used even when lockfile packages map exists."""
    manifest = {
        "packages": {
            "": {"name": "project", "version": "1.0.0"},
            "node_modules/a": {"name": "a", "version": "1.0.0"},
            "node_modules/a/node_modules/b": {"name": "b", "version": "1.0.0"},
            "node_modules/c": {"name": "c", "version": "1.0.0"},
            "node_modules/d": {"name": "d", "version": "1.0.0"},
            "node_modules/e": {"name": "e", "version": "1.0.0"},
        }
    }
    # Graph/tree view contains only two dependency nodes.
    tree = {
        "name": "project",
        "version": "1.0.0",
        "children": [
            {
                "name": "a",
                "version": "1.0.0",
                "children": [
                    {"name": "b", "version": "1.0.0", "children": []},
                ],
            }
        ],
    }

    workload = build_npm_scan_workload(manifest, tree)

    assert workload.total_dependency_nodes == 2
    assert workload.unique_packages == 2
    assert {(ref.name, ref.version) for ref in workload.refs} == {
        ("a", "1.0.0"),
        ("b", "1.0.0"),
    }


@pytest.mark.asyncio
async def test_resolve_npm_dependency_tree_resolves_ranges_and_marks_metadata():
    """Direct npm ranges should resolve to a concrete version and carry provenance."""

    manifest = {
        "name": "project",
        "version": "1.0.0",
        "dependencies": {
            "left-pad": "^1.1.0",
        },
    }

    client = AsyncMock()
    with patch(
        "app.services.manifest_utils.package_fetcher.list_npm_package_versions",
        AsyncMock(return_value={"versions": ["1.1.0", "1.2.0", "2.0.0"], "latest_version": "2.0.0"}),
    ):
        tree = await resolve_npm_dependency_tree(client, manifest)

    child = tree["children"][0]
    assert child["name"] == "left-pad"
    assert child["resolution"]["is_direct_dependency"] is True
    assert child["resolution"]["requested_spec"] == "^1.1.0"
    assert child["resolution"]["resolution_kind"] == "resolved-range"
    assert child["version"] == "1.2.0"


@pytest.mark.asyncio
async def test_build_pypi_dependency_tree_deep_carries_requested_spec():
    """PyPI dependency trees should preserve the original requirement spec."""

    manifest = {
        "name": "project",
        "version": "1.0.0",
        "dependencies": {
            "requests": ">=2.31,<3",
        },
    }

    client = AsyncMock()
    with patch(
        "app.services.manifest_utils.package_fetcher.list_pypi_package_versions",
        AsyncMock(return_value={"versions": ["2.30.0", "2.31.0", "2.32.0"], "latest_version": "2.32.0"}),
    ), patch(
        "app.services.manifest_utils._fetch_pypi_package_metadata",
        AsyncMock(return_value=("requests", "2.31.0", [])),
    ):
        tree = await build_pypi_dependency_tree_deep(client, manifest)

    child = tree["children"][0]
    assert child["name"] == "requests"
    assert child["resolution"]["is_direct_dependency"] is True
    assert child["resolution"]["requested_spec"] == ">=2.31,<3"
    assert child["version"] == "2.31.0"


def test_parse_requirement_spec_handles_extras_and_environment_marker():
    """Dependency parser should normalize requirement lines used by remediation and graph building."""

    name, spec = manifest_utils._parse_requirement_spec("requests[socks]>=2.31,<3 ; python_version>='3.10'")

    assert name == "requests"
    assert spec == ">=2.31,<3"
