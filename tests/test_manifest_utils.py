"""Tests for manifest workload helpers."""

from app.services.manifest_utils import build_npm_scan_workload


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
