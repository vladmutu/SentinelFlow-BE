"""Tests for dependency version compatibility checking."""

import pytest

from app.api.endpoints.compatibility import (
    _check_npm_compatibility,
    _check_pypi_compatibility,
    _parse_requirements_txt,
)


class TestNpmCompatibility:
    """Tests for npm version compatibility checks."""

    def test_new_dependency(self):
        """New dependency (no existing constraint) is always compatible."""
        result = _check_npm_compatibility("lodash", "5.0.0", None)
        assert result.compatible is True
        assert result.exists_in_manifest is False

    def test_caret_range_compatible(self):
        """Version within caret range is compatible."""
        result = _check_npm_compatibility("lodash", "4.18.0", "^4.17.21")
        assert result.compatible is True

    def test_caret_range_incompatible(self):
        """Major version change outside caret range is incompatible."""
        result = _check_npm_compatibility("lodash", "5.0.0", "^4.17.21")
        assert result.compatible is False
        assert result.suggestion is not None

    def test_tilde_range_compatible(self):
        """Version within tilde range is compatible."""
        result = _check_npm_compatibility("express", "4.17.22", "~4.17.21")
        assert result.compatible is True

    def test_tilde_range_incompatible_minor(self):
        """Minor version change outside tilde range is incompatible."""
        result = _check_npm_compatibility("express", "4.18.0", "~4.17.21")
        assert result.compatible is False

    def test_exact_match(self):
        """Exact pinned version matches correctly."""
        result = _check_npm_compatibility("react", "18.2.0", "18.2.0")
        assert result.compatible is True

    def test_exact_mismatch(self):
        """Different version from pinned is incompatible."""
        result = _check_npm_compatibility("react", "19.0.0", "18.2.0")
        assert result.compatible is False

    def test_non_exact_spec_same(self):
        """Identical non-exact specs are compatible."""
        result = _check_npm_compatibility("pkg", "^4.0.0", "^4.0.0")
        assert result.compatible is True

    def test_caret_range_below_base(self):
        """Version below caret base is incompatible."""
        result = _check_npm_compatibility("lodash", "4.16.0", "^4.17.21")
        assert result.compatible is False


class TestPypiCompatibility:
    """Tests for PyPI version compatibility checks."""

    def test_new_dependency(self):
        """New dependency is always compatible."""
        result = _check_pypi_compatibility("requests", "2.31.0", None)
        assert result.compatible is True

    def test_pinned_same_major(self):
        """Pinned with same major version is compatible."""
        result = _check_pypi_compatibility("requests", "2.32.0", "==2.31.0")
        assert result.compatible is True

    def test_pinned_different_major(self):
        """Pinned with different major version is incompatible."""
        result = _check_pypi_compatibility("requests", "3.0.0", "==2.31.0")
        assert result.compatible is False

    def test_lower_bound_satisfied(self):
        """Version above lower bound is compatible."""
        result = _check_pypi_compatibility("flask", "3.1.0", ">=3.0.0")
        assert result.compatible is True

    def test_lower_bound_not_satisfied(self):
        """Version below lower bound is incompatible."""
        result = _check_pypi_compatibility("flask", "2.9.0", ">=3.0.0")
        assert result.compatible is False

    def test_compatible_release(self):
        """Compatible release (~=) within range."""
        result = _check_pypi_compatibility("pkg", "2.1.0", "~=2.0.0")
        assert result.compatible is True

    def test_compatible_release_outside(self):
        """Compatible release (~=) outside range."""
        result = _check_pypi_compatibility("pkg", "3.0.0", "~=2.0.0")
        assert result.compatible is False


class TestParseRequirementsTxt:
    """Tests for requirements.txt parsing."""

    def test_basic_parsing(self):
        content = "requests==2.31.0\nflask>=3.0.0\nnumpy"
        result = _parse_requirements_txt(content)
        assert result["requests"] == "==2.31.0"
        assert result["flask"] == ">=3.0.0"
        assert result["numpy"] is None

    def test_ignores_comments(self):
        content = "# This is a comment\nrequests==2.31.0"
        result = _parse_requirements_txt(content)
        assert "# this is a comment" not in result
        assert "requests" in result

    def test_ignores_flags(self):
        content = "-r base.txt\nrequests==2.31.0"
        result = _parse_requirements_txt(content)
        assert len(result) == 1
        assert "requests" in result

    def test_ignores_empty_lines(self):
        content = "\n\nrequests==2.31.0\n\n"
        result = _parse_requirements_txt(content)
        assert len(result) == 1

    def test_strips_extras(self):
        content = "uvicorn[standard]==0.30.0"
        result = _parse_requirements_txt(content)
        assert "uvicorn" in result

    def test_strips_environment_markers(self):
        content = "pywin32==306 ; sys_platform == 'win32'"
        result = _parse_requirements_txt(content)
        assert "pywin32" in result
