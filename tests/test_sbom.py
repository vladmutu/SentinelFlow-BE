"""Tests for SBOM generation and CycloneDX export."""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

from app.api.schemas.sbom import SbomDocument, SbomComponent, SbomLicense, SbomVulnerability
from app.services.sbom_service import _build_purl, export_cyclonedx, _extract_vulnerabilities_from_risk_assessment


class TestBuildPurl:
    """Tests for Package URL generation."""

    def test_npm_simple(self):
        assert _build_purl("npm", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"

    def test_npm_scoped(self):
        result = _build_purl("npm", "@types/node", "22.0.0")
        assert result.startswith("pkg:npm/")
        assert "22.0.0" in result

    def test_pypi(self):
        assert _build_purl("pypi", "requests", "2.31.0") == "pkg:pypi/requests@2.31.0"

    def test_pypi_uppercase_normalized(self):
        result = _build_purl("pypi", "Flask", "3.0.0")
        assert "flask" in result


class TestExportCycloneDx:
    """Tests for CycloneDX 1.5 export."""

    def _make_sbom(self, components=None):
        from app.api.schemas.sbom import SbomMetadata, SbomToolInfo
        return SbomDocument(
            metadata=SbomMetadata(
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                repository_owner="test-owner",
                repository_name="test-repo",
                ecosystem="npm",
                component_count=len(components or []),
            ),
            components=components or [],
        )

    def test_empty_sbom(self):
        sbom = self._make_sbom()
        cdx = export_cyclonedx(sbom)
        assert cdx.bomFormat == "CycloneDX"
        assert cdx.specVersion == "1.5"
        assert cdx.components == []
        assert cdx.vulnerabilities == []

    def test_component_with_license(self):
        component = SbomComponent(
            name="lodash",
            version="4.17.21",
            ecosystem="npm",
            purl="pkg:npm/lodash@4.17.21",
            licenses=[SbomLicense(id="MIT", name="MIT")],
        )
        sbom = self._make_sbom(components=[component])
        cdx = export_cyclonedx(sbom)
        assert len(cdx.components) == 1
        assert cdx.components[0]["name"] == "lodash"
        assert cdx.components[0]["purl"] == "pkg:npm/lodash@4.17.21"
        assert len(cdx.components[0]["licenses"]) == 1

    def test_component_with_vulnerability(self):
        component = SbomComponent(
            name="express",
            version="4.17.0",
            ecosystem="npm",
            purl="pkg:npm/express@4.17.0",
            vulnerabilities=[
                SbomVulnerability(id="CVE-2024-1234", source="nvd", severity=7.5)
            ],
            risk_status="malicious",
            risk_score=0.85,
        )
        sbom = self._make_sbom(components=[component])
        cdx = export_cyclonedx(sbom)
        assert len(cdx.vulnerabilities) == 1
        assert cdx.vulnerabilities[0]["id"] == "CVE-2024-1234"

    def test_metadata_tool(self):
        sbom = self._make_sbom()
        cdx = export_cyclonedx(sbom)
        assert cdx.metadata["tools"][0]["vendor"] == "SentinelFlow"
        assert cdx.metadata["tools"][0]["name"] == "SentinelFlow-BE"

    def test_deduplicates_vulnerabilities(self):
        vuln = SbomVulnerability(id="CVE-2024-1234")
        c1 = SbomComponent(
            name="pkg1", version="1.0.0", ecosystem="npm",
            purl="pkg:npm/pkg1@1.0.0", vulnerabilities=[vuln],
        )
        c2 = SbomComponent(
            name="pkg2", version="2.0.0", ecosystem="npm",
            purl="pkg:npm/pkg2@2.0.0", vulnerabilities=[vuln],
        )
        sbom = self._make_sbom(components=[c1, c2])
        cdx = export_cyclonedx(sbom)
        assert len(cdx.vulnerabilities) == 1


class TestExtractVulnerabilities:
    """Tests for vulnerability extraction from risk assessments."""

    def test_empty_assessment(self):
        assert _extract_vulnerabilities_from_risk_assessment(None) == []
        assert _extract_vulnerabilities_from_risk_assessment({}) == []

    def test_extracts_from_signals(self):
        assessment = {
            "vulnerability_signals": [
                {
                    "source": "osv",
                    "name": "vulnerability_detected",
                    "value": 9.8,
                    "metadata": {
                        "advisory_id": "GHSA-1234",
                        "details": "Critical vuln",
                    },
                }
            ],
        }
        vulns = _extract_vulnerabilities_from_risk_assessment(assessment)
        assert len(vulns) == 1
        assert vulns[0].id == "GHSA-1234"
        assert vulns[0].severity == 9.8

    def test_extracts_from_advisory_references(self):
        assessment = {
            "vulnerability_signals": [],
            "advisory_references": ["CVE-2024-5678"],
        }
        vulns = _extract_vulnerabilities_from_risk_assessment(assessment)
        assert len(vulns) == 1
        assert vulns[0].id == "CVE-2024-5678"

    def test_deduplicates(self):
        assessment = {
            "vulnerability_signals": [
                {
                    "source": "osv",
                    "name": "vulnerability_detected",
                    "value": None,
                    "metadata": {"advisory_id": "CVE-2024-1111"},
                },
            ],
            "advisory_references": ["CVE-2024-1111"],
        }
        vulns = _extract_vulnerabilities_from_risk_assessment(assessment)
        assert len(vulns) == 1
