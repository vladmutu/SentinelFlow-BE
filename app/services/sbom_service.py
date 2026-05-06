"""SBOM generation service with CycloneDX 1.5 export.

Generates a clean JSON SBOM-like structure from dependency trees and
scan results, with optional CycloneDX format export.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas.sbom import (
    CycloneDxDocument,
    SbomComponent,
    SbomDocument,
    SbomLicense,
    SbomMetadata,
    SbomVulnerability,
)
from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models.scan import ScanJob, ScanResult
from app.services import manifest_utils

logger = logging.getLogger(__name__)

_NPM_REGISTRY = "https://registry.npmjs.org"
_PYPI_JSON_API = "https://pypi.org/pypi"


def _build_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a Package URL (purl) identifier."""
    if ecosystem == "npm":
        if name.startswith("@"):
            scope, pkg = name.split("/", 1) if "/" in name else (name, "")
            return f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}@{version}"
        return f"pkg:npm/{quote(name, safe='')}@{version}"
    elif ecosystem == "pypi":
        return f"pkg:pypi/{quote(name.lower(), safe='')}@{version}"
    return f"pkg:{ecosystem}/{quote(name, safe='')}@{version}"


async def _fetch_npm_license(
    client: httpx.AsyncClient,
    name: str,
    version: str,
) -> list[SbomLicense]:
    """Fetch license data from npm registry."""
    try:
        encoded = name.replace("/", "%2F")
        resp = await client.get(f"{_NPM_REGISTRY}/{encoded}/{version}")
        if resp.is_error:
            resp = await client.get(f"{_NPM_REGISTRY}/{encoded}")
            if resp.is_error:
                return []

        data = resp.json()
        if not isinstance(data, dict):
            return []

        license_value = data.get("license")
        if isinstance(license_value, str) and license_value.strip():
            return [SbomLicense(id=license_value.strip(), name=license_value.strip())]
        if isinstance(license_value, dict):
            return [SbomLicense(
                id=license_value.get("type"),
                name=license_value.get("type"),
                url=license_value.get("url"),
            )]

        licenses = data.get("licenses")
        if isinstance(licenses, list):
            result = []
            for lic in licenses:
                if isinstance(lic, dict):
                    result.append(SbomLicense(
                        id=lic.get("type"),
                        name=lic.get("type"),
                        url=lic.get("url"),
                    ))
                elif isinstance(lic, str):
                    result.append(SbomLicense(id=lic, name=lic))
            return result

    except (httpx.RequestError, ValueError):
        pass
    return []


async def _fetch_pypi_license(
    client: httpx.AsyncClient,
    name: str,
    version: str,
) -> list[SbomLicense]:
    """Fetch license data from PyPI JSON API."""
    try:
        resp = await client.get(f"{_PYPI_JSON_API}/{quote(name, safe='')}/{version}/json")
        if resp.is_error:
            resp = await client.get(f"{_PYPI_JSON_API}/{quote(name, safe='')}/json")
            if resp.is_error:
                return []

        data = resp.json()
        if not isinstance(data, dict):
            return []

        info = data.get("info", {})
        if not isinstance(info, dict):
            return []

        license_value = info.get("license")
        if isinstance(license_value, str) and license_value.strip() and license_value.strip().upper() != "UNKNOWN":
            return [SbomLicense(id=license_value.strip(), name=license_value.strip())]

        # Fall back to classifiers
        classifiers = info.get("classifiers", [])
        if isinstance(classifiers, list):
            licenses = []
            for classifier in classifiers:
                if isinstance(classifier, str) and classifier.startswith("License :: "):
                    parts = classifier.split(" :: ")
                    license_name = parts[-1] if len(parts) > 2 else parts[-1]
                    if license_name and license_name != "License":
                        licenses.append(SbomLicense(id=license_name, name=license_name))
            return licenses

    except (httpx.RequestError, ValueError):
        pass
    return []


async def _fetch_licenses_batch(
    ecosystem: str,
    components: list[tuple[str, str]],
) -> dict[str, list[SbomLicense]]:
    """Fetch licenses for a batch of components in parallel."""
    if not settings.sbom_license_fetch_enabled:
        return {}

    semaphore = asyncio.Semaphore(max(1, settings.sbom_license_fetch_concurrency))
    results: dict[str, list[SbomLicense]] = {}

    async def _fetch_one(name: str, version: str) -> None:
        async with semaphore:
            timeout = httpx.Timeout(10.0, connect=5.0)
            async with httpx.AsyncClient(timeout=timeout) as client:
                if ecosystem == "npm":
                    licenses = await _fetch_npm_license(client, name, version)
                else:
                    licenses = await _fetch_pypi_license(client, name, version)
                results[f"{name}@{version}"] = licenses

    await asyncio.gather(
        *(_fetch_one(name, version) for name, version in components),
        return_exceptions=True,
    )
    return results


async def _get_latest_scan_results(
    owner: str,
    repo_name: str,
) -> dict[str, ScanResult]:
    """Load the latest completed scan results keyed by name@version."""
    async with AsyncSessionLocal() as db:
        job_stmt = (
            select(ScanJob)
            .where(
                ScanJob.owner == owner,
                ScanJob.repo_name == repo_name,
                ScanJob.status == "completed",
            )
            .order_by(ScanJob.completed_at.desc())
            .limit(1)
        )
        job = (await db.execute(job_stmt)).scalar_one_or_none()
        if job is None:
            return {}

        results_stmt = select(ScanResult).where(ScanResult.job_id == job.id)
        rows = (await db.execute(results_stmt)).scalars().all()

        return {
            f"{r.package_name}@{r.package_version}": r
            for r in rows
        }


def _extract_vulnerabilities_from_risk_assessment(
    risk_assessment: dict[str, Any] | None,
) -> list[SbomVulnerability]:
    """Extract vulnerability references from a risk assessment payload."""
    if not isinstance(risk_assessment, dict):
        return []

    vuln_signals = risk_assessment.get("vulnerability_signals", [])
    if not isinstance(vuln_signals, list):
        return []

    vulns: list[SbomVulnerability] = []
    seen: set[str] = set()

    for signal in vuln_signals:
        if not isinstance(signal, dict):
            continue
        metadata = signal.get("metadata", {})
        if not isinstance(metadata, dict):
            continue
        advisory_id = metadata.get("advisory_id")
        if not isinstance(advisory_id, str) or not advisory_id or advisory_id in seen:
            continue
        seen.add(advisory_id)

        severity = signal.get("value")
        severity_float = float(severity) if isinstance(severity, (int, float)) else None

        vulns.append(SbomVulnerability(
            id=advisory_id,
            source=signal.get("source"),
            severity=severity_float,
            description=metadata.get("details") or metadata.get("description"),
        ))

    # Also check advisory_references
    refs = risk_assessment.get("advisory_references", [])
    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, str) and ref not in seen:
                seen.add(ref)
                vulns.append(SbomVulnerability(id=ref))

    return vulns


async def generate_sbom(
    owner: str,
    repo: str,
    ecosystem: str,
    access_token: str,
) -> SbomDocument:
    """Generate an SBOM document from the dependency tree and scan results."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Fetch the dependency tree
    timeout = httpx.Timeout(connect=10.0, read=20.0, write=20.0, pool=30.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        if ecosystem == "npm":
            manifest = await manifest_utils.fetch_npm_manifest(client, owner, repo, headers)
            tree = await manifest_utils.resolve_npm_dependency_tree(client, manifest)
        else:
            manifest = await manifest_utils.fetch_pypi_manifest(client, owner, repo, headers)
            tree = await manifest_utils.build_pypi_dependency_tree_deep(client, manifest)

    # Flatten to unique packages
    refs = manifest_utils.flatten_dependencies(tree)

    # Identify direct dependencies from tree root
    direct_dep_names = set()
    for child in tree.get("children", []):
        name = child.get("name", "")
        if name:
            direct_dep_names.add(name.lower())

    # Fetch scan results
    scan_results = await _get_latest_scan_results(owner, repo)

    # Fetch licenses in parallel
    unique_packages = list({(ref.name, ref.version) for ref in refs})
    license_map = await _fetch_licenses_batch(ecosystem, unique_packages)

    # Build components
    components: list[SbomComponent] = []
    seen: set[str] = set()

    for ref in refs:
        key = f"{ref.name}@{ref.version}"
        if key in seen:
            continue
        seen.add(key)

        purl = _build_purl(ecosystem, ref.name, ref.version)
        licenses = license_map.get(key, [])

        # Get scan data
        scan_result = scan_results.get(key)
        risk_status: str | None = None
        risk_score: float | None = None
        vulnerabilities: list[SbomVulnerability] = []

        if scan_result is not None:
            risk_status = scan_result.malware_status
            risk_score = scan_result.malware_score
            if isinstance(scan_result.risk_assessment, dict):
                vulnerabilities = _extract_vulnerabilities_from_risk_assessment(
                    scan_result.risk_assessment
                )

        components.append(SbomComponent(
            name=ref.name,
            version=ref.version,
            ecosystem=ecosystem,
            purl=purl,
            licenses=licenses,
            vulnerabilities=vulnerabilities,
            risk_status=risk_status,
            risk_score=risk_score,
            is_direct=ref.name.lower() in direct_dep_names,
        ))

    return SbomDocument(
        metadata=SbomMetadata(
            timestamp=datetime.now(timezone.utc),
            repository_owner=owner,
            repository_name=repo,
            ecosystem=ecosystem,
            component_count=len(components),
        ),
        components=components,
    )


def export_cyclonedx(sbom: SbomDocument) -> CycloneDxDocument:
    """Convert an internal SBOM document to CycloneDX 1.5 JSON format."""
    cdx_components: list[dict[str, Any]] = []
    cdx_vulnerabilities: list[dict[str, Any]] = []
    seen_vuln_ids: set[str] = set()

    for component in sbom.components:
        cdx_licenses: list[dict[str, Any]] = []
        for lic in component.licenses:
            if lic.id:
                cdx_licenses.append({"license": {"id": lic.id}})
            elif lic.name:
                cdx_licenses.append({"license": {"name": lic.name}})

        cdx_comp: dict[str, Any] = {
            "type": "library",
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
        }
        if cdx_licenses:
            cdx_comp["licenses"] = cdx_licenses

        if component.risk_status:
            cdx_comp["properties"] = [
                {"name": "sentinelflow:risk_status", "value": component.risk_status},
            ]
            if component.risk_score is not None:
                cdx_comp["properties"].append(
                    {"name": "sentinelflow:risk_score", "value": str(round(component.risk_score, 6))}
                )

        cdx_components.append(cdx_comp)

        # Add vulnerabilities
        for vuln in component.vulnerabilities:
            if vuln.id in seen_vuln_ids:
                continue
            seen_vuln_ids.add(vuln.id)

            cdx_vuln: dict[str, Any] = {"id": vuln.id}

            if vuln.source:
                cdx_vuln["source"] = {"name": vuln.source}

            if vuln.severity is not None:
                cdx_vuln["ratings"] = [{"score": vuln.severity, "method": "other"}]

            if vuln.description:
                cdx_vuln["description"] = vuln.description

            cdx_vuln["affects"] = [{
                "ref": component.purl,
                "versions": [{"version": component.version, "status": "affected"}],
            }]

            cdx_vulnerabilities.append(cdx_vuln)

    metadata: dict[str, Any] = {
        "timestamp": sbom.metadata.timestamp.isoformat(),
        "tools": [{
            "vendor": sbom.metadata.tool.vendor,
            "name": sbom.metadata.tool.name,
            "version": sbom.metadata.tool.version,
        }],
        "component": {
            "type": "application",
            "name": f"{sbom.metadata.repository_owner}/{sbom.metadata.repository_name}",
        },
    }

    return CycloneDxDocument(
        metadata=metadata,
        components=cdx_components,
        vulnerabilities=cdx_vulnerabilities if cdx_vulnerabilities else [],
    )
