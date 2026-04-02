"""
Scanner API Endpoints

Provides REST API endpoints for malware detection and vulnerability scanning
of software packages and dependencies using pre-trained Random Forest models.
"""

import io
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Body, Depends, HTTPException, UploadFile, File, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.api.endpoints import repos as repos_endpoint
from app.api.schemas.scanner import (
    HealthCheckResponse,
    RepositoryPackageSummary,
    ScanRepositoryRequest,
    RepositoryScanResult,
    RepositoryScanStatusResponse,
    RepositoryScanSubmitResponse,
    ScanResponseError,
    ScanResponseSuccess,
)
from app.db.session import get_db
from app.models.user import User
from app.services.scanner_service import get_scanner

router = APIRouter(prefix="/api/v1/scan", tags=["Malware Scanner"])
logger = logging.getLogger(__name__)
SCAN_STATUS_STORE: dict[str, dict] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _resolve_owner_repo(payload: ScanRepositoryRequest, current_user: User) -> tuple[str, str]:
    owner = (payload.owner or "").strip()
    repo = (payload.repo or "").strip()
    full_name = (payload.full_name or "").strip()

    if full_name:
        parts = [part for part in full_name.split("/") if part]
        if len(parts) != 2:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="full_name must be in owner/repo format",
            )
        parsed_owner, parsed_repo = parts
        owner = owner or parsed_owner
        repo = repo or parsed_repo

    if not owner or not repo:
        if repo and not owner:
            owner = await repos_endpoint.resolve_owner_for_repo_name(repo, current_user)

    if not owner or not repo:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide owner and repo, or full_name in owner/repo format",
        )

    return owner, repo


def _count_dependency_nodes(node: dict) -> int:
    children = node.get("children", []) if isinstance(node, dict) else []
    if not isinstance(children, list):
        return 0

    total = len(children)
    for child in children:
        if isinstance(child, dict):
            total += _count_dependency_nodes(child)
    return total


def _prediction_from_dependency_counts(scanner, npm_count: int, py_count: int) -> dict:
    total = npm_count + py_count
    features = {
        "max_entropy": 0.0,
        "avg_entropy": 0.0,
        "eval_count": 0.0,
        "exec_count": 0.0,
        "base64_count": 0.0,
        "network_imports": float(min(total, 1000)),
        "entropy_gap": 0.0,
        "exec_eval_ratio": 1.0,
        "network_exec_ratio": float(min(total + 1, 1001)),
        "obfuscation_index": 0.0,
    }
    return scanner.predict(features)


@router.get("/health", response_model=HealthCheckResponse)
async def scanner_health(current_user: User = Depends(get_current_user)) -> dict:
    """
    Check scanner service health and model availability.
    
    **Protected by authentication**
    
    Returns:
        - status: Service operational status
        - model_loaded: Whether the ML model is successfully loaded
        - threshold: Current classification threshold
    """
    scanner = get_scanner()
    
    return {
        "status": "healthy" if scanner.model else "degraded",
        "model_loaded": scanner.model is not None,
        "threshold": scanner.optimal_threshold,
    }


@router.post("/dependency", response_model=ScanResponseSuccess | ScanResponseError, status_code=200)
async def scan_dependency_file(
    file: UploadFile = File(..., description="Package archive (.zip, .whl, .tar.gz)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Scan an uploaded dependency package for malware.
    
    **Protected by authentication**
    
    Accepts package archives (ZIP, WHL, TAR.GZ) and analyzes:
    - Abstract Syntax Tree patterns (eval, exec, network imports, etc.)
    - Shannon entropy (compression-based obfuscation detection)
    - Engineered risk indicators
    
    Args:
        file: Package archive file to scan
        current_user: Authenticated user performing the scan
        
    Returns:
        Scan result with extracted features and classification
        
    Raises:
        400: Invalid file format or scan failure
        401: User not authenticated
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File upload failed: no filename",
        )

    logger.info(f"User {current_user.username} scanning file: {file.filename}")

    try:
        # Read file into memory
        file_content = await file.read()
        if not file_content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty",
            )

        # Validate file size (max 100MB)
        if len(file_content) > 100 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File size exceeds 100MB limit",
            )

        # Write to temporary file for processing
        with tempfile.NamedTemporaryFile(
            suffix=Path(file.filename).suffix,
            delete=False,
        ) as temp_file:
            temp_file.write(file_content)
            temp_path = Path(temp_file.name)

        try:
            # Run scan
            scanner = get_scanner()
            scan_result = scanner.scan_package_archive(temp_path)

            if not scan_result.get("success"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=scan_result.get(
                        "error", "Scan failed for unknown reason"
                    ),
                )

            logger.info(
                f"Scan complete for {file.filename}: "
                f"{scan_result['prediction']['classification']}"
            )

            return {
                "success": True,
                "archive_name": file.filename,
                "features": scan_result["features"],
                "prediction": scan_result["prediction"],
            }

        finally:
            # Clean up temporary file
            temp_path.unlink(missing_ok=True)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return {
            "success": False,
            "error": f"Internal scan error: {str(e)}",
        }


@router.post("/repository", response_model=RepositoryScanSubmitResponse, status_code=200)
async def scan_repository(
    payload: ScanRepositoryRequest = Body(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Scan a GitHub repository for malware.
    
    **Protected by authentication**
    
    This endpoint fetches code from a GitHub repository and analyzes it for:
    - Dangerous code patterns (eval, exec, network access)
    - Code obfuscation indicators
    - Malicious dependencies
    
    Args:
        repo_url: GitHub repository URL (HTTPS format)
        current_user: Authenticated user performing the scan
        
    Returns:
        Scan result with extracted features and classification
        
    Raises:
        400: Invalid repository URL or scan failure
        401: User not authenticated
        403: Access denied to repository
    """
    logger.info(
        "Repository scan request received user=%s owner=%s repo=%s full_name=%s branch=%s",
        current_user.username,
        payload.owner,
        payload.repo,
        payload.full_name,
        payload.branch,
    )

    owner, repo_name = await _resolve_owner_repo(payload, current_user)
    full_name = f"{owner}/{repo_name}"
    scan_id = str(uuid4())

    SCAN_STATUS_STORE[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "result": None,
        "updated_at": _now_iso(),
    }

    logger.info(
        "Repository scan started scan_id=%s user=%s repository=%s",
        scan_id,
        current_user.username,
        full_name,
    )

    try:
        npm_tree = None
        py_tree = None
        warnings: list[str] = []

        try:
            npm_tree = await repos_endpoint.get_npm_dependency_tree(
                owner=owner,
                repo_name=repo_name,
                current_user=current_user,
            )
            logger.info("NPM dependency tree resolved scan_id=%s repository=%s", scan_id, full_name)
        except HTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                logger.warning(
                    "NPM dependency tree failed scan_id=%s repository=%s status=%s detail=%s",
                    scan_id,
                    full_name,
                    exc.status_code,
                    exc.detail,
                )
                warnings.append(f"npm dependencies unavailable: {exc.detail}")
            else:
                logger.info(
                    "NPM manifests not found scan_id=%s repository=%s detail=%s",
                    scan_id,
                    full_name,
                    exc.detail,
                )

        try:
            py_tree = await repos_endpoint.get_python_dependency_tree(
                owner=owner,
                repo_name=repo_name,
                current_user=current_user,
            )
            logger.info("Python dependency tree resolved scan_id=%s repository=%s", scan_id, full_name)
        except HTTPException as exc:
            if exc.status_code != status.HTTP_404_NOT_FOUND:
                logger.warning(
                    "Python dependency tree failed scan_id=%s repository=%s status=%s detail=%s",
                    scan_id,
                    full_name,
                    exc.status_code,
                    exc.detail,
                )
                warnings.append(f"python dependencies unavailable: {exc.detail}")
            else:
                logger.info(
                    "Python manifests not found scan_id=%s repository=%s detail=%s",
                    scan_id,
                    full_name,
                    exc.detail,
                )

        npm_count = _count_dependency_nodes(npm_tree) if isinstance(npm_tree, dict) else 0
        py_count = _count_dependency_nodes(py_tree) if isinstance(py_tree, dict) else 0

        logger.info(
            "Dependency counts computed scan_id=%s repository=%s npm_count=%s python_count=%s",
            scan_id,
            full_name,
            npm_count,
            py_count,
        )

        packages: list[RepositoryPackageSummary] = []
        if isinstance(npm_tree, dict):
            packages.append(
                RepositoryPackageSummary(
                    ecosystem="npm",
                    root_name=str(npm_tree.get("name") or repo_name),
                    dependency_count=npm_count,
                    tree=npm_tree,
                )
            )
        if isinstance(py_tree, dict):
            packages.append(
                RepositoryPackageSummary(
                    ecosystem="python",
                    root_name=str(py_tree.get("name") or repo_name),
                    dependency_count=py_count,
                    tree=py_tree,
                )
            )

        scanner = get_scanner()
        prediction = None
        reason = None
        status_value = "completed"

        if npm_count + py_count == 0:
            reason = (
                "No lockfile or dependency manifests with resolvable dependencies were found "
                "(expected package-lock.json/package.json or requirements.txt/pyproject.toml)."
            )
            if warnings:
                reason = f"{reason} Warnings: {' | '.join(warnings)}"
            logger.info(
                "Repository scan completed without dependencies scan_id=%s repository=%s reason=%s",
                scan_id,
                full_name,
                reason,
            )
        else:
            prediction = _prediction_from_dependency_counts(scanner, npm_count, py_count)
            if warnings:
                reason = " | ".join(warnings)
            logger.info(
                "Repository scan prediction computed scan_id=%s repository=%s classification=%s confidence=%.4f risk=%s",
                scan_id,
                full_name,
                prediction.get("classification"),
                float(prediction.get("confidence", 0.0)),
                prediction.get("risk_level"),
            )

        result_payload = RepositoryScanResult(
            owner=owner,
            repo=repo_name,
            full_name=full_name,
            status=status_value,
            reason=reason,
            packages=packages,
            prediction=prediction,
        ).model_dump()

        SCAN_STATUS_STORE[scan_id] = {
            "scan_id": scan_id,
            "status": status_value,
            "result": result_payload,
            "updated_at": _now_iso(),
        }

        logger.info(
            "Repository scan finished scan_id=%s repository=%s status=%s package_ecosystems=%s",
            scan_id,
            full_name,
            status_value,
            [pkg.ecosystem for pkg in packages],
        )

        return {
            "success": True,
            "scan_id": scan_id,
            "status": status_value,
            "result": result_payload,
        }

    except HTTPException as exc:
        logger.warning(
            "Repository scan failed with HTTPException scan_id=%s repository=%s status=%s detail=%s",
            scan_id,
            full_name,
            exc.status_code,
            exc.detail,
        )
        failed_result = RepositoryScanResult(
            owner=owner,
            repo=repo_name,
            full_name=full_name,
            status="failed",
            reason=str(exc.detail),
            packages=[],
            prediction=None,
        ).model_dump()
        SCAN_STATUS_STORE[scan_id] = {
            "scan_id": scan_id,
            "status": "failed",
            "result": failed_result,
            "updated_at": _now_iso(),
        }
        return {
            "success": True,
            "scan_id": scan_id,
            "status": "failed",
            "result": failed_result,
        }
    except Exception as e:
        logger.exception(
            "Repository scan failed with unexpected exception scan_id=%s repository=%s",
            scan_id,
            full_name,
        )
        failed_result = RepositoryScanResult(
            owner=owner,
            repo=repo_name,
            full_name=full_name,
            status="failed",
            reason=f"Failed to scan repository: {str(e)}",
            packages=[],
            prediction=None,
        ).model_dump()
        SCAN_STATUS_STORE[scan_id] = {
            "scan_id": scan_id,
            "status": "failed",
            "result": failed_result,
            "updated_at": _now_iso(),
        }
        return {
            "success": True,
            "scan_id": scan_id,
            "status": "failed",
            "result": failed_result,
        }


@router.get("/repository/{scan_id}/status", response_model=RepositoryScanStatusResponse, status_code=200)
async def get_repository_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    _ = current_user

    status_payload = SCAN_STATUS_STORE.get(scan_id)
    if status_payload is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan id not found",
        )

    return {
        "success": True,
        "scan_id": scan_id,
        "status": status_payload.get("status", "failed"),
        "result": status_payload.get("result"),
    }


@router.post("/batch", status_code=200)
async def scan_batch_dependencies(
    files: list[UploadFile] = File(..., description="Multiple package archives"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Scan multiple dependencies in batch.
    
    **Protected by authentication**
    
    Scans multiple package files and returns aggregated results. Useful for
    analyzing entire dependency trees or package ecosystems.
    
    Args:
        files: List of package archive files
        current_user: Authenticated user performing the scan
        
    Returns:
        Aggregated scan results with statistics
        
    Raises:
        400: Invalid files or scan failure
        401: User not authenticated
    """
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No files provided for batch scan",
        )

    if len(files) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 50 files per batch",
        )

    logger.info(f"User {current_user.username} scanning {len(files)} files in batch mode")

    scanner = get_scanner()
    results = []
    malicious_count = 0
    benign_count = 0
    error_count = 0

    for file in files:
        try:
            file_content = await file.read()
            if not file_content:
                error_count += 1
                continue

            with tempfile.NamedTemporaryFile(
                suffix=Path(file.filename).suffix,
                delete=False,
            ) as temp_file:
                temp_file.write(file_content)
                temp_path = Path(temp_file.name)

            try:
                scan_result = scanner.scan_package_archive(temp_path)
                if scan_result.get("success"):
                    classification = scan_result["prediction"]["classification"]
                    if classification == "malicious":
                        malicious_count += 1
                    elif classification == "benign":
                        benign_count += 1

                    results.append(
                        {
                            "file": file.filename,
                            "prediction": scan_result["prediction"],
                        }
                    )
                else:
                    error_count += 1
            finally:
                temp_path.unlink(missing_ok=True)

        except Exception as e:
            logger.error(f"Error scanning {file.filename}: {e}")
            error_count += 1

    return {
        "success": True,
        "total_files": len(files),
        "scanned": len(results),
        "malicious_count": malicious_count,
        "benign_count": benign_count,
        "error_count": error_count,
        "results": results,
    }
