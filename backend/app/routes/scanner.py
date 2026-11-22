import uuid
from typing import Dict, Any, Literal
from fastapi import APIRouter, UploadFile, File, HTTPException, status
from pydantic import BaseModel

from ..scanner.parser import parse_configuration, ConfigurationParseError
from ..scanner.analyzer import analyze_configuration
from ..scanner.rules import get_all_rules
from ..scanner.open5gs_rules import get_open5gs_rules
from ..database.db import (
    get_scan_details,
    get_scan_statistics,
    search_scan_history,
    save_scan_record,
    update_remediation_status,
)

router = APIRouter(prefix="/api/scan", tags=["Scanner"])

ALLOWED_EXTENSIONS = {".yaml", ".yml", ".json"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


class RemediationStatusUpdate(BaseModel):
    target_nf: str
    status: Literal["PENDING", "FIXED", "ACCEPTED_RISK"]


@router.post(
    "/upload",
    summary="Upload and scan a 5G Network Function configuration file",
    response_description="Parsed configuration findings and risk assessment summary"
)
async def upload_and_scan_configuration(
    file: UploadFile = File(...)
) -> Dict[str, Any]:
    """
    Accepts a 5G Network Function configuration file (YAML or JSON),
    validates syntax, executes predefined security checks, stores the scan
    record in SQLite, and returns actionable security findings.
    """
    if not file or not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No configuration file was uploaded."
        )

    filename = file.filename
    lower_filename = filename.lower()
    
    # 1. Validate file extension
    has_valid_ext = any(lower_filename.endswith(ext) for ext in ALLOWED_EXTENSIONS)
    if not has_valid_ext:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format for '{filename}'. Only YAML (.yaml, .yml) and JSON (.json) files are permitted."
        )

    # 2. Read file contents and check size
    try:
        content_bytes = await file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(e)}"
        )

    if len(content_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded configuration file is empty."
        )

    if len(content_bytes) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Configuration file exceeds maximum allowed size of 5MB."
        )

    # Decode bytes to string
    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File content must be valid UTF-8 encoded text."
        )

    # 3. Parse configuration (YAML / JSON)
    try:
        parsed_config = parse_configuration(content_str, filename=filename)
    except ConfigurationParseError as pe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Configuration syntax error: {str(pe)}"
        )

    # Determine file type representation
    file_type = "json" if lower_filename.endswith(".json") else "yaml"

    # 4. Analyze configuration with modular rule engine
    analysis_result = analyze_configuration(parsed_config, filename=filename)
    scan_id = str(uuid.uuid4())

    # 5. Persist scan summary and findings into SQLite
    try:
        save_scan_record(
            scan_id=scan_id,
            filename=filename,
            file_type=file_type,
            summary=analysis_result["summary"],
            findings=analysis_result["findings"],
            status="COMPLETED"
        )
    except Exception as db_err:
        # Non-fatal error log: do not fail response if DB persistence encounters an issue
        print(f"[Warning] Failed to persist scan record to database: {db_err}")

    # 6. Return response
    return {
        "status": "success",
        "scan_id": scan_id,
        "filename": filename,
        "file_type": file_type,
        "summary": analysis_result["summary"],
        "findings": analysis_result["findings"]
    }


async def list_recent_scans() -> Dict[str, Any]:
    """
    Backwards-compatible helper for direct callers of the legacy route handler.
    """
    return await get_scan_history()


@router.get(
    "/history",
    summary="Retrieve scan history",
    response_description="Paginated scan summaries with score and NF metadata"
)
async def get_scan_history(
    limit: int = 100,
    offset: int = 0,
    search: str = "",
    network_function: str = "",
    severity: str = "",
    sort: str = "date-desc"
) -> Dict[str, Any]:
    if limit < 1 or limit > 500 or offset < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="History limit must be between 1 and 500 and offset cannot be negative."
        )
    try:
        page = search_scan_history(
            limit=limit,
            offset=offset,
            search=search,
            network_function=network_function,
            severity=severity,
            sort=sort,
        )
        return {
            "status": "success",
            "count": len(page["scans"]),
            "total": page["total"],
            "limit": limit,
            "offset": offset,
            "scans": page["scans"],
        }
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch scan history: {str(e)}"
        )


@router.get(
    "/history/{scan_id}",
    summary="Retrieve a completed scan and its findings"
)
async def get_scan_history_detail(scan_id: str) -> Dict[str, Any]:
    try:
        scan = get_scan_details(scan_id)
        if scan is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan was not found."
            )
        return {
            **scan,
            "scan_status": scan["status"],
            "status": "success",
        }
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch scan details: {str(error)}"
        )


@router.get(
    "/statistics",
    summary="Retrieve database-backed scan analytics"
)
async def scan_statistics() -> Dict[str, Any]:
    try:
        return {"status": "success", **get_scan_statistics()}
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate scan statistics: {str(error)}"
        )


@router.get(
    "/rules",
    summary="Retrieve the implemented security rule catalog"
)
async def list_security_rules() -> Dict[str, Any]:
    generic_rules = get_all_rules()
    open5gs_rules = get_open5gs_rules()
    return {
        "status": "success",
        "rules": [
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "target_nf": rule.target_nf,
                "severity": rule.severity.value,
                "category": rule.category,
                "description": rule.description,
                "remediation": rule.remediation,
                "scope": scope,
            }
            for scope, rules in (
                ("Generic", generic_rules),
                ("Open5GS-specific", open5gs_rules),
            )
            for rule in rules
        ],
    }


@router.put(
    "/history/{scan_id}/findings/{rule_id}/status",
    summary="Update a finding's remediation status"
)
async def set_remediation_status(
    scan_id: str,
    rule_id: str,
    update: RemediationStatusUpdate
) -> Dict[str, Any]:
    try:
        result = update_remediation_status(
            scan_id,
            rule_id,
            update.target_nf,
            update.status,
        )
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding was not found in the requested scan."
            )
        return {"status": "success", "remediation": result}
    except HTTPException:
        raise
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error)
        )
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update remediation status: {str(error)}"
        )
