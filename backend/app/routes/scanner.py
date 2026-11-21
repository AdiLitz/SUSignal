import uuid
from typing import Dict, Any, List
from fastapi import APIRouter, UploadFile, File, HTTPException, status
from fastapi.responses import JSONResponse

from ..scanner.parser import parse_configuration, ConfigurationParseError
from ..scanner.analyzer import analyze_configuration
from ..database.db import save_scan_record, get_recent_scans

router = APIRouter(prefix="/api/scan", tags=["Scanner"])

ALLOWED_EXTENSIONS = {".yaml", ".yml", ".json"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


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


@router.get(
    "/history",
    summary="Retrieve recent scans history",
    response_description="List of recently scanned configuration summaries"
)
async def list_recent_scans() -> Dict[str, Any]:
    """
    Returns the list of recently executed configuration scans stored in SQLite.
    """
    try:
        scans = get_recent_scans(limit=10)
        return {
            "status": "success",
            "count": len(scans),
            "scans": scans
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch scan history: {str(e)}"
        )
