from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query, status
from starlette.concurrency import run_in_threadpool

from ..database.db import (
    get_latest_runtime_assessment,
    get_runtime_assessment,
    get_runtime_assessment_statistics,
    get_scan_statistics,
    list_runtime_assessments,
)
from ..integrations.open5gs_alpha import (
    EnvironmentManagerError,
    NETWORK_NAME,
    alpha_environment,
    beta_environment,
)
from ..scanner.runtime_assessment import assess_network_alpha, assess_network_beta


router = APIRouter(prefix="/api/environments", tags=["Test Environments"])


def _unavailable(
    error: Exception,
    environment_name: str = NETWORK_NAME,
) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=f"{environment_name} operation failed: {error}",
    )


@router.get("", summary="List managed test environments")
async def list_environments() -> Dict[str, Any]:
    try:
        environments = [
            await run_in_threadpool(alpha_environment.get_status),
            await run_in_threadpool(beta_environment.get_status),
        ]
        return {"status": "success", "environments": environments}
    except EnvironmentManagerError as error:
        raise _unavailable(error, "Managed test environments") from error


@router.get("/statistics", summary="Retrieve environment and runtime analytics")
async def environment_statistics() -> Dict[str, Any]:
    try:
        environments = [
            await run_in_threadpool(alpha_environment.get_status),
            await run_in_threadpool(beta_environment.get_status),
        ]
        runtime_stats = get_runtime_assessment_statistics()
        configuration_stats = get_scan_statistics()
    except EnvironmentManagerError as error:
        raise _unavailable(error, "Managed test environments") from error
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate environment statistics: {error}",
        ) from error

    distribution = {
        "RUNNING": 0,
        "DEGRADED": 0,
        "STOPPED": 0,
        "NOT_CREATED": 0,
    }
    status_keys = {
        "running": "RUNNING",
        "degraded": "DEGRADED",
        "stopped": "STOPPED",
        "not_created": "NOT_CREATED",
    }
    for environment in environments:
        status_key = status_keys.get(environment["status"], "DEGRADED")
        distribution[status_key] += 1

    return {
        "status": "success",
        "total_test_networks": len(environments),
        "running_networks": sum(
            int(environment["is_running"]) for environment in environments
        ),
        "runtime_assessments_completed": runtime_stats[
            "runtime_assessments_completed"
        ],
        "total_runtime_findings": runtime_stats["total_runtime_findings"],
        "network_status_distribution": [
            {"status": name, "count": count}
            for name, count in distribution.items()
        ],
        "runtime_findings_by_severity": runtime_stats[
            "runtime_findings_by_severity"
        ],
        "runtime_findings_by_network": runtime_stats[
            "runtime_findings_by_network"
        ],
        "findings_by_type": [
            {
                "assessment_type": "configuration",
                "label": "Configuration Assessment",
                "count": configuration_stats["stats"]["total_vulnerabilities"],
            },
            {
                "assessment_type": "runtime",
                "label": "Runtime Assessment",
                "count": runtime_stats["total_runtime_findings"],
            },
        ],
    }


@router.get("/alpha", summary="Get Network Alpha health and latest assessment")
async def get_network_alpha() -> Dict[str, Any]:
    try:
        environment = await run_in_threadpool(alpha_environment.get_status)
        latest_assessment = get_latest_runtime_assessment("alpha")
        return {
            "status": "success",
            "environment": environment,
            "last_runtime_assessment": latest_assessment,
        }
    except EnvironmentManagerError as error:
        raise _unavailable(error, NETWORK_NAME) from error
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve Network Alpha status: {error}",
        ) from error


@router.post("/alpha/start", summary="Start Network Alpha")
async def start_network_alpha() -> Dict[str, Any]:
    try:
        environment = await run_in_threadpool(alpha_environment.start)
        return {"status": "success", "environment": environment}
    except EnvironmentManagerError as error:
        raise _unavailable(error) from error


@router.post("/alpha/stop", summary="Stop Network Alpha without deleting data")
async def stop_network_alpha() -> Dict[str, Any]:
    try:
        environment = await run_in_threadpool(alpha_environment.stop)
        return {"status": "success", "environment": environment}
    except EnvironmentManagerError as error:
        raise _unavailable(error) from error


@router.post("/alpha/assessments", summary="Run a Network Alpha runtime assessment")
async def assess_network_alpha_route() -> Dict[str, Any]:
    try:
        result = await run_in_threadpool(assess_network_alpha)
        return {"status": "success", **result}
    except EnvironmentManagerError as error:
        raise _unavailable(error) from error
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Runtime assessment failed: {error}",
        ) from error


@router.get("/alpha/assessments", summary="List saved Network Alpha assessments")
async def list_network_alpha_assessments(
    limit: int = Query(default=20, ge=1, le=100),
) -> Dict[str, Any]:
    try:
        assessments = list_runtime_assessments(limit, "alpha")
        return {
            "status": "success",
            "count": len(assessments),
            "assessments": assessments,
        }
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve runtime assessment history: {error}",
        ) from error


@router.get(
    "/alpha/assessments/{assessment_id}",
    summary="Retrieve a saved Network Alpha runtime assessment",
)
async def get_network_alpha_assessment(assessment_id: str) -> Dict[str, Any]:
    try:
        assessment = get_runtime_assessment(assessment_id)
        if assessment is None or assessment["network_id"] != "alpha":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Runtime assessment was not found.",
            )
        return {"status": "success", **assessment}
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve runtime assessment: {error}",
        ) from error


@router.get("/beta", summary="Get Network Beta health and latest assessment")
async def get_network_beta() -> Dict[str, Any]:
    try:
        environment = await run_in_threadpool(beta_environment.get_status)
        latest_assessment = get_latest_runtime_assessment("beta")
        return {
            "status": "success",
            "environment": environment,
            "last_runtime_assessment": latest_assessment,
        }
    except EnvironmentManagerError as error:
        raise _unavailable(error, beta_environment.network_name) from error
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve Network Beta status: {error}",
        ) from error


@router.post("/beta/start", summary="Start Network Beta")
async def start_network_beta() -> Dict[str, Any]:
    try:
        environment = await run_in_threadpool(beta_environment.start)
        return {"status": "success", "environment": environment}
    except EnvironmentManagerError as error:
        raise _unavailable(error, beta_environment.network_name) from error


@router.post("/beta/stop", summary="Stop Network Beta without deleting data")
async def stop_network_beta() -> Dict[str, Any]:
    try:
        environment = await run_in_threadpool(beta_environment.stop)
        return {"status": "success", "environment": environment}
    except EnvironmentManagerError as error:
        raise _unavailable(error, beta_environment.network_name) from error


@router.post("/beta/assessments", summary="Run a Network Beta runtime assessment")
async def assess_network_beta_route() -> Dict[str, Any]:
    try:
        result = await run_in_threadpool(assess_network_beta)
        return {"status": "success", **result}
    except EnvironmentManagerError as error:
        raise _unavailable(error, beta_environment.network_name) from error
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network Beta runtime assessment failed: {error}",
        ) from error


@router.get("/beta/assessments", summary="List saved Network Beta assessments")
async def list_network_beta_assessments(
    limit: int = Query(default=20, ge=1, le=100),
) -> Dict[str, Any]:
    try:
        assessments = list_runtime_assessments(limit, "beta")
        return {
            "status": "success",
            "count": len(assessments),
            "assessments": assessments,
        }
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve Network Beta assessment history: {error}",
        ) from error


@router.get(
    "/beta/assessments/{assessment_id}",
    summary="Retrieve a saved Network Beta runtime assessment",
)
async def get_network_beta_assessment(assessment_id: str) -> Dict[str, Any]:
    try:
        assessment = get_runtime_assessment(assessment_id)
        if assessment is None or assessment["network_id"] != "beta":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Runtime assessment was not found.",
            )
        return {"status": "success", **assessment}
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve Network Beta runtime assessment: {error}",
        ) from error
