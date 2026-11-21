from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any

from .database.db import init_db
from .routes.scanner import router as scanner_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan events: initialize SQLite database on startup.
    """
    init_db()
    yield


# Initialize FastAPI application
app = FastAPI(
    title="SUSignal API",
    description="Intelligent 5G Network Security Misconfiguration Scanner backend API",
    version="0.1.0",
    lifespan=lifespan
)

# Enable CORS for local frontend development (React + Vite default ports)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(scanner_router)


@app.get("/api/health", tags=["Health Check"])
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint to verify backend service readiness.
    """
    return {
        "status": "healthy",
        "service": "SUSignal API",
        "version": "0.1.0",
        "supported_formats": ["YAML", "JSON"],
        "modules": {
            "scanner": "online",
            "database": "online",
            "integrations": "ready_for_phase2"
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
