from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
import os
import logging

from routes import auth, users, rules, alerts, assets, response, threat_intel, agents, fim, vulnerabilities, sca, compliance, hunting, audit, health, reporting, dashboard, threat_map, incidents, logs, sandbox
from db.database import engine, Base
import db.models  # noqa: F401 — ensures all models are registered with Base

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Validate Environment Variables
REQUIRED_ENV_VARS = ["JWT_SECRET", "POSTGRES_URL", "REDIS_URL", "ELASTICSEARCH_HOSTS"]
missing_vars = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
if missing_vars:
    logger.error(f"CRITICAL: Missing required environment variables: {', '.join(missing_vars)}")
    import sys
    sys.exit(1)

# Lifespan: create all DB tables on startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Creating database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready.")
    yield

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)

# Initialize FastAPI
app = FastAPI(
    title="SecureWatch SOC API",
    description="Enterprise-grade API backing the SOC Dashboard",
    version="1.0.0",
    lifespan=lifespan
)

from fastapi.responses import JSONResponse
import traceback

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}\n{traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal Server Error", "detail": str(exc)},
    )

# Apply limits
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS Policy — allow localhost, 127.0.0.1, and any LAN (192.168.x.x / 10.x.x.x) origin
# "credentials=True" requires explicit origins; "*" + credentials is invalid in browsers.
_default_origins = (
    "http://localhost:3000,http://127.0.0.1:3000,"
    "http://localhost:5173,http://127.0.0.1:5173,"
    "http://localhost:5174,http://127.0.0.1:5174,"
    # LAN IPs — cover the whole /24 so any device on the network can use the sandbox
    "http://192.168.1.3:3000,http://192.168.1.3:5174,"
    "http://192.168.1.6:3000,http://192.168.1.6:5174"
)
CORS_ORIGINS = os.getenv("CORS_ORIGINS", _default_origins).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi import Depends
from auth.rbac import get_current_user

# Includes
app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(users.router, prefix="/api/users", tags=["Users"], dependencies=[Depends(get_current_user)])
app.include_router(rules.router, prefix="/api/rules", tags=["Rules"], dependencies=[Depends(get_current_user)])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(assets.router, prefix="/api/assets", tags=["Assets"])  # Auth handled per-endpoint (risk-update is internal)
app.include_router(response.router, prefix="/api/response", tags=["Active Response"], dependencies=[Depends(get_current_user)])
app.include_router(threat_intel.router, prefix="/api/threat-intel", tags=["Threat Intel"], dependencies=[Depends(get_current_user)])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"], dependencies=[Depends(get_current_user)])
app.include_router(fim.router, prefix="/api/fim", tags=["File Integrity"], dependencies=[Depends(get_current_user)])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["Vulnerabilities"], dependencies=[Depends(get_current_user)])
app.include_router(sca.router, prefix="/api/sca", tags=["Configuration Assessment"], dependencies=[Depends(get_current_user)])
app.include_router(compliance.router, prefix="/api/compliance", tags=["Compliance"], dependencies=[Depends(get_current_user)])
app.include_router(hunting.router, prefix="/api/hunting", tags=["Threat Hunting"], dependencies=[Depends(get_current_user)])
app.include_router(audit.router, prefix="/api/audit", tags=["Audit Logs"], dependencies=[Depends(get_current_user)])
app.include_router(health.router, prefix="/api/diagnostics", tags=["Health Diagnostics"])
app.include_router(reporting.router, prefix="/api/reporting", tags=["Reporting Engine"], dependencies=[Depends(get_current_user)])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
app.include_router(threat_map.router, prefix="/api/v1/threat-map", tags=["Threat Map"])
app.include_router(incidents.router, prefix="/api/v1/incidents", tags=["Incidents"])
app.include_router(logs.router, prefix="/api/v1/logs", tags=["Logs"])
app.include_router(sandbox.router, prefix="/api/sandbox", tags=["Attack Sandbox"])

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "SecureWatch Backend"}
