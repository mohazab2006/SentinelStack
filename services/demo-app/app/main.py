import os
import time
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="SentinelStack Demo App")
logging_service_url = os.getenv("LOGGING_SERVICE_URL", "http://logging-service:8000")
admin_token = os.getenv("ADMIN_TOKEN", "admin-secret")


@app.middleware("http")
async def request_logger(request: Request, call_next):
    started_at = time.perf_counter()
    response = await call_next(request)
    response_time_ms = int((time.perf_counter() - started_at) * 1000)
    client_ip = request.headers.get("x-forwarded-for", request.client.host if request.client else "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    payload = {
        "ip_address": client_ip,
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "user_agent": request.headers.get("user-agent"),
        "response_time_ms": response_time_ms,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{logging_service_url}/ingest-request", json=payload)
    except Exception:
        # Request logging should not block demo app responses.
        pass
    return response


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "SentinelStack demo app is running"}


@app.post("/login")
async def login(body: dict) -> JSONResponse:
    username = body.get("username")
    password = body.get("password")
    if username == "admin" and password == "password123":
        return JSONResponse({"success": True, "token": admin_token}, status_code=200)
    return JSONResponse({"success": False, "error": "Invalid credentials"}, status_code=401)


@app.get("/admin")
async def admin(x_admin_token: str | None = Header(default=None)) -> JSONResponse:
    if x_admin_token != admin_token:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse({"message": "Sensitive admin data"}, status_code=200)


@app.get("/profile")
async def profile() -> dict[str, str]:
    return {"profile": "Demo user profile"}


@app.get("/reports")
async def reports() -> dict[str, list[str]]:
    return {"reports": ["daily-traffic", "weekly-security-summary"]}


@app.get("/config")
async def config(x_admin_token: str | None = Header(default=None)) -> JSONResponse:
    if x_admin_token != admin_token:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return JSONResponse({"feature_flags": "demo-only"}, status_code=200)
