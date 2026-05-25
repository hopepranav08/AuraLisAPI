# api/auth.py — JWT authentication for AuralisAPI remediation-brain
#
# Flow:
#   POST /auth/token  →  validates ADMIN_EMAIL + ADMIN_PASSWORD from env
#                        returns {"access_token": "<jwt>", "token_type": "bearer"}
#   Protect routes:   →  Depends(require_auth)  (mutating endpoints)
#                    →  Depends(require_auth_optional)  (read-only, returns None if no token)
#
# Sensor auth is separate (see routes.py _validate_sensor_token).
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog  # type: ignore[import]
from fastapi import APIRouter, Depends, HTTPException, status  # type: ignore[import]
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer  # type: ignore[import]
from jose import JWTError, jwt  # type: ignore[import]
from pydantic import BaseModel  # type: ignore[import]

log = structlog.get_logger(__name__)

auth_router = APIRouter()

# ── Config from env ────────────────────────────────────────────────────────────

def _get_secret() -> str:
    s = os.getenv("SECRET_KEY", "")
    if not s or s.startswith("changeme"):
        return "auralis-dev-insecure-key-replace-in-production"
    return s

def _admin_email() -> str:
    return os.getenv("ADMIN_EMAIL", "admin@auralisapi.dev")

def _admin_password() -> str:
    return os.getenv("ADMIN_PASSWORD", "auralis2025")

ALGORITHM       = "HS256"
EXPIRE_HOURS    = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

# ── Bearer scheme (auto_error=False so read-only routes can be unauthenticated) ──

_bearer = HTTPBearer(auto_error=False)


# ── Token creation ─────────────────────────────────────────────────────────────

def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=EXPIRE_HOURS)
    payload = {"sub": subject, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, _get_secret(), algorithm=ALGORITHM)


def _decode_token(token: str) -> Optional[str]:
    try:
        data = jwt.decode(token, _get_secret(), algorithms=[ALGORITHM])
        return data.get("sub")
    except JWTError:
        return None


# ── FastAPI dependencies ───────────────────────────────────────────────────────

def require_auth(creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> str:
    """
    Dependency for mutating endpoints — raises 401 if no valid JWT is present.
    Returns the token subject (email) on success.
    """
    if creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    subject = _decode_token(creds.credentials)
    if subject is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return subject


def optional_auth(creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> Optional[str]:
    """
    Dependency for read-only endpoints — returns subject if token valid, None otherwise.
    Allows unauthenticated access for monitoring/status endpoints.
    """
    if creds is None:
        return None
    return _decode_token(creds.credentials)


# ── Login endpoint ─────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = EXPIRE_HOURS * 3600


@auth_router.post("/auth/token", tags=["Auth"], response_model=TokenResponse)
async def login(body: LoginRequest):
    """
    Exchange admin credentials for a JWT access token.
    Credentials are validated against ADMIN_EMAIL + ADMIN_PASSWORD env vars.
    The returned token must be sent as 'Authorization: Bearer <token>' on
    all protected brain endpoints.
    """
    if body.email.strip().lower() != _admin_email().lower() or body.password != _admin_password():
        log.warning("failed login attempt", email=body.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    env = os.getenv("ENVIRONMENT", "development")
    if env == "production" and _get_secret().startswith("auralis-dev-"):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration: SECRET_KEY not set for production",
        )

    token = create_access_token(subject=body.email.strip())
    log.info("login successful", email=body.email)
    return TokenResponse(access_token=token)
