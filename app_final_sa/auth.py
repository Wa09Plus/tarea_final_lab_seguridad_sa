import hmac
import logging
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app_final_sa.database import get_connection, hash_password

logger = logging.getLogger("internaldesk.trace")

JWT_SECRET = os.getenv("JWT_SECRET", "local-lab-jwt-key-32-chars-minimum!")
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

bearer_scheme = HTTPBearer(auto_error=False)


def authenticate_user(username: str, password: str) -> dict | None:
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, username, password_hash, salt, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not row:
            return None
        candidate_hash = hash_password(password, row["salt"])
        if not hmac.compare_digest(candidate_hash, row["password_hash"]):
            return None
        return {"id": row["id"], "username": row["username"], "role": row["role"]}
    finally:
        conn.close()


def create_access_token(user: dict) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    req_id = getattr(request.state, "request_id", "no-id")
    if credentials is None or credentials.scheme.lower() != "bearer":
        logger.warning("[TRACE][%s] AUTH_JWT -> DENY (missing or invalid scheme)", req_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticación requerida",
        )
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user = {
            "id": int(payload["sub"]),
            "username": payload["username"],
            "role": payload["role"],
        }
        logger.info(
            "[TRACE][%s] AUTH_JWT -> OK (user=%s, id=%s, role=%s)",
            req_id,
            user["username"],
            user["id"],
            user["role"],
        )
        return user
    except jwt.PyJWTError:
        logger.warning("[TRACE][%s] AUTH_JWT -> DENY (invalid or expired token)", req_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
        )


def require_admin(
    request: Request,
    current_user: dict = Depends(get_current_user),
) -> dict:
    req_id = getattr(request.state, "request_id", "no-id")
    if current_user["role"] != "admin":
        logger.warning(
            "[TRACE][%s] AUTHZ_ROLE -> DENY (user=%s, role=%s, required=admin)",
            req_id,
            current_user["username"],
            current_user["role"],
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operación restringida a administradores",
        )
    logger.info("[TRACE][%s] AUTHZ_ROLE -> ALLOW (admin=%s)", req_id, current_user["username"])
    return current_user