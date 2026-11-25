import logging
import uuid
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from app_final_sa.auth import authenticate_user, create_access_token, get_current_user, require_admin
from app_final_sa.database import get_connection, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("internaldesk.trace")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="InternalDesk API",
    version="1.0.0-lab",
    description="API interna de gestión de tickets para tarea final de Seguridad en Aplicaciones",
    lifespan=lifespan,
)


@app.middleware("http")
async def trace_requests(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    request.state.request_id = request_id
    logger.info("[TRACE][%s] HTTP_IN -> %s %s", request_id, request.method, request.url.path)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    logger.info("[TRACE][%s] HTTP_OUT -> status=%s", request_id, response.status_code)
    return response


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=50)
    password: str = Field(..., min_length=4, max_length=100)


class TicketCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=3, max_length=500)
    priority: Literal["low", "medium", "high"] = "medium"


@app.get("/health")
def health_check():
    return {"status": "ok", "version": app.version}


@app.post("/auth/login")
def login(payload: LoginRequest, request: Request):
    req_id = request.state.request_id
    user = authenticate_user(payload.username, payload.password)
    if not user:
        logger.warning("[TRACE][%s] LOGIN -> FAILED (username=%s)", req_id, payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )
    token = create_access_token(user)
    logger.info("[TRACE][%s] LOGIN -> OK (username=%s, role=%s)", req_id, user["username"], user["role"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user,
    }


@app.get("/tickets")
def list_own_tickets(request: Request, current_user: dict = Depends(get_current_user)):
    req_id = request.state.request_id
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, owner_id, title, description, priority, status FROM tickets WHERE owner_id = ?",
            (current_user["id"],),
        ).fetchall()
        logger.info("[TRACE][%s] DB_QUERY -> list_own_tickets count=%d", req_id, len(rows))
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.post("/tickets", status_code=status.HTTP_201_CREATED)
def create_ticket(
    payload: TicketCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    req_id = request.state.request_id
    conn = get_connection()
    try:
        cur = conn.execute(
            "INSERT INTO tickets (owner_id, title, description, priority, status) VALUES (?, ?, ?, ?, 'open')",
            (current_user["id"], payload.title, payload.description, payload.priority),
        )
        conn.commit()
        ticket_id = cur.lastrowid
        logger.info("[TRACE][%s] DB_INSERT -> ticket_id=%s owner_id=%s", req_id, ticket_id, current_user["id"])
        return {
            "id": ticket_id,
            "owner_id": current_user["id"],
            "title": payload.title,
            "description": payload.description,
            "priority": payload.priority,
            "status": "open",
        }
    finally:
        conn.close()


@app.get("/tickets/search")
def search_tickets(
    request: Request,
    q: str = Query(..., min_length=1),
    current_user: dict = Depends(get_current_user),
):
    """Busca tickets propios del usuario autenticado usando consulta SQL parametrizada."""
    req_id = request.state.request_id
    escaped_q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    conn = get_connection()
    try:
        query = (
            "SELECT id, owner_id, title, description, priority, status "
            "FROM tickets WHERE owner_id = ? AND title LIKE ? ESCAPE '\\'"
        )
        rows = conn.execute(query, (current_user["id"], f"%{escaped_q}%")).fetchall()
        logger.info("[TRACE][%s] DB_QUERY -> search_tickets count=%d", req_id, len(rows))
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/tickets/{ticket_id}")
def get_ticket_by_id(
    ticket_id: int,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Obtiene un ticket por ID verificando que pertenezca al usuario autenticado (prevención BOLA/IDOR)."""
    req_id = request.state.request_id
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, owner_id, title, description, priority, status FROM tickets WHERE id = ?",
            (ticket_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket no encontrado")
        if row["owner_id"] != current_user["id"]:
            logger.warning(
                "[TRACE][%s] AUTHZ_BOLA -> DENY (user_id=%s attempted ticket_id=%s owned by owner_id=%s)",
                req_id,
                current_user["id"],
                ticket_id,
                row["owner_id"],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permiso para acceder a este ticket",
            )
        logger.info(
            "[TRACE][%s] RESOURCE_ACCESS -> user_id=%s accessed ticket_id=%s (owner_id=%s)",
            req_id,
            current_user["id"],
            ticket_id,
            row["owner_id"],
        )
        return dict(row)
    finally:
        conn.close()


@app.get("/admin/audit-summary")
def admin_audit_summary(
    request: Request,
    current_user: dict = Depends(require_admin),
):
    req_id = request.state.request_id
    conn = get_connection()
    try:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_tickets = conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0]
        logger.info("[TRACE][%s] ADMIN_SUMMARY -> served to %s", req_id, current_user["username"])
        return {
            "requested_by": current_user["username"],
            "total_users": total_users,
            "total_tickets": total_tickets,
        }
    finally:
        conn.close()