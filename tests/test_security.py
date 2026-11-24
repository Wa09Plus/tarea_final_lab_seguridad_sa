import pytest
from fastapi.testclient import TestClient

from app_final_sa.main import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Levanta la API contra una base SQLite aislada para cada prueba."""
    db_file = tmp_path / "test_internaldesk.db"
    monkeypatch.setenv("INTERNALDESK_DB", str(db_file))
    with TestClient(app) as test_client:
        yield test_client


def get_auth_header(client: TestClient, username: str, password: str) -> dict:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"Login falló para {username}: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# 1. Acceso legítimo a un recurso propio (Prueba positiva)
def test_legitimate_access_to_own_resource(client: TestClient):
    """Entrada: usuario Sofia accede a su ticket #1. Esperado: HTTP 200 con owner_id=1."""
    headers = get_auth_header(client, "Sofia", "SofiaPass2026?")
    resp = client.get("/tickets/1", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == 1
    assert body["owner_id"] == 1


# 2. Denegación de acceso a un recurso ajeno - BOLA/IDOR (Prueba negativa)
def test_deny_access_to_other_user_resource_bola(client: TestClient):
    """Entrada: usuario Sofia solicita ticket #3 perteneciente a Steve. Esperado: HTTP 403."""
    headers = get_auth_header(client, "Sofia", "SofiaPass2026?")
    resp = client.get("/tickets/3", headers=headers)
    assert resp.status_code == 403, (
        f"BOLA/IDOR detectado: Sofia obtuvo HTTP {resp.status_code} "
        f"al solicitar un recurso de Steve (esperado 403)."
    )


# 3. Solicitud sin autenticación válida
def test_unauthenticated_and_invalid_token_denied(client: TestClient):
    """Entrada: petición sin header Authorization y con token alterado. Esperado: HTTP 401."""
    resp_no_auth = client.get("/tickets")
    assert resp_no_auth.status_code == 401

    resp_bad_token = client.get("/tickets", headers={"Authorization": "Bearer token.falso.invalido"})
    assert resp_bad_token.status_code == 401


# 4. Validación de entrada inesperada
def test_unexpected_input_rejected(client: TestClient):
    """Entrada: payload con prioridad fuera del catálogo y campos demasiado cortos. Esperado: HTTP 422."""
    headers = get_auth_header(client, "Sofia", "SofiaPass2026?")
    invalid_payload = {
        "title": "a",
        "description": "b",
        "priority": "critical_invalid_value",
    }
    resp = client.post("/tickets", json=invalid_payload, headers=headers)
    assert resp.status_code == 422


# 5. Restricción de operación según rol
def test_role_restriction_on_admin_endpoint(client: TestClient):
    """Entrada: Sofia (user) vs admin (admin) en /admin/audit-summary. Esperado: 403 y 200."""
    sofia_headers = get_auth_header(client, "Sofia", "SofiaPass2026?")
    resp_user = client.get("/admin/audit-summary", headers=sofia_headers)
    assert resp_user.status_code == 403

    admin_headers = get_auth_header(client, "admin", "AdminPass2026?")
    resp_admin = client.get("/admin/audit-summary", headers=admin_headers)
    assert resp_admin.status_code == 200
    assert resp_admin.json()["total_users"] == 3


# 6. Búsqueda legítima funcional (Prueba positiva para regresión de SQLi)
def test_search_legitimate_query(client: TestClient):
    """Entrada: Sofia busca 'VPN'. Esperado: HTTP 200 solo con su ticket coincidente."""
    headers = get_auth_header(client, "Sofia", "SofiaPass2026?")
    resp = client.get("/tickets/search", params={"q": "VPN"}, headers=headers)
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["owner_id"] == 1
    assert "VPN" in results[0]["title"]


# 7. Intento de SQL Injection en búsqueda (Prueba negativa)
def test_search_sqli_payload_blocked(client: TestClient):
    """Entrada: Sofia envía payload SQLi `' OR 1=1 --`. Esperado: HTTP 200 sin exponer datos ajenos."""
    headers = get_auth_header(client, "Sofia", "SofiaPass2026?")
    resp = client.get("/tickets/search", params={"q": "' OR 1=1 --"}, headers=headers)
    assert resp.status_code == 200
    results = resp.json()
    assert all(ticket["owner_id"] == 1 for ticket in results), (
        f"SQL Injection detectado: se devolvieron registros de otros usuarios: {results}"
    )
    assert len(results) == 0