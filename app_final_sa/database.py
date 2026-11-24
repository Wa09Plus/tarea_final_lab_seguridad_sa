import hashlib
import os
import sqlite3

DEFAULT_DB_PATH = "internaldesk.db"


def get_db_path() -> str:
    return os.getenv("INTERNALDESK_DB", DEFAULT_DB_PATH)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()


def init_db() -> None:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
            """
        )

        # Poblar datos ficticios de laboratorio si la tabla está vacía
        existing = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing == 0:
            seed_users = [
                ("Sofia", "SofiaPass2026?", "salt-sofia-01", "user"),
                ("Steve", "StevePass2026?", "salt-steve-02", "user"),
                ("admin", "AdminPass2026?", "salt-admin-03", "admin"),
            ]
            for username, pwd, salt, role in seed_users:
                cur.execute(
                    "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
                    (username, hash_password(pwd, salt), salt, role),
                )

            seed_tickets = [
                (1, "Falla en VPN corporativa", "Error al conectar desde red externa", "high", "open"),
                (1, "Solicitud de monitor", "Reemplazo de pantalla en puesto 4B", "low", "open"),
                (2, "Confidencial: ajuste salarial Q4", "Expediente interno #9941 solo para RRHH/Steve", "high", "open"),
            ]
            cur.executemany(
                "INSERT INTO tickets (owner_id, title, description, priority, status) VALUES (?, ?, ?, ?, ?)",
                seed_tickets,
            )

        conn.commit()
    finally:
        conn.close()