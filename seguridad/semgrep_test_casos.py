import sqlite3


def bad_search_query(conn: sqlite3.Connection, user_input: str):
    # ruleid: internaldesk-sqlite-sqli-fstring
    query = f"SELECT id, title FROM tickets WHERE title LIKE '%{user_input}%'"
    return conn.execute(query).fetchall()


def good_search_query(conn: sqlite3.Connection, user_input: str):
    # ok: internaldesk-sqlite-sqli-fstring
    query = "SELECT id, title FROM tickets WHERE title LIKE ?"
    return conn.execute(query, (f"%{user_input}%",)).fetchall()