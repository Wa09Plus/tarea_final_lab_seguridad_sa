import sqlite3

def bad_search_query(conn: sqlite3.Connection, user_input: str):
    query = f"SELECT id, title FROM tickets WHERE title LIKE '%{user_input}%'"
    # ruleid: internaldesk-sqlite-sqli-fstring
    return conn.execute(query).fetchall()


def good_search_query(conn: sqlite3.Connection, user_input: str):
    query = "SELECT id, title FROM tickets WHERE title LIKE ?"
    # ok: internaldesk-sqlite-sqli-fstring
    return conn.execute(query, (f"%{user_input}%",)).fetchall()
    