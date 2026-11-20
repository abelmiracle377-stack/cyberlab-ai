"""Read-only SQLite forensic inspection (browser history, cookies, logins, …).

Opens a SQLite database strictly read-only and immutable, so the evidence file
is never modified or locked-written. Lists tables with their columns and row
counts, and samples a chosen table with a bounded number of rows. Table names
are validated against the database's own catalogue (no string interpolation of
untrusted names into SQL beyond a verified identifier). Uses only the Python
standard library (sqlite3).
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_SAMPLE_ROWS = 200
MAX_CELL = 512


def _open_readonly(path: Path) -> sqlite3.Connection:
    uri = "file:" + str(path) + "?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True, timeout=5)


def _validate_file(path: str) -> Path:
    resolved = Path(path).expanduser()
    if resolved.is_symlink():
        raise ValueError("Database path must not be a symlink.")
    if not resolved.is_file():
        raise ValueError("SQLite database not found: " + str(resolved))
    size = resolved.stat().st_size
    if size == 0:
        raise ValueError("Database file is empty.")
    if size > MAX_FILE_BYTES:
        raise ValueError("Database exceeds the 4 GiB limit.")
    with resolved.open("rb") as handle:
        if handle.read(16) != b"SQLite format 3\x00":
            raise ValueError("Not a SQLite 3 database (missing the SQLite header).")
    return resolved


def _cell(value):
    if isinstance(value, bytes):
        return {"_type": "blob", "length": len(value), "hex_prefix": value[:24].hex()}
    if isinstance(value, str) and len(value) > MAX_CELL:
        return value[:MAX_CELL] + "…"
    return value


def inspect_sqlite(path: str) -> dict:
    """List the user tables with their columns and row counts (read-only)."""
    resolved = _validate_file(path)
    connection = _open_readonly(resolved)
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' "
                       "AND name NOT LIKE 'sqlite_%' ORDER BY name")
        tables = []
        for (name,) in cursor.fetchall():
            columns = [row[1] for row in cursor.execute('PRAGMA table_info("%s")'
                                                        % name.replace('"', '""')).fetchall()]
            try:
                row_count = cursor.execute('SELECT COUNT(*) FROM "%s"'
                                           % name.replace('"', '""')).fetchone()[0]
            except sqlite3.DatabaseError:
                row_count = None
            tables.append({"name": name, "columns": columns[:100], "row_count": row_count})
        return {"file": str(resolved), "table_count": len(tables), "tables": tables,
                "note": "Opened read-only and immutable; the database was not modified."}
    finally:
        connection.close()


def sample_table(path: str, table: str, limit: int = 50) -> dict:
    """Return up to `limit` rows from one table (validated against the catalogue)."""
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_SAMPLE_ROWS:
        raise ValueError("limit must be between 1 and %d." % MAX_SAMPLE_ROWS)
    resolved = _validate_file(path)
    connection = _open_readonly(resolved)
    try:
        cursor = connection.cursor()
        known = {row[0] for row in cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if table not in known:
            raise ValueError("No such table in this database: " + str(table))
        # `table` is now a verified identifier from the DB's own catalogue.
        safe = table.replace('"', '""')
        columns = [row[1] for row in cursor.execute('PRAGMA table_info("%s")' % safe).fetchall()]
        rows = cursor.execute('SELECT * FROM "%s" LIMIT ?' % safe, (limit,)).fetchall()
        preview = [[_cell(cell) for cell in row] for row in rows]
        return {"file": str(resolved), "table": table, "columns": columns,
                "row_count": len(preview), "rows": preview,
                "note": "Opened read-only and immutable; up to %d rows shown." % limit}
    finally:
        connection.close()
