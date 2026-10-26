"""
Database Module for DNS Query and Analysis Tool
Manages SQLite database connections, schema creation, parameterized queries,
query history recording, filtering, pagination, and statistical aggregations.
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional

DB_FILE = os.path.join(os.path.dirname(__file__), "instance", "dns_analysis.db")


def get_db_connection() -> sqlite3.Connection:
    """Creates and returns a connection to the SQLite database with Row factory."""
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Initializes the database schema and indexes if they do not exist."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    answers TEXT,
                    mx_priority TEXT,
                    response_time_ms REAL NOT NULL,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    resolver TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_domain ON queries(domain)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_status ON queries(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_created ON queries(created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queries_batch ON queries(batch_id)")

            # Seed initial telemetry data if table is completely fresh
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM queries")
            if cur.fetchone()[0] == 0:
                sample_queries = [
                    ("seed001", "google.com", "A", "142.250.190.46, 142.250.190.78", None, 28.45, "SUCCESS", None, "Google DNS (8.8.8.8)"),
                    ("seed001", "google.com", "AAAA", "2607:f8b0:4005:805::200e", None, 31.12, "SUCCESS", None, "Google DNS (8.8.8.8)"),
                    ("seed001", "google.com", "MX", "smtp.google.com", "10", 35.80, "SUCCESS", None, "Google DNS (8.8.8.8)"),
                    ("seed002", "cloudflare.com", "A", "104.16.132.229, 104.16.133.229", None, 18.90, "SUCCESS", None, "Cloudflare (1.1.1.1)"),
                    ("seed002", "github.com", "A", "140.82.121.4", None, 45.20, "SUCCESS", None, "Cloudflare (1.1.1.1)"),
                    ("seed003", "example-nxdomain-test.xyz", "A", "", None, 52.10, "NXDOMAIN", "Non-Existent Domain (NXDOMAIN)", "Quad9 (9.9.9.9)")
                ]
                cur.executemany("""
                    INSERT INTO queries (batch_id, domain, record_type, answers, mx_priority, response_time_ms, status, error_message, resolver)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, sample_queries)
    finally:
        conn.close()


def save_query_result(
    batch_id: str,
    domain: str,
    record_type: str,
    answers: str,
    mx_priority: Optional[str],
    response_time_ms: float,
    status: str,
    error_message: Optional[str] = None,
    resolver: str = "System Default"
) -> int:
    """
    Saves a single DNS query execution result safely into SQLite.
    Returns the newly inserted record ID.
    """
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO queries (
                    batch_id, domain, record_type, answers, mx_priority,
                    response_time_ms, status, error_message, resolver, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
            """, (
                batch_id,
                domain.strip().lower(),
                record_type.upper(),
                answers if answers else "",
                mx_priority if mx_priority else "",
                round(float(response_time_ms), 2),
                status,
                error_message if error_message else "",
                resolver
            ))
            return cursor.lastrowid
    finally:
        conn.close()


def save_batch_results(results: List[Dict[str, Any]], batch_id: str) -> None:
    """Saves multiple query results efficiently in a single transaction."""
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            for r in results:
                cursor.execute("""
                    INSERT INTO queries (
                        batch_id, domain, record_type, answers, mx_priority,
                        response_time_ms, status, error_message, resolver, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))
                """, (
                    batch_id,
                    r.get("domain", "").strip().lower(),
                    r.get("record_type", "").upper(),
                    r.get("answers_text", "") or ", ".join(r.get("answers", [])) if isinstance(r.get("answers"), list) else str(r.get("answers", "")),
                    r.get("mx_priority", "") or "",
                    round(float(r.get("response_time_ms", 0.0)), 2),
                    r.get("status", "UNKNOWN"),
                    r.get("error_message", "") or "",
                    r.get("resolver", "System Default")
                ))
    finally:
        conn.close()


def get_query_by_id(query_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves full details for a single DNS query by ID."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM queries WHERE id = ?", (query_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_queries_by_batch(batch_id: str) -> List[Dict[str, Any]]:
    """Retrieves all query results associated with a given batch identifier."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM queries WHERE batch_id = ? ORDER BY id ASC", (batch_id,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_filtered_history(
    search: str = "",
    record_type: str = "",
    status: str = "",
    sort_by: str = "date_desc",
    page: int = 1,
    per_page: int = 15
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Searches, filters, sorts, and paginates query history.
    Returns: (list_of_records, total_count, total_pages)
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        conditions = []
        params = []

        if search and search.strip():
            conditions.append("(domain LIKE ? OR answers LIKE ?)")
            search_param = f"%{search.strip().lower()}%"
            params.extend([search_param, search_param])

        if record_type and record_type.strip() and record_type.upper() != "ALL":
            conditions.append("record_type = ?")
            params.append(record_type.strip().upper())

        if status and status.strip() and status.upper() != "ALL":
            conditions.append("status = ?")
            params.append(status.strip().upper())

        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        # Count total matching rows
        count_query = f"SELECT COUNT(*) FROM queries {where_clause}"
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()[0]

        # Sorting logic
        sort_mappings = {
            "date_desc": "created_at DESC, id DESC",
            "date_asc": "created_at ASC, id ASC",
            "time_asc": "response_time_ms ASC",
            "time_desc": "response_time_ms DESC",
            "domain_asc": "domain ASC",
            "domain_desc": "domain DESC"
        }
        order_by = sort_mappings.get(sort_by, "created_at DESC, id DESC")

        total_pages = max(1, (total_count + per_page - 1) // per_page)
        page = max(1, min(page, total_pages))
        offset = (page - 1) * per_page

        data_query = f"""
            SELECT * FROM queries
            {where_clause}
            ORDER BY {order_by}
            LIMIT ? OFFSET ?
        """
        query_params = list(params) + [per_page, offset]
        cursor.execute(data_query, query_params)
        records = [dict(row) for row in cursor.fetchall()]

        return records, total_count, total_pages
    finally:
        conn.close()


def get_dashboard_statistics() -> Dict[str, Any]:
    """
    Computes real summary metrics and recent history for the main Dashboard.
    All data is computed directly from SQLite.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # Total, Success, Failed counts
        cursor.execute("SELECT COUNT(*) FROM queries")
        total_queries = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM queries WHERE status = 'SUCCESS'")
        successful_queries = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM queries WHERE status != 'SUCCESS'")
        failed_queries = cursor.fetchone()[0]

        # Average response time for successful queries
        cursor.execute("SELECT AVG(response_time_ms) FROM queries WHERE status = 'SUCCESS'")
        avg_time_row = cursor.fetchone()[0]
        avg_response_time = round(float(avg_time_row), 2) if avg_time_row is not None else 0.0

        # Record type distribution
        cursor.execute("""
            SELECT record_type, COUNT(*) as count
            FROM queries
            GROUP BY record_type
            ORDER BY count DESC
        """)
        type_distribution = {row["record_type"]: row["count"] for row in cursor.fetchall()}

        # Recent 8 queries for dashboard table
        cursor.execute("""
            SELECT * FROM queries
            ORDER BY created_at DESC, id DESC
            LIMIT 8
        """)
        recent_queries = [dict(row) for row in cursor.fetchall()]

        return {
            "total_queries": total_queries,
            "successful_queries": successful_queries,
            "failed_queries": failed_queries,
            "avg_response_time": avg_response_time,
            "type_distribution": type_distribution,
            "recent_queries": recent_queries
        }
    finally:
        conn.close()


def get_all_records_for_export() -> List[Dict[str, Any]]:
    """Fetches all query records ordered by timestamp descending for CSV/JSON export."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM queries ORDER BY id DESC")
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def get_recent_queries_for_graph(limit: int = 25) -> List[Dict[str, Any]]:
    """Fetches recent queries chronologically for graph plotting."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT domain, record_type, response_time_ms, status, created_at
            FROM queries
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        # Reverse to show in chronological order on graphs
        rows = cursor.fetchall()
        return [dict(r) for r in reversed(rows)]
    finally:
        conn.close()


def clear_all_history() -> int:
    """Safely clears all query history from the database. Returns deleted count."""
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM queries")
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM queries")
            conn.execute("VACUUM")
            return count
    finally:
        conn.close()
