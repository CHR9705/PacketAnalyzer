import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "packets.db"))
TABLE_NAME = "packets"
IP_COLUMN = "src_ip"


def get_ip_list_from_db(db_path: str = DB_PATH, limit: int | None = None) -> list[str]:
    """DB에서 IP 목록을 조회해 리스트로 반환.

    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        query = f"SELECT {IP_COLUMN} FROM {TABLE_NAME}"
        if limit:
            query += f" LIMIT {limit}"
        cur.execute(query)
        rows = cur.fetchall()
        return [row[0] for row in rows]
    finally:
        conn.close()

def get_warnings_list_from_db(db_path: str = DB_PATH, limit: int | None = None) -> list[str]:
    """warnings 테이블에서 IP 목록을 조회해 리스트로 반환.

    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        query = f"SELECT {IP_COLUMN} FROM warnings"
        if limit:
            query += f" LIMIT {limit}"
        cur.execute(query)
        rows = cur.fetchall()
        return [row[0] for row in rows]
    finally:
        conn.close()

