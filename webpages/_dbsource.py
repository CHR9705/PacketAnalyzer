import sqlite3
import os
from typing import Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "packets.db"))


class dbsource:
    def __init__(self):
        self.db_path = DB_PATH

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def fetch(
        self,
        table: str,
        columns: str | list[str] = "*",
        where: str | None = None,
        params: tuple = (),
        limit: int | None = None,
    ) -> list[dict]:
        

        if isinstance(columns, list):
            columns = ", ".join(columns)

        query = f"SELECT {columns} FROM {table}"

        if where:
            query += f" WHERE {where}"

        if limit is not None:
            query += " LIMIT ?"
            params += (limit,)

        conn = self._connect()

        try:
            cur = conn.cursor()
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def column(
        self,
        table: str,
        column: str,
        where: str | None = None,
        params: tuple = (),
        limit: int | None = None,
    ) -> list[Any]:
        """
        Return a single column as a list.

        Example:
            db.column("packets", "src_ip")
        """

        rows = self.fetch(
            table=table,
            columns=column,
            where=where,
            params=params,
            limit=limit,
        )

        return [row[column] for row in rows]

    def row(
        self,
        table: str,
        where: str,
        params: tuple = (),
    ) -> dict | None:
        """
        Return a single row.
        """

        rows = self.fetch(
            table=table,
            where=where,
            params=params,
            limit=1,
        )

        return rows[0] if rows else None

    def execute(
        self,
        query: str,
        params: tuple = (),
    ) -> None:
        """
        Execute INSERT, UPDATE, DELETE, CREATE...
        """

        conn = self._connect()

        try:
            cur = conn.cursor()
            cur.execute(query, params)
            conn.commit()
        finally:
            conn.close()
   
   