import sqlite3
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from . import config


class DBWatcher:
    def __init__(self, on_new_rows_callback):  
        self.on_new_rows_callback = on_new_rows_callback
        self.last_seen_key = self._get_max_existing_key()
        self.observer = None
        self.column_names = self._get_column_names() 

    def _get_column_names(self):  # 
            """Fetch all real column names (rowid is implicit, so we add it manually)."""
            conn = sqlite3.connect(config.DB_PATH)
            cur = conn.cursor()
            cur.execute(f"PRAGMA table_info({config.TABLE_NAME})")
            cols = [row[1] for row in cur.fetchall()]
            conn.close()
            return cols

    def _get_max_existing_key(self):
        conn = sqlite3.connect(config.DB_PATH)
        cur = conn.cursor()
        cur.execute(f"SELECT MAX({config.KEY_COLUMN}) FROM {config.TABLE_NAME}")
        result = cur.fetchone()[0]
        conn.close()
        return result if result is not None else 0

    def _get_new_rows(self):  # 🔶 renamed: _get_new_keys → _get_new_rows
        conn = sqlite3.connect(config.DB_PATH)
        cur = conn.cursor()
        select_cols = f"{config.KEY_COLUMN}, *"   # 🟢 NEW — was: f"{KEY_COLUMN}, {DISPLAY_COLUMN}"
        cur.execute(
            f"SELECT {select_cols} FROM {config.TABLE_NAME} "
            f"WHERE {config.KEY_COLUMN} > ? ORDER BY {config.KEY_COLUMN} ASC",
            (self.last_seen_key,)
        )
        rows = cur.fetchall()
        conn.close()
        results = []
        for row in rows:
            row_dict = {"rowid": row[0]}
            for col_name, value in zip(self.column_names, row[1:]):
                row_dict[col_name] = value
            results.append(row_dict)
        return results 

    def check_for_updates(self):
        new_rows = self._get_new_rows()         
        if new_rows:
            self.last_seen_key = new_rows[-1]["rowid"]   
            self.on_new_rows_callback(new_rows)

    def start(self):
        print(f"Starting from key: {self.last_seen_key}")
        handler = _FileChangeHandler(self.check_for_updates)
        watch_dir = os.path.dirname(os.path.abspath(config.DB_PATH)) or "."
        self.observer = Observer()
        self.observer.schedule(handler, path=watch_dir, recursive=False)
        self.observer.start()
        print("Watching database for new records...")


class _FileChangeHandler(FileSystemEventHandler):
    def __init__(self, on_change_callback):
        self.on_change_callback = on_change_callback

    def on_modified(self, event):
        db_name = os.path.basename(config.DB_PATH)
        if event.src_path.endswith(db_name) or event.src_path.endswith(db_name + "-wal"):
            self.on_change_callback()