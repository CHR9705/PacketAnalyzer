import time

class BlackWhiteRepo:
    def __init__(self, db_module):
        self.db = db_module
    
    def create_blackNwhites(self):
       self.db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS black_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                ip TEXT,
                accepted INTEGER DEFAULT 0
            );
        ''') 
       
       self.db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS white_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                ip TEXT,
                accepted INTEGER DEFAULT 0
            );
        ''') 
    
    def insert_white_list(self, ip:str, accepted:bool = False):
        self.db.cursor.execute('''
            INSERT INTO white_list (timestamp, ip, accepted)
            VALUES (?, ?, ?)
        ''', (time.time(), ip, 1 if accepted == True else 0))

    def insert_black_list(self, ip:str, accepted:bool = False):
        self.db.cursor.execute('''
            INSERT INTO black_list (timestamp, ip, accepted)
            VALUES (?, ?, ?)
        ''', (time.time(), ip, 1 if accepted == True else 0))
    
    def get_pending_rules(self, table: str):
        self.db.cursor.execute(f"""
            SELECT id, ip
            FROM {table}
            WHERE accepted = 0
        """)
        return self.db.cursor.fetchall()


    def get_delete_rules(self, table: str):
        self.db.cursor.execute(f"""
            SELECT id, ip
            FROM {table}
            WHERE accepted = 2
        """)
        return self.db.cursor.fetchall()


    def accept_rule(self, table: str, rule_id: int):
        self.db.cursor.execute(f"""
            UPDATE {table}
            SET accepted = 1
            WHERE id = ?
        """, (rule_id,))
        self.db.conn.commit()


    def delete_rule(self, table: str, rule_id: int):
        self.db.cursor.execute(f"""
            DELETE FROM {table}
            WHERE id = ?
        """, (rule_id,))
        self.db.conn.commit()
    