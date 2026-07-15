class WarningRepo:
    def __init__(self, db_module):
        self.db = db_module

    def create_warnings(self):
        self.db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_timestamp INTEGER,
                last_timestamp INTEGER,
                src_ip TEXT,
                attack_type TEXT,
                counter INTEGER
            );
        ''')
    
    def insert_warning_table(self, timestamp, src_ip, attack_type, counter):
        current_timestamp = timestamp
        self.db.cursor.execute("""
            UPDATE warnings
            SET
                counter = counter + ?,
                last_timestamp = ?
            WHERE
                src_ip = ?
                AND attack_type = ?
                AND last_timestamp >= ?;
        """, (
            counter,
            current_timestamp,
            src_ip,
            attack_type,
            current_timestamp - 10
        ))

        if self.db.cursor.rowcount == 0:
            self.db.cursor.execute("""
                INSERT INTO warnings (
                    first_timestamp,
                    last_timestamp,
                    src_ip,
                    attack_type,
                    counter
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                current_timestamp,
                current_timestamp,
                src_ip,
                attack_type,
                counter
            ))
        self.db.conn.commit()