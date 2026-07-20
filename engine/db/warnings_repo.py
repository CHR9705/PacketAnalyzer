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
                counter INTEGER DEFAULT 0,
                score REAL DEFAULT 0.0
            );
        ''')
    
    def insert_warning_table(self, timestamp, src_ip, attack_type, counter, score=0):
        current_timestamp = timestamp
        self.db.cursor.execute("""
            UPDATE warnings
            SET
                counter = counter + ?,
                last_timestamp = ?,
                score = ?
            WHERE
                src_ip = ?
                AND attack_type = ?
                AND last_timestamp >= ?;
        """, (
            counter,
            current_timestamp,
            score,
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
                    counter,
                    score
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                current_timestamp,
                current_timestamp,
                src_ip,
                attack_type,
                counter,
                score
            ))
        self.db.conn.commit()