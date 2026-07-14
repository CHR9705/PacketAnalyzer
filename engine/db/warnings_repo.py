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
                counter INTEGER,
                            
            
                UNIQUE(src_ip, attack_type)
            );
        ''')
    
    def insert_warning_table(self, timestamp, src_ip, attack_type, counter):
        self.db.cursor.execute('''
            INSERT INTO warnings (first_timestamp, last_timestamp, src_ip, attack_type, counter)
            VALUES (?, ?, ?, ?, ?)
                            
            ON CONFLICT(src_ip, attack_type)
            DO UPDATE SET
            counter = counter + excluded.counter,
            last_timestamp = excluded.last_timestamp
        ''', (timestamp, timestamp, src_ip, attack_type, counter))
        self.db.conn.commit()