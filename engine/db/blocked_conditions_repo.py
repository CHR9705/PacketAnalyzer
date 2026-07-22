class BlockedConditionsRepo:
    def __init__(self, db_module):
        self.db = db_module

    def create_conditions(self):
        self.db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_conditions (
                grade TEXT PRIMARY KEY,
                score FLOAT
            )
        ''')

        self.db.cursor.execute('''
        INSERT OR IGNORE INTO blocked_conditions (grade, score) 
        VALUES ('Medium', 5)
        ''')
        self.db.conn.commit()

    def update_conditions_table(self, score,grade):
        self.db.cursor.execute('''
            update blocked_conditions SET score = ? WHERE grade = ?
        ''', (score,grade))
        self.db.conn.commit()
    
    def get_conditions_table(self):
        self.db.cursor.execute(f"""
            SELECT grade, score
            FROM blocked_conditions
        """)
        return self.db.cursor.fetchone()
            
