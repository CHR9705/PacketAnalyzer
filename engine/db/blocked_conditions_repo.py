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
        self.db.conn.commit()

    def insert_conditions_table(self, grade, score):
        self.db.cursor.execute('''
            INSERT INTO blocked_conditions (grade, score)
            VALUES (?, ?)
            ON CONFLICT(grade) DO UPDATE SET score = excluded.score
        ''', (grade, score))
        self.db.conn.commit()