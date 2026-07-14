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
    
    def get_notaccepted_blacklist(self):
        self.db.cursor.execute('''
            SELECT * FROM black_list
            where accepted = ?;
        ''', (0,))
        return self.db.cursor.fetchall()
    
    def get_notaccepted_whitelist(self):
        self.db.cursor.execute('''
            SELECT * FROM white_list
            where accepted = ?;
        ''', (0,))
        return self.db.cursor.fetchall()
    