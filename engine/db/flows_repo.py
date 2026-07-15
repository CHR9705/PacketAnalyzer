class FlowRepo:
    def __init__(self, db_module):
        self.db = db_module
    
    def create_flows(self):
        self.db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                start_time INTEGER,
                last_seen INTEGER,
                endpoint1_ip TEXT,
                endpoint2_ip TEXT,
                packet_count INTEGER,
                byte_count INTEGER,
                protocol TEXT,
                syn_count INTEGER,
                ack_count INTEGER,
                fin_count INTEGER,
                rst_count INTEGER
            );
        ''')
        self.db.cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_flows_id
        ON flows(id)
        """)

    def insert_flow_table(self,start_time, last_seen, endpoint1_ip, endpoint2_ip, packet_count, byte_count,
                          protocol, syn_count, ack_count, fin_count, rst_count  ):
        self.db.cursor.execute('''
            INSERT INTO flows (start_time, last_seen, endpoint1_ip, endpoint2_ip, packet_count, byte_count,
                          protocol, syn_count, ack_count, fin_count, rst_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (start_time, last_seen, endpoint1_ip, endpoint2_ip, packet_count, byte_count,
                          protocol, syn_count, ack_count, fin_count, rst_count))
        self.db.conn.commit()