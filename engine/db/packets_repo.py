import time

class PacketRepo:
    def __init__(self, db_module):
        self.db = db_module
        self.packet_buffer = []
        self.last_packet_flush = time.time()

    def create_packets(self):
        self.db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                payload_size INTEGER,
                tcp_flags TEXT
            );
        ''')

        self.db.cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_timestamp
        ON packets(timestamp)
        """)

        self.db.cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_src_ip
        ON packets(src_ip)
        """)

    def insert_packet_table(self, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags):
        '''
        패킷 정보를 쌓아두었다가 100개 혹은 1초마다 한번에 DB에 저장
        '''
        # print("DB모듈 들어옴")
        self.packet_buffer.append(
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
        )

        now = time.time()
        if (len(self.packet_buffer) >= 100 or now - self.last_packet_flush >= 1):  # 버퍼가 100개 이상이거나 마지막 커밋으로부터 1초 이상 지났다면 한 번에 커밋
            self.db.cursor.executemany('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', self.packet_buffer)
            self.db.conn.commit()
            self.packet_buffer.clear()
            self.cleanup_packets()
            self.last_packet_flush = time.time()
            # print("100개의 패킷이 DB에 저장되었습니다.")
  

    def cleanup_packets(self):
        self.db.cursor.execute("SELECT COUNT(*) FROM packets")
        count = self.db.cursor.fetchone()[0]

        if count > 5000:
            self.db.cursor.execute("""
                DELETE FROM packets
                WHERE id NOT IN (
                    SELECT id
                    FROM packets
                    ORDER BY id DESC
                    LIMIT 5000
                )
            """)
            self.db.conn.commit()
    
    def flush(self):
        """
        버퍼에 있는 패킷들을 전부 저장한다.
        """
        if not self.packet_buffer:
            return

        self.db.cursor.executemany("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, self.packet_buffer)

        self.db.conn.commit()
        self.packet_buffer.clear()
