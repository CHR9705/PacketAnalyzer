import time

class BlockedRepo:
    def __init__(self, db_module):
        self.db = db_module
        self.packet_buffer = []
        self.last_packet_flush = time.time()
    
    def create_blocked(self):
        self.db.cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_packets (
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

    def insert_blocked_table(self, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags):
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
                INSERT INTO blocked_packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', self.packet_buffer)
            self.db.conn.commit()
            self.packet_buffer.clear()
            self.cleanup_blocked()
            self.last_packet_flush = time.time()
            # print("100개의 패킷이 DB에 저장되었습니다.")
  

    def cleanup_blocked(self):
        one_hour_ago = int(time.time()) - 3600

        # 1시간이 지난 패킷 삭제
        self.db.cursor.execute("""
            DELETE FROM blocked_packets
            WHERE timestamp < ?
        """, (one_hour_ago,))

        # 5000개 이상 쌓이면 삭제
        self.db.cursor.execute("SELECT COUNT(*) FROM blocked_packets")
        count = self.db.cursor.fetchone()[0]

        if count > 5000:
            self.db.cursor.execute("""
                DELETE FROM blocked_packets
                WHERE id NOT IN (
                    SELECT id
                    FROM blocked_packets
                    ORDER BY id DESC
                    LIMIT 5000
                )
            """)
            self.db.conn.commit()
    
    def flush_blocked(self):
        """
        버퍼에 있는 패킷들을 전부 저장한다.
        """
        if not self.packet_buffer:
            return

        self.db.cursor.executemany("""
            INSERT INTO blocked_packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, self.packet_buffer)

        self.db.conn.commit()
        self.packet_buffer.clear()