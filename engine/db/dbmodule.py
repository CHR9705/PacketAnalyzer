import sqlite3
import time

class DBModule:
    def __init__(self):
        self.conn = sqlite3.connect("packets.db")
        self.cursor = self.conn.cursor()
        self.create_table()
        self.packet_buffer = []
        self.last_packet_flush = time.time()

    def create_table(self):
        # 들어오는 패킷 전부 저장하는 테이블
        self.create_packets()

        # Flow 끝날 때마다 저장하는 테이블
        self.create_flows()

        # 경고 메시지만 저장하는 테이블
        self.create_warnings()

        # 블랙리스트, 화이트리스트 테이블
        self.create_blackNwhites()

        self.conn.commit()

    def create_packets(self):
        self.cursor.execute('''
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

        self.cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_timestamp
        ON packets(timestamp)
        """)
        self.cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_packets_src_ip
        ON packets(src_ip)
        """)

    def create_flows(self):
        self.cursor.execute('''
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
        self.cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_flows_id
        ON flows(id)
        """)

    def create_warnings(self):
        self.cursor.execute('''
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

    def create_blackNwhites(self):
       self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS black_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                ip TEXT,
                accepted INTEGER DEFAULT 0
            );
        ''') 
       
       self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS white_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                ip TEXT,
                accepted INTEGER DEFAULT 0
            );
        ''') 

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
            self.cursor.executemany('''
                INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', self.packet_buffer)
            self.conn.commit()
            self.packet_buffer.clear()
            self.cleanup_packets()
            self.last_packet_flush = time.time()
            # print("100개의 패킷이 DB에 저장되었습니다.")
  

    def cleanup_packets(self):
        self.cursor.execute("SELECT COUNT(*) FROM packets")
        count = self.cursor.fetchone()[0]

        if count > 1500:
            self.cursor.execute("""
                DELETE FROM packets
                WHERE id NOT IN (
                    SELECT id
                    FROM packets
                    ORDER BY id DESC
                    LIMIT 1500
                )
            """)
            self.conn.commit()


    def insert_warning_table(self, timestamp, src_ip, attack_type, counter):
        self.cursor.execute('''
            INSERT INTO warnings (first_timestamp, last_timestamp, src_ip, attack_type, counter)
            VALUES (?, ?, ?, ?, ?)
                            
            ON CONFLICT(src_ip, attack_type)
            DO UPDATE SET
            counter = counter + excluded.counter,
            last_timestamp = excluded.last_timestamp
        ''', (timestamp, timestamp, src_ip, attack_type, counter))
        self.conn.commit()

    def insert_flow_table(self,start_time, last_seen, endpoint1_ip, endpoint2_ip, packet_count, byte_count,
                          protocol, syn_count, ack_count, fin_count, rst_count  ):
        self.cursor.execute('''
            INSERT INTO flows (start_time, last_seen, endpoint1_ip, endpoint2_ip, packet_count, byte_count,
                          protocol, syn_count, ack_count, fin_count, rst_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (start_time, last_seen, endpoint1_ip, endpoint2_ip, packet_count, byte_count,
                          protocol, syn_count, ack_count, fin_count, rst_count))
        self.conn.commit()

    def insert_white_list(self, ip):
        self.cursor.execute('''
            INSERT INTO white_list (timestamp, ip)
            VALUES (?, ?)
        ''', (time.time(), ip))

    def insert_black_list(self, ip):
        self.cursor.execute('''
            INSERT INTO black_list (timestamp, ip)
            VALUES (?, ?)
        ''', (time.time(), ip))

    

    def flush(self):
        """
        버퍼에 있는 패킷들을 전부 저장한다.
        """
        if not self.packet_buffer:
            return

        self.cursor.executemany("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size, payload_size, tcp_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, self.packet_buffer)

        self.conn.commit()
        self.packet_buffer.clear()


    def close(self):
        self.flush()
        self.conn.close()