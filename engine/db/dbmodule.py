import sqlite3

from .packets_repo import PacketRepo
from .flows_repo import FlowRepo
from .warnings_repo import WarningRepo
from .black_white_list_repo import BlackWhiteRepo
from .blocked_packets_repo import BlockedRepo
from .blocked_conditions_repo import BlockedConditionsRepo

class DBModule:
    def __init__(self):
        self.conn = sqlite3.connect("packets.db")
        self.cursor = self.conn.cursor()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.packet = PacketRepo(self)
        self.flow = FlowRepo(self)
        self.warnig_repo = WarningRepo(self)
        self.black_white_repo = BlackWhiteRepo(self)
        self.blocked_packets_repo = BlockedRepo(self)
        self.blocked_conditions_repo = BlockedConditionsRepo(self)

        self.create_table()

    def __getattr__(self, name):
        for repo in (self.packet, self.flow, self.warnig_repo, self.black_white_repo, self.blocked_packets_repo, self.blocked_conditions_repo):
            if hasattr(repo, name):
                return getattr(repo, name)
        raise AttributeError(name)

    def create_table(self):
        # 들어오는 패킷 전부 저장하는 테이블
        self.packet.create_packets()

        # Flow 끝날 때마다 저장하는 테이블
        self.flow.create_flows()

        # 경고 메시지만 저장하는 테이블
        self.warnig_repo.create_warnings()

        # 블랙리스트, 화이트리스트 테이블
        self.black_white_repo.create_blackNwhites()

        # 차단된 패킷 리스트
        self.blocked_packets_repo.create_blocked()

        # 차단조건 테이블
        self.blocked_conditions_repo.create_conditions()

        self.conn.commit()


    def close(self):
        self.packet.flush()
        self.conn.close()
