from engine.iptables import add_black

class AutoBlock:
    def __init__(self, db):
        self.th_dict = {
            "low": 0.1,
            "medium": 4,
            "high": 7,
            "critical": 9,
        }
        self.db = db

    def get_threshold(self) -> float:
        """
        어디서부터 자동차단할지 가져오는 함수
        """

        condition = self.db.get_conditions_table()
        condition = float(condition[1]) if condition else 11.0

        return condition

    def auto_block(self, score, src_ip):
        """
        자동 차단
        """
        threshold = self.get_threshold()
        if score >= threshold:
            add_black(src_ip)
            self.db.insert_black_list(src_ip, True)