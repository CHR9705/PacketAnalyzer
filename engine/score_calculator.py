from .packet_data import PacketData


class ScoreCalculator:
    def __init__(self, db):
        self.db = db

    def calc_score(self, name:str, packet:PacketData):
        """
        점수를 계산해서 반환함.
        """
        score = 0

        if "Flood".lower() in name.lower():
            score = self.calc_flood(name, packet)
        elif "Scan".lower() in name.lower():
            score = self.calc_scan(name, packet)
        elif "Amplification".lower() in name.lower():
            score = self.calc_amplification(name, packet)
        elif "Hijacking".lower() in name.lower():
            score = self.calc_hijacking(name, packet)

        if score > 10: score = 10
        elif score < 0 : score = 0

        return score


    def calc_flood(self, name, packet):
        """
        flood 전용 점수 계산기
        """
        # counter에 따라서 점수 계산해서 반환
        cnt = self.get_counter(name, packet.src_ip)
        
        return cnt/18
    
    def calc_scan(self, name, packet):
        """
        scan 전용 점수 계산기
        """
        cnt = self.get_counter(name, packet.src_ip)
        cnt = cnt/15
        
        if cnt >= 7: cnt = 6.9
        return cnt
    
    def calc_amplification(self, name, packet):
        """
        amplification 전용 점수 계산기
        """
        rows = self.db.get_warning_counter_by_attacktype(name)
        cnt = 0

        for row in rows:
            cnt += row[0]

        if cnt < 5 : cnt = 5
        return cnt
    
    def calc_hijacking(self, name, packet):
        """
        hijacking 전용 점수 계산기
        """
        cnt = self.get_counter(name, packet.src_ip)
        cnt = cnt * 7
        
        if cnt < 7 : cnt = 7
        return cnt
    
    def get_counter(self, name, src_ip):
        """
        공격 이름과 src_ip로 찾아서 counter 반환
        """
        return self.db.get_warning_counter(name, src_ip)[0][0]
    