
import time

from engine.db.dbmodule import DBModule

from engine.iptables import add_black, add_white, remove_black, remove_white

class FirewallWorker():

    def __init__(self):
        self.running = True

    def run(self):
        self.db = DBModule()
        while self.running:

            self.process_table("black_list")
            self.process_table("white_list")

            time.sleep(1)

    def stop(self):
        self.running = False

    def process_table(self, table):

        # 추가
        for rule_id, ip in self.db.get_pending_rules(table):
            try:
                if table == "black_list":
                    add_black(ip)
                else:
                    add_white(ip)

                self.db.accept_rule(table, rule_id)

            except Exception as e:
                print(f"[Firewall] add failed : {ip} ({e})")

        # 삭제
        for rule_id, ip in self.db.get_delete_rules(table):
            try:
                if table == "black_list":
                    remove_black(ip)
                else:
                    remove_white(ip)

                self.db.delete_rule(table, rule_id)

            except Exception as e:
                print(f"[Firewall] delete failed : {ip} ({e})")