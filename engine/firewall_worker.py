
import time
import platform


from engine.db.dbmodule import DBModule

from engine.iptables import add_black, add_white, remove_black, remove_white

class FirewallWorker():

    def __init__(self):
        self.running = True

    def run(self):
        if platform.system() != "Linux":
            return

        self.db = DBModule()
        self.first_run()

        while self.running:

            self.process_table("black_list")
            self.process_table("white_list")

            time.sleep(1)

    def stop(self):
        self.running = False

    def first_run(self):
        for rule_id, ip in self.db.get_rules("black_list"):
            try:
                add_black(ip)
                self.db.accept_rule("black_list", rule_id)

            except Exception as e:
                print(f"[Firewall] add failed : {ip} ({e})")

        for rule_id, ip in self.db.get_rules("white_list"):
            try:
                add_black(ip)
                self.db.accept_rule("black_list", rule_id)

            except Exception as e:
                print(f"[Firewall] add failed : {ip} ({e})")

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