
class WarningManager:

    def __init__(self):
        self.cache = {}
    
    def add_warning(self, timestamp, src_ip, attack_type):
        key = (src_ip, attack_type)

        if key not in self.cache:
            self.cache[key] = {
                "timestamp": timestamp,
                "counter": 1
            }
        else:
            self.cache[key]["counter"] += 1
            self.cache[key]["timestamp"] = timestamp

    def flush(self, db):

        for (src_ip, attack_type), data in self.cache.items():

            db.insert_warning_table(
                data["timestamp"],
                src_ip,
                attack_type,
                data["counter"]
            )

        self.cache.clear()