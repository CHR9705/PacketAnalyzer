from .discord_alert import AlertBot
from .db_watcher import DBWatcher


watcher = None

def start_watching(bot):
    global watcher
    watcher = DBWatcher(on_new_rows_callback=bot.notify_new_rows)
    watcher.start()
    return watcher


def run_bot():
   
    bot = AlertBot()
    
    bot.set_on_ready(lambda: start_watching(bot))

    bot.run()

# 만약 이 파일만 따로 단독 실행할 때도 작동하게 하려면 아래 코드를 추가
