from queue import Queue
from threading import Thread

from engine.packet_capture import PacketCapture
from engine.processor import PacketProcessor
from engine.discord.dm_main import run_bot
from engine.firewall_worker import FirewallWorker


packet_queue = Queue()

capture = PacketCapture(packet_queue)
processor = PacketProcessor(packet_queue)

# 1초에 한번 DB 보고 방화벽 설정 수행
firewall = FirewallWorker()

capture_thread = Thread(
    target=capture.start,
    daemon=True
)

processor_thread = Thread(
    target=processor.run,
    daemon=True
)


bot_thread = Thread(
    target=run_bot,
    daemon=True
)

firewall_thread = Thread(
    target = firewall.run,
    daemon=True
)

capture_thread.start()
processor_thread.start()
bot_thread.start()
firewall_thread.start()

capture_thread.join()
processor_thread.join()
bot_thread.join()
firewall_thread.join()

