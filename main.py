from queue import Queue
from threading import Thread

from engine.packet_capture import PacketCapture
from engine.processor import PacketProcessor
from engine.discord.dm_main import run_bot   


packet_queue = Queue()

capture = PacketCapture(packet_queue)
processor = PacketProcessor(packet_queue)

capture_thread = Thread(
    target=capture.start,
    daemon=True
)

processor_thread = Thread(
    target=processor.run,
    daemon=True
)

bot_thread = Thread(          # 추가
    target=run_bot,
    daemon=True
)

capture_thread.start()
processor_thread.start()
bot_thread.start() 

capture_thread.join()
processor_thread.join()
bot_thread.join()  

