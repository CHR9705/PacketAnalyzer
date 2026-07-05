from queue import Queue
from threading import Thread

from packet_capture import PacketCapture
from processor import PacketProcessor


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


capture_thread.start()

processor_thread.start()


capture_thread.join()

processor_thread.join()