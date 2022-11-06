from multiprocessing import Process, Queue
import PacketInfo
import socket
import time

class IP4Scanner(Process):
    
    def __init__(self, pkt_queue: Queue):
        super(IP4Scanner, self).__init__()
        self.pkt_queue = pkt_queue
        
    def run(self):
        while True:
            conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            raw_data, addr = conn.recvfrom(65535)
            self.pkt_queue.put_nowait(raw_data)
