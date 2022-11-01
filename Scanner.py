from multiprocessing import Process
import socket

class IP4Scanner(Process):
    
    def run(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(3))
        print("Ran")
        while True:
            raw_data, addr = conn.recvfrom(65535)
            print(f"addr: {addr}")
            