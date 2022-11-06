from multiprocessing import Process, Queue
from Utils import AddrType, FilterType
from Command import CommandHandler
from EDR import EDR
from PacketInfo import PacketInfo

class EDRManager(Process):

    def __init__(self, pkt_queue: Queue, gui_queue: Queue, cmd_queue: Queue):
        super(EDRManager, self).__init__()
        self.edr_list = list()
        self.pkt_queue = pkt_queue
        self.gui_queue = gui_queue
        self.cmd_queue = cmd_queue


    def run(self):
        cmd_handler = CommandHandler(self)
        while True:
            #Check cmd input
            try:
                cmd = self.cmd_queue.get_nowait()
                cmd_handler.handle_command(cmd)
            except:
                pass
            
            # Check for packet input
            try:
                pkt = self.pkt_queue.get_nowait()
                print(f"Received packet {pkt}")
                self.handle_packet(pkt)
            except:
                pass

    def handle_packet(self, pkt):
        pkt_info = PacketInfo(pkt)
        dst_ip = pkt_info.get_dst_ip()
        
        for edr in self.get_edr_list():
            if edr.get_addr() == dst_ip:
                pkt_protocol = pkt_info.get_protocol()
                if edr.has_filter(FilterType.TCPUDP) or edr.has_filter(pkt_protocol):
                    if edr.has_filter(FilterType.ACK) and pkt_info.get_ack_flag() == 0:
                        return
                    if edr.has_filter(FilterType.SYN) and pkt_info.get_syn_flag() == 0:
                        return
                    if edr.has_filter(FilterType.EVIL_BIT) and not pkt_info.is_evil_bit():
                        return

                    self.gui_queue.put_nowait(pkt_info.get_data())
                 

    def edr_exists(self,edr):
        for existing_edr in self.edr_list:
            if existing_edr.get_addr() == edr.get_addr():
                return True
        return False

    def add_edr(self, edr):
        self.edr_list.append(edr)

    def remove_edr(self, edr):
        for idx, existing_edr in enumerate(self.edr_list):
            if existing_edr.get_unique_id() == edr.get_unique_id():
                self.edr_list.remove(idx)
                return True

        False

    def add_edr_filter(self, addr, filter):
        edr = self.get_edr_by_id(addr)
        if edr is None:
            return False

        edr.add_filter(filter)    
        return True        

    def get_edr_by_id(self, addr) -> EDR: 
        for existing_edr in self.edr_list:
            if existing_edr.get_addr() == addr:
                return existing_edr
        return None

    def get_edr_list(self):
        return self.edr_list