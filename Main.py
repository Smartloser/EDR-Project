from multiprocessing import Queue
from EDRManager import EDRManager
from GUI import EdrGui
from Scanner import IP4Scanner

if __name__ == "__main__":

    packet_queue = Queue()
    cmd_queue = Queue()
    gui_queue = Queue()

    edr_manager = EDRManager(packet_queue,gui_queue, cmd_queue)
    scanner = IP4Scanner(packet_queue)
    edr_gui = EdrGui(gui_queue)

    edr_manager.start()
    scanner.start()
    edr_gui.start()
    
    print("Welcome to Matan's EDR Tool.")
    while(True):
        cmd = input("> ")
        try:
            cmd_queue.put_nowait(cmd)
        except:
            print("Command not recorded. Please try again.")
        