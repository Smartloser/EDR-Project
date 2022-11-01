import multiprocessing
from EDR import EDR, EDRManager
from Command import CommandHandler
from IP4Scanner import IP4Scanner

if __name__ == "__main__":
    print("Welcome to Matan's EDR Tool.")

    edr_manager = EDRManager()
    command_handler = CommandHandler(edr_manager)
    scanner = IP4Scanner()
    scanner.start()
    
    while(True):
        cmd = input("> ")
        command_handler.handle_command(cmd)
        