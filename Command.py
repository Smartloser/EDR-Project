import ipaddress
import re
import EDR
from Utils import AddrType, FilterType

class CommandHandler:
    
    def __init__(self, edr_manager):
        self.edr_manager = edr_manager

    def handle_command(self, cmd):
        cmd_args = cmd.split()
        cmd_header = cmd_args[0]

        if cmd_header == "add":
            self.add_edr(cmd_args[1:])
        elif cmd_header == "remove":
            self.remove_edr(cmd_args[1])
        elif cmd_header == "filter":
            self.filter_edr(cmd_args[1], cmd_args[2], cmd_args[3])
        elif cmd_header == "list":
            self.list_edr()
        elif cmd_header == "help":
            print("""List of commands:\n\n
                    add <ipv4/ipv6/mac> - Adds a new scanner for specific address\n
                    remove <ipv4/ipv6/mac - Removes scanner if exists for specific address\n
                    filter <ipv4/ipv6/mac> <add/remove> <TCP/UDP/TCPUDP/TCPSYN/TCPACK/TCPEVILBIT> - Add/Remove filter for specific address
                    list - List all running scanners""")
        else:
            print("Unknown command. Please type 'help' for list of available commands.")

    def add_edr(self, command_data):
        addr = command_data[0]
        try:
            command_data = ipaddress.ipaddress.ip_address(addr)

            if command_data.find('6') > -1:
                addr_type = AddrType.IPv6
            else:
                addr_type = AddrType.IPv4

            edr = EDR.EDR(addr, addr_type)
            self.edr_manager.add_edr(edr)
        except:
            if re.match("[0-9A-F]{2}([:]?)[0-9A-F]{2}(\\1[0-9A-F]{2}){4}$", addr):
                edr = EDR.EDR(AddrType.MAC)
                self.edr_manager.add_edr(edr)
            else:
                print("An invalid address was entered. Please make sure the address is correct.")
                return
        print(f"Scanner for {addr} added succesfully")
        

    def remove_edr(self, addr):
        if self.edr_manager.remove_edr(addr):
            print(f"Succesfully removed scanner for {addr}")
        else:
            print(f"Scanner for {addr} does not exist.")

    def filter_edr(self, addr, type, filter): # type = add or remove
        if self.edr_manager.exists(addr):
            if self.is_valid_filter(filter):
                if type == 'add':
                    self.edr_manager.add_filter_edr(addr, filter)
                    print(f"Succesfully added filter {filter} to scanner {addr}")
                else:
                    self.edr_manager.remove_filter_edr(addr, filter)
                    print(f"Succesfully removed filter {filter} to scanner {addr}")
            else:
                print("Invalid filter was entered.")
                return
        else:
            print(f"Scanner for {addr} hasn't been created, cannot add filter.")

    def list_edr(self):
        for edr in self.edr_manager.get_edr_list():
            print(f"EDR for address {edr.get_addr()}, Filters: " + ", ".join(filter for filter in edr.filters))

    def is_valid_filter(self, filter):
        if filter in FilterType.filter_dict:
            return True

        return False

    
