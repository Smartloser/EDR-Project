
class EDR:

    def __init__(self, addr, addrtype):
        self.addr = addr
        self.addrtype = addrtype
        self.filters = set()

    def add_filter(self, filter):
        self.filters.add(filter)

    def remove_filter(self, filter):
        try:
            self.filters.remove(filter)
        except:
            return False
        return True

    def get_addr(self):
        return self.addr

    def get_addr_type(self):
        return self.addrtype

    def get_filters(self):
        return self.filters

    def get_unique_id(self):
        return self.addr + '.'.join(num for num in self.filters)

class EDRManager:

    def __init__(self):
        self.edr_list = list()

    def edr_exists(self,edr):
        for existing_edr in self.edr_list:
            if existing_edr.get_unique_id() == edr.get_unique_id():
                return True
        return False

    def add_edr(self, edr):
        self.edr_list.add(edr)

    def remove_edr(self, edr):
        for idx, existing_edr in enumerate(self.edr_list):
            if existing_edr.get_unique_id() == edr.get_unique_id():
                self.edr_list.remove(idx)
                return True

        False

    def add_filter_edr(self, addr, filter):
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

