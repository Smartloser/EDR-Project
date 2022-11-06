from multiprocessing import Process
class EDR:

    def __init__(self, addr, addrtype):
        self.addr = addr
        self.addrtype = addrtype
        self.filters = list()

    def add_filter(self, filter):
        self.filters.append(filter)

    def remove_filter(self, filter):
        try:
            self.filters.remove(filter)
        except:
            return False
        return True

    def has_filter(self, filter):
        return self.filters.count(filter) > 0

    def get_addr(self):
        return self.addr

    def get_addr_type(self):
        return self.addrtype

    def get_filters(self):
        return self.filters

