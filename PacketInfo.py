import PacketUtils


class PacketInfo:

    def __init__(self, raw_packet):
        self.eth_layer, self.ip_layer, self.proto_layer, data = PacketUtils.unpack(raw_packet)

    def get_src_mac(self):
        return self.eth_layer[1]

    def get_dst_mac(self):
        return self.eth_layer[0]
    
    def get_src_ip(self):
        return self.ip_layer[-3]

    def get_dst_ip(self):
        return self.ip_layer[-2]

    def get_src_port(self):
        return self.proto_layer[0]

    def get_dst_port(self):
        return self.proto_layer[1]

    def get_protocol(self):
        return self.ip_layer[-5]

    def get_syn_flag(self):
        if self.get_protocol == 6:
            return self.proto_layer[-6]
        return 0

    def get_ack_flag(self):
        if self.get_protocol == 6:
            return self.proto_layer[-9]
        return 0

    def is_evil_bit(self):
        if self.ip_layer[5] == 1:
            return True
        return False

    def get_data(self):
        return PacketUtils.format_payload(self.proto_layer[-1])