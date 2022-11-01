import PacketUtils


class PacketInfo:

    def __init__(self, raw_packet, proto):
        self.eth_layer, self.ip_layer, self.proto_layer, data = PacketUtils.unpack(raw_packet, proto)

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

    def is_evil_bit(self):
        if self.ip_layer[5] == 1:
            return True
        return False

    def get_data(self):
        return PacketUtils.format_payload(self.proto_layer[-1])