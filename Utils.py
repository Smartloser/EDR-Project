class AddrType:
    
    MAC = 1
    IPv4 = 4
    IPv6 = 6

class FilterType:

    TCP = 6
    UDP = 17
    TCPUDP = 3
    SYN = 4
    ACK = 5
    EVIL_BIT = 6

    filter_dict = {'tcp', TCP, 'udp', UDP, 'tcpudp', TCPUDP, 'syn', SYN, 'ack', ACK, 'evil', EVIL_BIT}