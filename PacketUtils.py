import socket
import struct
import textwrap

def unpack_ethernet(raw_data):
    dest_mac, src_mac, eth_protocol = struct.unpack('! 6s 6s H', raw_data[:14]) # ! = big endian s = char[](char=1byte), H = short(2bytes)
    return convert_mac_addr(dest_mac), convert_mac_addr(src_mac), socket.htons(eth_protocol), raw_data[14:] # htons convert from computer encoding to network(big endian)

def unpack_ipv4(raw_data):
    vihl, tos, total_len, identification, flags_offset, TTL, protocol, header_checksum, s_ip, d_ip = struct.unpack('! B B H H H B B H 4s 4s', raw_data[:20]) # B=unsigned char.

    version = vihl >> 4 # bitshift 4 right to obtain
    IHL = vihl & 15 # 15 = 0xF. & operator to obtain ihl

    x_flag = (flags_offset >> 15) & 1 # evil bit
    D_flag = (flags_offset >> 14) & 1 # defragmented
    M_flag = (flags_offset >> 13) & 1 # more fragments to follow

    frag_offset = flags_offset & 8191

    return version, IHL, tos, total_len, identification, x_flag, D_flag, M_flag, frag_offset, TTL, protocol, header_checksum , getip(s_ip), getip(d_ip), raw_data[20:]

def tcp_unpack(data):
        s_port, d_port, seq_no, ack_no, offset_reserved, flags, window, checksum, urg_pointer = struct.unpack('! H H L L B B H H H', data[:20])

        offset = offset_reserved >> 4
        reserved = offset & 15

        cwr = (flags >> 7) & 1
        ece = (flags >> 6) & 1
        urg = (flags >> 5) & 1
        ack = (flags >> 4) & 1 # SYN -> SYN-ACK -> ACK
        psh = (flags >> 3) & 1
        rst = (flags >> 2) & 1
        syn = (flags >> 1) & 1
        fin = flags & 1

        return s_port, d_port, seq_no, ack_no, cwr, ece, urg, ack, psh, rst, syn, fin , window, checksum, urg_pointer, data[offset:]

def udp_unpack(data):
        s_port, d_port, length, checksum = struct.unpack('! H H H H', data[:8])
        return s_port, d_port, length, checksum, data[8:]

def unpack(raw_packet):
    eth_layer = unpack_ethernet(raw_packet)
    ip_layer = unpack_ipv4(eth_layer[-1])
    protocol = ip_layer[-5]
    proto_layer = ()

    if protocol == 'TCP':
        proto_layer = tcp_unpack(ip_layer[-1])
    else:
        proto_layer = udp_unpack(ip_layer[-1])

    return eth_layer, ip_layer, proto_layer, format_payload(proto_layer[-1]) # formatting rest of packet to Hex


def getip(ip_data):
        return '.'.join(map(str, ip_data))

def convert_mac_addr(data):
    mac = map ('{:02x}'.format, data)
    return ':'.join(mac).upper()

def format_payload(payload):
    hexed_payload = ' '.join(format(n, '02X') for n in payload)

    return '\n'.join('\t\t\t' + line for line in textwrap.wrap(hexed_payload, 100))

