from scapy.all import *
from scapy.layers.inet import IP, ICMP

from general_functions.find_ip_router import scapy_direct_way as direct_way


def send_ping(number_of_packets_to_send: int = 4, size_of_packet: int = 65000):
    target_ip_address = direct_way()

    ip_ping = IP(dst=target_ip_address)
    icmp = ICMP()
    raw_ping = Raw(b"X" * size_of_packet)
    p = ip_ping / icmp / raw_ping
    send(p, count=number_of_packets_to_send, verbose=0)
    print('\nsend_ping(): Sent ' + str(number_of_packets_to_send) + ' pings of ' + str(
        size_of_packet) + ' size to ' + target_ip_address)


# send_ping(ip, number_of_packets_to_send=1000)
