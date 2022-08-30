from scapy.all import *
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Beacon, Dot11Elt


# interface to use to send beacon frames, must be in monitor mode
iface = "wlp2s0mon"
# generate a random MAC address (built-in in scapy)
sender_mac = "C0:8C:71:C7:13:43"
# SSID (name of access point)
ssid = "Test"
# 802.11 frame
dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
# beacon layer
beacon = Dot11Beacon()
# putting ssid in the frame
essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
# stack all the layers and add a RadioTap
frame = RadioTap()/dot11/beacon/essid
# send the frame in layer 2 every 100 milliseconds forever
# using the `iface` interface
sendp(frame, inter=0.1, iface=iface, loop=1)


# https://www.thepythoncode.com/article/create-fake-access-points-scapy
