from scapy.all import *
from scapy.layers.inet import IP, ICMP


def scapy_direct_way():
    info = conf.route.route("0.0.0.0")

    print("Conectado na Interface: " + info[0] + " (" + info[1] + ")")
    print("Endereco IP do Default Gateway: " + info[2])
    return info[2]


def scapy_trace_router():
    info = sr1(IP(dst="www.google.com", ttl=0) / ICMP() / "XXXXXXXXXXX")

    print("Dados brutos: ", info)
    print("\nDados tratados (lista): ", list(info))
    return info.src


# descobrir endereco ip roteador: https://scapy.readthedocs.io/en/latest/routing.html
# https://stackoverflow.com/questions/38134095/find-lan-router-ip-address-with-scapy
