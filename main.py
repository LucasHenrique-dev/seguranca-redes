from ping_attack import send_ping
from SYN_attack import send_syn

escolha = 0
while escolha != 1 and escolha != 2:
    escolha = int(input("1 - SYN Attack\n2 - Ping Attack\n"))

if escolha == 1:
    send_syn()
else:
    send_ping(number_of_packets_to_send=1000)

# teste de net: ifstat -t -i wlp2s0
