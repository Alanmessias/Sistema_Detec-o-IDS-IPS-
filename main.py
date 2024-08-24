from scapy.all import sniff
from scapy.layers.inet import TCP
from scapy.layers.inet import IP

def packet_callback(packet):
    print(packet.show()) # mostra os detalhes do pacote

#captura os pacotes em tempo real
sniff(prn=packet_callback, count=10) # Captura 10 pacotes como exemplo

def detect_attack(packet):
    if packet.haslayer(TCP):
        ip_src = packet[IP].src
        tcp_dport = packet[TCP].dport

        if tcp_dport == 80:
            print(f"Possivel scan de portadetectado de {ip_src} na porta {tcp_dport}")

sniff(prn=detect_attack, count=10)




