import os
from scapy.all import sniff
from scapy.layers.inet import TCP


def block_ip(ip_address):
    os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
    print(f"IP {ip_address} bloqueado.")

def detect_and_block(packet):
    if packet.haslayer(TCP):
        ip_src = packet[IP].src
        tcp_dport = packet[TCP].dport

        if tcp_dport == 80:
            print(f"Possivel scan de porta detectadode {ip_src} na porta{tcp_dport}")
            block_ip(ip_src)

sniff(prn=detect_and_block, count=10)