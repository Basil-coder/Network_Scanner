from scapy.all import ARP, Ether, srp

target_ip = "192.168.1.1/24"

# Create an ARP packet
arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

result = srp(packet, timeout=3, verbose=0)[0]

clients = []
for sent, received in result:
    clients.append({'ip': received.psrc, 'mac': received.hwsrc})

print("Available devices in the network:")
for client in clients:
    print(client)
