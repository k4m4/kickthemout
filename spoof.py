#kickthemout/scan.py by @xdavidhu

def sendPacket(my_mac, interface, my_ip, target_ip, target_mac):

    import sys
    from scapy.all import (
        get_if_hwaddr,
        getmacbyip,
        ARP,
        Ether,
        sendp
    )

    ether = Ether()
    ether.src = my_mac

    arp = ARP()
    arp.psrc = my_ip
    arp.hwsrc = my_mac

    arp = arp
    arp.pdst = target_ip
    arp.hwdst = target_mac

    ether = ether
    ether.src = my_mac
    ether.dst = target_mac

    arp.op = 2
    packet = ether/arp
    sendp(x=packet)
