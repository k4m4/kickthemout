#!/usr/bin/env python
# -.- coding: utf-8 -.-
# scan.py 
# author: Benedikt Waldvogel (MIT Licensed)
# edited by: k4m4 & xdavidhu

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.config, scapy.layers.l2, scapy.route, socket, math, errno

def scanNetwork():

    def long2net(arg):
        if (arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("illegal netmask value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))

    def to_CIDR_notation(bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" % (network, netmask)
        if netmask < 16:
            return None

        return net

    def scan_and_print_neighbors(net, interface, timeout=1):
        hostsList = []
        try:
            ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=False)
            for s, r in ans.res:
                mac = r.sprintf("%Ether.src%")
                ip = r.sprintf("%ARP.psrc%")
                line = r.sprintf("%Ether.src%  %ARP.psrc%")
                hostsList.append([ip, mac])
                try:
                    hostname = socket.gethostbyaddr(r.psrc)
                    line += "," + hostname[0]
                except socket.herror:
                    pass
        except socket.error as e:
            if e.errno == errno.EPERM:     # Operation not permitted
                exit()
            else:
                raise
        return hostsList

    for network, netmask, _, interface, address in scapy.config.conf.route.routes:

        # skip loopback network and default gw
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        net = to_CIDR_notation(network, netmask)

        if interface != scapy.config.conf.iface:
            # see http://trac.secdev.org/scapy/ticket/537
            continue

        if net:
            return scan_and_print_neighbors(net, interface)