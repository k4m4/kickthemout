#!/usr/bin/env python
# -.- coding: utf-8 -.-
# scan.py
# author: xdavidhu

def scanNetwork(network):
    returnlist = []
    import nmap
    nm = nmap.PortScanner()
    a = nm.scan(hosts=network, arguments='-sP')

    for k, v in a['scan'].iteritems():
        if str(v['status']['state']) == 'up':
            try:
                returnlist.append([str(v['addresses']['ipv4']), str(v['addresses']['mac'])])
            except:
                pass

    return returnlist
