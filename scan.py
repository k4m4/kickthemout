#!/usr/bin/env python
# -.- coding: utf-8 -.-
# scan.py
# authors: k4m4 & xdavidhu

def scanNetwork(network):
    # Function for performing a network scan with nmap with the help of the python-nmap module
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

    # returnlist = hostsList array
    return returnlist
