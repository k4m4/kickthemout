#!/usr/bin/env python
# -.- coding: utf-8 -.-
# scan.py

"""
Copyright (C) 2017 Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

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
