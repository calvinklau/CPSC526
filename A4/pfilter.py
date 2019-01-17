# CPSC 526 - Fall 2018
# Assignment 4 - Packet Filter
# Calvin Lau | 10151228

import sys
import struct   # For struct.unpack(packet_bytes)
import socket   # For socket.inet_ntoa(packet_IP)

class Packet:
    """
    Represents a packet with the following attributes:
        protocol: protocol found in packet IP header
        srcIP: source IP in packet IP header
        dstIP: destination IP in packet IP header
        srcPort: source port in packet TCP/UDP header
        dstPort: destination port in packet TCP/UDP header
    """
    def __init__(self):
        self.protocol = 0
        self.srcIP = ''
        self.dstIP = ''
        self.srcPort = 0
        self.dstPort = 0

def extractPacket(filename):
    """
    Extracts packet header values from the binary file (protocol, IPs, and ports)
    :param filename: name of binary raw packet file
    :return: Packet object containing header values
    """
    packet = Packet()

    with open(filename, "rb") as f:
        rawPacket = f.read()

    # Extract IP header from packet
    iph = rawPacket[:20]

    iphdr = struct.unpack('!BBHHHBBH4s4s', iph)    # Unpack the IP header
    packet.protocol = iphdr[6]  # IP Protocol
    packet.srcIP = socket.inet_ntoa(iphdr[8])
    packet.dstIP = socket.inet_ntoa(iphdr[9])

    # Extract TCP header from TCP packet
    if packet.protocol == 6:
        tcph = rawPacket[20:40]

        tcphdr = struct.unpack('!HHLLBBHHH', tcph)  # Unpack TCP header
        packet.srcPort = tcphdr[0]
        packet.dstPort = tcphdr[1]

    # Extract UDP header from UDP packet
    elif packet.protocol == 17:
        udph = rawPacket[20:28]

        udphdr = struct.unpack('!HHHH', udph)   # Unpack UDP header
        packet.srcPort = udphdr[0]
        packet.dstPort = udphdr[1]

    # If neither TCP nor UDP, unpack format string is unknown -> assign arbitrary port values
    else:
        packet.srcPort = 12345
        packet.dstPort = 54321

    return packet

def extractRules(filename):
    """
    Extracts all rules in a string array from the rules file
    :param filename: name of file containing packet filter rules
    :return: string array containing the rules of the packet filter
    """
    with open(filename) as f:
        allRules = f.readlines()
        allRules = [x.strip() for x in allRules]

    return allRules

def getHeaderValues(rule):
    """
    Extracts all values from a rule for the packet filter
    :param rule: a single rule from the rules file (string)
    :return: access (allow|deny), protocol, IPs, ports
    """
    access = rule[0]

    if rule[1] == 'tcp':
        protocol = 6
    elif rule[1] == 'udp':
        protocol = 17
    else:
        protocol = 999
    src = rule[2].split(':')
    srcIP = src[0]
    srcPort = src[1]
    dst = rule[3].split(':')
    dstIP = dst[0]
    dstPort = dst[1]

    return access, protocol, srcIP, dstIP, srcPort, dstPort

def validateIP(ip, packet_ip):
    """
    Determines if the packet's IP equals the rule's IP. Handles any wildcards in the rule IP
    :param ip: IP from a rule
    :param packet_ip: the packet's IP
    :return: (boolean) rule_IP == packet_IP
    """
    try:
        index = ip.index('*')
        if index > -1:
            if index == 0:  # If entire rule IP is wildcard, accept any packet IP
                return True
            elif ip[0:index-1] == packet_ip[0:index-1]:
                return True
            else:
                return False
    except(ValueError):
        pass    # Ignore ValueError exception -> indicates that a rule IP address doesn't contain a wildcard

    # If the rule IP has no wildcard, compare the entire IP
    if ip == packet_ip:
        return True
    else:
        return False

def applyRules(rules, packet):
    """
    Takes the packet and applies each filter rule to it to determine if it is allowed, denied,
    or unspecified
    :param rules: the string array containing the rules from the rules file
    :param packet: the packet being filtered
    :return: (allow|deny|unspecified)
    """
    acceptFlag = 'unspecified'

    for rule in rules:
        rule = rule.replace('-> ', '').split(' ')
        access, protocol, srcIP, dstIP, srcPort, dstPort = getHeaderValues(rule)

        # Handle any wildcards in the rule ports
        if srcPort == '*':
            srcPort = str(packet.srcPort)
        if dstPort == '*':
            dstPort = str(packet.dstPort)

        # If packet matches rule's protocol, IPs, and ports
        if (
            protocol == packet.protocol and
            validateIP(srcIP, packet.srcIP) and   # Handle any wildcards in the rule's source IP
            validateIP(dstIP, packet.dstIP) and   # Handle any wildcards in the rule's destination IP
            srcPort == str(packet.srcPort) and
            dstPort == str(packet.dstPort)
        ):
            if access == 'allow':   # If packet matches and rule allows it, continue
                acceptFlag = True
                continue
            else:                   # If packet matches and rule denies it, break
                acceptFlag = False
                break

    return acceptFlag

if __name__ == '__main__':
    rules = extractRules(sys.argv[1])   # Get rules from file
    packet = extractPacket(sys.argv[2]) # Read packet from file
    access = applyRules(rules, packet)  # Apply rules on packet

    if access == 'unspecified':
        print('unspecified')
    elif access == True:
        print('allow')
    else:
        print('deny')

    exit(0)
