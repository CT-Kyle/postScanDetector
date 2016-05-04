#!/usr/bin/env python2.7

'''Resources used:
https://github.com/VinTeK/Port-Scan-Detector/blob/master/detector.py
https://nmap.org/book/man-port-scanning-techniques.html (info on types of flags used in port scans)
'''

import dpkt, socket, sys

#=CONSTANTS===================================================================#

SYN_SYNACK_RATIO = 3

#=FUNCTIONS===================================================================#

def tcpFlags(tcp):
    """Returns a list of the set flags in this TCP packet."""
    ret = list()

    if tcp.flags & dpkt.tcp.TH_FIN != 0:
        ret.append('FIN')
    if tcp.flags & dpkt.tcp.TH_SYN  != 0:
        ret.append('SYN')
    if tcp.flags & dpkt.tcp.TH_RST  != 0:
        ret.append('RST')
    if tcp.flags & dpkt.tcp.TH_PUSH != 0:
        ret.append('PSH')
    if tcp.flags & dpkt.tcp.TH_ACK  != 0:
        ret.append('ACK')
    if tcp.flags & dpkt.tcp.TH_URG  != 0:
        ret.append('URG')
    if tcp.flags & dpkt.tcp.TH_ECE  != 0:
        ret.append('ECE')
    if tcp.flags & dpkt.tcp.TH_CWR  != 0:
        ret.append('CWR')

    # print ret
    return ret


def compare_IPs(ip1, ip2):
    """
    Return negative if ip1 < ip2, 0 if they are equal, positive if ip1 > ip2.
    """
    return sum(map(int, ip1.split('.'))) - sum(map(int, ip2.split('.')))

#=ARG PARSING=================================================================#

# Must include a pcap to read from.
if len(sys.argv) <= 1:
    print "{0}: needs a filepath to a PCAP file".format(sys.argv[0])
    sys.exit(-1)

# Try to open the pcap file and create a pcap.Reader object.
try:
    f = open(sys.argv[1])
    pcap = dpkt.pcap.Reader(f)
except (IOError, KeyError):
    print "Cannot open file:", sys.argv[1]
    sys.exit(-1)

# Set ratio if provided.
if len(sys.argv) == 3:
    try:
        SYN_SYNACK_RATIO = float(sys.argv[2])
    except ValueError:
        print "invalid ratio value:", sys.argv[2]
        sys.exit(-1)

#=MAIN========================================================================#

suspects = dict() # Dictionary of suspects. suspect's IP: {# SYNs, # SYN-ACKs}
curPacket = 0     # Current packet number.
destDict = {}
sourceDict = {}
timeStampArray = []

# Analyze captured packets.
for ts, buf in pcap:
    curPacket += 1
    timeStampArray.append(ts)  #push timestamp into array to analyze time of port scan
    # print"{0:.6f}".format(ts)
    # print curPacket
    # print dpkt.tcp.TH_CWR
    # print tcp.flags

    # Ignore malformed packets
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.dpkt.UnpackError, IndexError):
        continue

    # Packet must include IP protocol to get TCP
    ip = eth.data
    if not ip:
        continue

    # Skip packets that are not TCP
    tcp = ip.data
    if type(tcp) != dpkt.tcp.TCP:
        # print "Not TCP"
        continue

# Compute range of Source and Dest ports
    if tcp.sport in sourceDict:
        sourceDict[tcp.sport] += 1
    else:
        sourceDict[tcp.sport] = 1

    if tcp.dport in destDict:
        destDict[tcp.dport] += 1
    else:
        destDict[tcp.dport] = 1

    # Get all of the set flags in this TCP packet
    tcpFlag = tcpFlags(tcp)

    srcIP = socket.inet_ntoa(ip.src)
    # print "source", srcIP
    dstIP = socket.inet_ntoa(ip.dst)
    # print "dest", dstIP

    # Fingerprint possible suspects.
    if {'SYN'} == set(tcpFlag):          # A 'SYN' request.
        if srcIP not in suspects:
            suspects[srcIP] = {'SYN': 0, 'SYN-ACK': 0}
            # print tcp.dport

        suspects[srcIP]['SYN'] += 1

    elif {'SYN', 'ACK'} == set(tcpFlag): # A 'SYN-ACK' reply.
        if dstIP not in suspects:
            suspects[dstIP] = {'SYN': 0, 'SYN-ACK': 0}
            # print tcpFlag
        suspects[dstIP]['SYN-ACK'] += 1
    elif {'FIN', 'PSH', 'URG'} == set(tcpFlag):
        if srcIP not in suspects:
            suspects[srcIP] = {'FIN': 0, 'PSH': 0, 'URG': 0}
        suspects[srcIP]['FIN'] += 1
        suspects[srcIP]['PSH'] += 1
        suspects[srcIP]['URG'] += 1
    # print suspects



destList = sorted(destDict)
sourceList = sorted(sourceDict)
destRange =  str(destList[0]) + " - " + str(destList[-1])
soureRange = str(sourceList[0]) + " - " + str(sourceList[-1])
timeStampArray = sorted(timeStampArray)
timeRange = str("{0:.6f}".format(timeStampArray[0])) + "s" + " - " + str("{0:.6f}".format(timeStampArray[-1])) + "s"
timeDuration = timeStampArray[-1] - timeStampArray[0]
print "##### Statistics of Transmission #####"
print "## Ports Involved ##"
print "Dest Port Range:", destRange
print "Number of Unique Dest Ports:", len(destDict)
print "Source Port Range:", soureRange
print "Number of Unique Source Ports:", len(sourceDict)
print ""
print "## Time of Transmission ##"
print "Time Range of Scan:", timeRange
print "Duration of Scan:", "{0:.6f}".format(timeDuration) + "s"
print ""


# Prune unlikely suspects based on ratio of SYNs to SYN-ACKs.
for s in suspects.keys():
    if 'SYN' in suspects[s].keys():
        if suspects[s]['SYN'] < (suspects[s]['SYN-ACK'] * SYN_SYNACK_RATIO):
            del suspects[s]

# Output results.
print "## Packet Analysis ##"
print "Analyzed", curPacket, "packets:"

if not suspects:
    print 'no suspicious packets detected...'


for s in sorted(suspects.keys(), cmp=compare_IPs):
    if 'SYN' in suspects[s].keys():
        syns = suspects[s]['SYN']
        synacks = suspects[s]['SYN-ACK']
        print "{0:15} had {1} SYNs and {2} SYN-ACKs".format(s, syns, synacks)
    if 'FIN' in suspects[s].keys():
        fins = suspects[s]['FIN']
        pshs = suspects[s]['PSH']
        urgs = suspects[s]['URG']
        print "{0:15} had {1} FINs and {2} PSHs and {3} URGs".format(s, fins, pshs, urgs)
        print "This is characteristic of a CHRISTMAS TREE ATTACK!"

print "########################################"
print ""
print "##### Results #####"
if (len(suspects.keys()) > 0):
    print "PORT SCAN DETECTED!!!"
else:
    print "COAST IS CLEAR"
