import socket
import os
import struct
from PacketAnalyzer import *
from IP import *

# A Class to capture network packets
# Captured raw packets are stored as strings in the self.packets list

class PacketCapture:
    def __init__(self):
        self.packets = [""]
        self.ipAddr = ""
        self.numPackets = 0
        
        # PacketAnalyzer will perform entropy analysis on packets
        self.pa = PacketAnalyzer()

    #Capture Packets and add to list    
    def capturePackets(self, ipAddr, numPackets):
        self.packets = [] # clear out the list
        self.ipAddr = ipAddr
        self.numPackets = numPackets

        # create a raw socket and bind it to the public interface
        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

        sniffer.bind((self.ipAddr, 0))

        # we want the IP headers included in the capture
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # if we're on Windows we need to send an IOCTL
        # to setup promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        num = 0 # Keep track of packets going to clients machine
        
        # read in a specified number of ethernet frames
        while num < self.numPackets:
            # Recieve packet
            rawPacket = sniffer.recvfrom(65565)[0]
            
            # create an IP header from the first 20 bytes of the buffer
            ip_header = IP(rawPacket[0:20])
        
            # If the packet is destined for clients machine add it to list
            if ip_header.dst_address == self.ipAddr:
                num += 1
                # Convert packet payload to string and add to packet list
                # Ethernet Header of frame is 14 bytes
                # IP Header is 20 bytes
                # Packet payload starts after byte 34
                self.packets.append(repr(rawPacket[34:]))
                
                # Print packet info for debug/testing purposes comment out later
                packetInfo = "Protocol: %s %s -> %s" % (ip_header.protocol, \
                                                        ip_header.src_address, \
                                                        ip_header.dst_address)
                print packetInfo
                      
        # Perform entropy analysis of packets    
        self.pa.entropyAnalysis(self.packets)
        

        # if we're on Windows turn off promiscuous mode
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        
        return self.pa.getEntropyResult()
            
                        
    def getPacketList(self):
        return self.packets

    def getStats(self):
        return self.pa.getStatistics()
