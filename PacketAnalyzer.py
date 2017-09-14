from __future__ import division
import socket
import math
import os
import struct

from ctypes import *


# Performs entropy analysis on packet data.


class PacketAnalyzer:

    def __init__(self):


        self.entropyResult = 0


    # Converts a list of filtered packet data into binary form

    # filteredPackets is a list of filtered packet data

    # Returns the binary form of the list

    def convertToBinary(self, filteredPackets):

        binaryPackets = []

        for packet in filteredPackets:  # examine each packet in the filtered packets list to convert each into binary

            binaryPacket = ''

            for packetChar in packet:

                packetCharValue = ord(packetChar)  # get ASCII value of each character

                packetCharValueBinary = self.convertNumberToBinary(packetCharValue, 8) # convert value into binary byte

                binaryPacket += packetCharValueBinary  # add binary byte value of character to binary packet string

            binaryPackets.append(binaryPacket)

        return binaryPackets



    # Converts a given (positive or zero) number into binary

    # num = number to convert to binary

    # numBits = how many bits to use to store the result

    # Note that if numBits cannot hold the value of num completely, the result will not be correct

    def convertNumberToBinary(self, num, numBits):

        byteString = ''  # start off byte string as all empty (the for loop below will build the bits)

        numRemaining = num

        for i in range(numBits, 0, -1): # go from numBits through 0 in steps of -1 (going backwards)

            if numRemaining >= 2 ** (i - 1):  # check if numRemaining >= 2^i (i.e., the value for this bit position

                byteString += '1'  # put 1 as bit if numRemaining was big enough to fill the bit

                numRemaining -= 2 ** (i - 1)  # decrement numReamining to subtract this filled bit's value

            else:

                byteString += '0'  # put 0 as bit if it numRemaining was too small

        return byteString

    # Converts the packets ascii values into their decimal values
    # and returns them in a list
    def getNumericList(self, packetData):
        numericList = []
        
        # Turn packetData into string
        s = "".join(packetData)

        # Turn each character in string into a decimal number
        for n in s:
            numericList.append(ord(n))

        return numericList
    
    # Counts the occurences of distinct characters
    # Counts the total number of characters
    # returns an character occurence map and total number of characters
    def hist(self,source):
        hist = {}
        l = 0
        for e in source:
            l += 1
            if e not in hist:
                hist[e] = 0
            hist[e] += 1
        return(l, hist)

    # Shannon's Entropy algorithm
    # Returns the entropy/character for the given data
    # result of algorithm is a real number
    def determineEntropy(self, hist, l):
        elist = []
        for v in hist.values():
            c = v / l
            elist.append(-c * math.log(c, 2))
        return sum(elist)
    
    # Passes packet data to Shannon's entropy algorithm
    # returns the results
    # Expected return value is a real number (eg. 2.89)
    def entropyAnalysis(self, packetData):
        print "Performing Entropy analysis\n"
        
        # Turn the packetData into decimal values
        numList = self.getNumericList(packetData)
        
        # Gets the number of occurences of each value in the list
        # and the total number of characters
        (l,h) = self.hist(numList)
        
        # Runs the Entropy algorithm on the list
        self.entropyResult = self.determineEntropy(h,l)
        return self.entropyResult
    
    # Accessor method that returns the entropy result
    def getEntropyResult(self):
        return self.entropyResult
