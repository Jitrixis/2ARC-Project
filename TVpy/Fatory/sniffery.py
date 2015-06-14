__author__ = 'jitrixis'

from TVpy.Frame.all import *
from TVpy.Packet.all import *
from TVpy.Segment.all import *
from TVpy.Data.all import *


class Sniffery:
    def __init__(self, dHwr, dAddr):
        self.__dHwr = dHwr
        self.__dAddr = dAddr
        self.__passed = True
        self.__type = ""
        pass

    def sniff(self, data):
        self.__passed = True
        packet = []

        '''Ethernet'''
        valE = self.__sniffEthernet(data)
        packet.append(valE[0])
        data = valE[1]

        if (valE[0].getType() == 0x0800):
            '''IPv4'''
            valI = self.__sniffIp(data)
            packet.append(valI[0])
            data = valI[1]

            if (valI[0].getProto() == 1):
                '''Icmp'''
                valJ = self.__sniffIcmp(data)
                packet.append(valJ[0])
                data = valJ[1]

                self.__type = "icmp"
            elif (valI[0].getProto() == 6):
                '''Tcp'''
                valT = self.__sniffTcp(data)
                packet.append(valT[0])
                data = valT[1]

                self.__type = "tcp"
            else:
                self.__passed = False

        elif (valE[0].getType() == 0x0806):
            '''Arp'''
            valA = self.__sniffArp(data)
            packet.append(valA[0])
            data = valA[1]

            self.__type = "arp"

        else:
            self.__passed = False

        '''Data'''
        valD = self.__sniffData(data)
        packet.append(valD[0])
        data = valD[1]

        if (self.__passed):
            return [self.__type, packet]
        return None


    def __sniffEthernet(self, data):
        return self.__sniffAll(Ethernet(), data)

    def __sniffArp(self, data):
        return self.__sniffAll(Arp(), data)

    def __sniffIcmp(self, data):
        return self.__sniffAll(Icmp(), data)

    def __sniffIp(self, data):
        return self.__sniffAll(Ip(), data)

    def __sniffTcp(self, data):
        return self.__sniffAll(Tcp(), data)

    def __sniffData(self, data):
        return self.__sniffAll(Data(), data)

    def __sniffAll(self, cls, data):
        data = cls.fromSource(data)
        return [cls, data]

class Harvest:
    def __init__(self, dHwr, dAddr, type, sHwr=None, sAddr=None, dport=None, sport=None):
        self.__type = type
        self.__dHwr = dHwr
        self.__dAddr = dAddr
        self.__sHwr = sHwr
        self.__sAddr = sAddr
        self.__dport = dport
        self.__sport = sport

    def farm(self, pkt):
        if(pkt != None):
            pass

    def __filtering(self, sniffer):
        type = sniffer[0]
        cls = sniffer[1]
        '''Type filter'''
        if (type != self.__type):
            return None

        '''sHwr'''
        if (self.__sHwr != None):
            if (cls[0].getSrc() != self.__sHwr):
                return None
            if (type == "arp"):
                if (cls[1].getHwsrc() != self.__sHwr):
                    return None
            elif (type == "icmp" or type == "tcp"):
                pass
            else:
                return None

        '''dHwr'''
        if (self.__dHwr != None):
            if (cls[0].getDst() != self.__dHwr):
                return None
            if (type == "arp"):
                if (cls[1].getHwdst() != self.__dHwr):
                    return None
            elif (type == "icmp" or type == "tcp"):
                pass
            else:
                return None

        '''sAddr'''
        if (self.__sAddr != None):
            if (type == "arp"):
                if (cls[1].getPsrc() != self.__sAddr):
                    return None
            elif (type == "icmp" or type == "tcp"):
                if (cls[1].getSrc() != self.__sAddr):
                    return None
            else:
                return None

        '''dAddr'''
        if (self.__dAddr != None):
            if (type == "arp"):
                if (cls[1].getPdst() != self.__dAddr):
                    return None
            elif (type == "icmp" or type == "tcp"):
                if (cls[1].getDst() != self.__dAddr):
                    return None
            else:
                return None

        '''sport'''
        if (self.__sport != None):
            if (type == "arp" or type == "icmp"):
                return None
            elif (type == "tcp"):
                if (cls[2].getSport() != self.__sport):
                    return None
            else:
                return None

        '''dport'''
        if (self.__dport != None):
            if (type == "arp" or type == "icmp"):
                return None
            elif (type == "tcp"):
                if (cls[2].getDport() != self.__dport):
                    return None
            else:
                return None

        return sniffer