__author__ = 'jitrixis'

from TVpy.Layers.all import *


class Sniffery:
    def __init__(self):
        self.__passed = True
        self.__type = ""
        pass

    def sniff(self, data):
        self.__passed = True
        packet = {}

        '''Ethernet'''
        valE = self.__sniffEthernet(data)
        packet["ethernet"] = valE[0]
        data = valE[1]

        if (valE[0].getType() == 0x0800):
            '''IPv4'''
            valI = self.__sniffIp(data)
            packet["ip"] = valI[0]
            data = valI[1]

            if (valI[0].getProto() == 1):
                '''Icmp'''
                valJ = self.__sniffIcmp(data)
                packet["icmp"] = valJ[0]
                data = valJ[1]

                self.__type = "icmp"
            elif (valI[0].getProto() == 6):
                '''Tcp'''
                valT = self.__sniffTcp(data)
                packet["tcp"] = valT[0]
                data = valT[1]

                self.__type = "tcp"
            else:
                self.__passed = False

        elif (valE[0].getType() == 0x0806):
            '''Arp'''
            valA = self.__sniffArp(data)
            packet["arp"] = valA[0]
            data = valA[1]

            self.__type = "arp"

        else:
            self.__passed = False

        '''Data'''
        valD = self.__sniffData(data)
        packet["data"] = valD[0]
        data = valD[1]

        if (self.__passed):
            return {"type": self.__type, "packet": packet}
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