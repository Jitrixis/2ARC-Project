__author__ = 'jitrixis'

from TVpy.Frame.all import *
from TVpy.Packet.all import *
from TVpy.Segment.all import *
from TVpy.Data.all import *


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

class Harvest:
    def __init__(self):
        self.__sniffery = Sniffery()

    def check(self, pks, pkt):
        pks = self.__sniffery.sniff(str(pks))
        pkt = self.__sniffery.sniff(str(pkt))
        if pks is None or pkt is None:
            return False
        return self.findWay(pks, pkt)


    def findWay(self, pks, pkt):
        if pks["type"] == "arp":
            return self.wayArp(pks, pkt)
        elif pks["type"] == "icmp":
            return self.wayIcmp(pks, pkt)
        elif pks["type"] == "icmp":
            return self.wayTcp(pks, pkt)
        else:
            return False

    def wayArp(self, pks, pkt):
        s = pks["packet"]
        d = pkt["packet"]

        if s["ethernet"].getSrc() != d["ethernet"].getDst():
            return False
        if s["ethernet"].getType() != d["ethernet"].getType():
            return False

        if s["arp"].getHwsrc() != d["arp"].getHwdst():
            return False
        if s["arp"].getHwlen() != d["arp"].getHwlen():
            return False
        if s["arp"].getHwtype() != d["arp"].getHwtype():
            return False

        if s["arp"].getPdst() != d["arp"].getPsrc():
            return False
        if s["arp"].getPsrc() != d["arp"].getPdst():
            return False
        if s["arp"].getPlen() != d["arp"].getPlen():
            return False
        if s["arp"].getPtype() != d["arp"].getPtype():
            return False

        if d["arp"].getOp() != 0x2:
            return False

        return True

    def wayIcmp(self, pks, pkt):
        s = pks["packet"]
        d = pkt["packet"]

        if s["ethernet"].getSrc() != d["ethernet"].getDst():
            return False
        if s["ethernet"].getDst() != d["ethernet"].getSrc():
            return False
        if s["ethernet"].getType() != d["ethernet"].getType():
            return False

        if s["ip"].getDst() != d["ip"].getSrc():
            return False
        if s["ip"].getSrc() != d["ip"].getDst():
            return False
        if s["ip"].getProto() != d["ip"].getProto():
            return False
        if s["ip"].getVersion() != d["ip"].getVersion():
            return False

        if s["icmp"].getId() != d["icmp"].getId():
            return False
        if s["icmp"].getSeq() != d["icmp"].getSeq():
            return False
        if d["icmp"].getCode() != 0:
            return False
        if d["icmp"].getType() != 0:
            return False

        return True

    def wayTcp(self, pks, pkt):
        return True