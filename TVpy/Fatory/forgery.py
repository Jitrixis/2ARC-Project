__author__ = 'jitrixis'

from TVpy.Frame.all import *
from TVpy.Packet.all import *
from TVpy.Segment.all import *
from TVpy.Data.all import *
from random import randint


class Forgery:
    def __init__(self, sHwr, hAddr):
        self.__sHwr = sHwr
        self.__sAddr = hAddr
        pass

    def generateIcmpRequest(self, dHwr, dAddr, seq=1, id=0):
        if id == 0:
            id = randint(0x0, 0xffff)

        ether = Ethernet()
        ether.setDst(dHwr)
        ether.setType(0x800)

        ip = Ip()
        ip.setDst(dAddr)
        ip.setProto(1)

        icmp = Icmp()
        icmp.setSeq(seq)
        icmp.setId(id)

        return self.__forgeIcmp(ether, ip, icmp)

    def generateArpRequest(self, dAddr):
        ether = Ethernet()
        ether.setType(0x0806)

        arp = Arp()
        arp.setPdst(dAddr)

        return self.__forgeArp(ether, arp)

    def __forgeArp(self, ethernet, arp):
        ethernet.setSrc(self.__sHwr)
        arp.setHwsrc(self.__sHwr)
        arp.setPsrc(self.__sAddr)
        return self.__forge([ethernet, arp])

    def __forgeIcmp(self, ethernet, ip, icmp):
        ethernet.setSrc(self.__sHwr)
        ip.setSrc(self.__sAddr)
        ip.setLen(icmp.getLength())
        return self.__forge([ethernet, ip, icmp])

    def __forgeTcp(self, ethernet, ip, tcp, data):
        ethernet.setSrc(self.__sHwr)
        ip.setSrc(self.__sAddr)
        ip.setLen(tcp.getLength() + data.getLength())
        return self.__forge([ethernet, ip, tcp, data])

    def __forge(self, stack):
        forge = ""
        for grp in stack:
            forge += grp.build()
        return forge