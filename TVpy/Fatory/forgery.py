__author__ = 'jitrixis'

from random import randint

from TVpy.Layers.all import *

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

    def generateTCPSyn(self, dHwr, dAddr, dPort, sPort, syn):
        ether = Ethernet()
        ether.setDst(dHwr)
        ether.setType(0x800)

        ip = Ip()
        ip.setDst(dAddr)
        ip.setProto(6)

        tcp = Tcp()
        tcp.setSport(sPort)
        tcp.setDport(dPort)
        tcp.setSeq(syn)
        tcp.setReserved(0xa0)
        tcp.setFlags(0x02)
        tcp.setWindow(0xaaaa)

        data = Data()

        return self.__forgeTcp(ether, ip, tcp, data)

    def generateTCPSynAck(self, dHwr, dAddr, dPort, sPort, syn, ack):
        ether = Ethernet()
        ether.setDst(dHwr)
        ether.setType(0x800)

        ip = Ip()
        ip.setDst(dAddr)
        ip.setProto(6)

        tcp = Tcp()
        tcp.setSport(sPort)
        tcp.setDport(dPort)
        tcp.setSeq(syn)
        tcp.setAck(ack)
        tcp.setReserved(0xa0)
        tcp.setFlags(0x12)
        tcp.setWindow(0xaaaa)

        data = Data()

        return self.__forgeTcp(ether, ip, tcp, data)

    def generateTCPAck(self, dHwr, dAddr, dPort, sPort, ack, syn):
        ether = Ethernet()
        ether.setDst(dHwr)
        ether.setType(0x800)

        ip = Ip()
        ip.setDst(dAddr)
        ip.setProto(6)

        tcp = Tcp()
        tcp.setSport(sPort)
        tcp.setDport(dPort)
        tcp.setSeq(syn)
        tcp.setAck(ack)
        tcp.setReserved(0x80)
        tcp.setFlags(0x10)
        tcp.setWindow(0xaaaa)

        data = Data()

        return self.__forgeTcp(ether, ip, tcp, data)

    def generateTCPData(self, dHwr, dAddr, dPort, sPort, data, syn, ack):
        ether = Ethernet()
        ether.setDst(dHwr)
        ether.setType(0x800)

        ip = Ip()
        ip.setDst(dAddr)
        ip.setProto(6)

        tcp = Tcp()
        tcp.setSport(sPort)
        tcp.setDport(dPort)
        tcp.setSeq(syn)
        tcp.setAck(ack)
        tcp.setReserved(0x80)
        tcp.setFlags(0x18)
        tcp.setWindow(0xaaaa)

        data = Data()

        return self.__forgeTcp(ether, ip, tcp, data)

    def generateTCPFin(self, dHwr, dAddr, dPort, sPort, syn, ack):
        ether = Ethernet()
        ether.setDst(dHwr)
        ether.setType(0x800)

        ip = Ip()
        ip.setDst(dAddr)
        ip.setProto(6)

        tcp = Tcp()
        tcp.setSport(sPort)
        tcp.setDport(dPort)
        tcp.setSeq(syn)
        tcp.setAck(ack)
        tcp.setReserved(0x80)
        tcp.setFlags(0x11)
        tcp.setWindow(0x0156)

        data = Data()

        return self.__forgeTcp(ether, ip, tcp, data)

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