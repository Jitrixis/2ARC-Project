__author__ = 'jitrixis'

from scapy.all import *
from forgery import *
from sniffery import *

class Engine:
    def __init__(self, device):
        self.__device = ""
        self.__forgery = Forgery("a4:17:31:50:73:2b", "10.31.16.253")
        self.__sniffery = Sniffery()
        pass

    def sendICMP(self):
        p1 = self.__forgery.generateArpRequest("10.31.18.16")
        h1 = Harvest("a4:17:31:50:73:2b", "10.31.16.253", "arp")

        result = self.send_receive(p1, h1)
        print(result[0])

        '''after sniff str(a[1])[0].encode('hex')'''

        p2 = self.__forgery.generateIcmpRequest(result[1][1].getHwsrc(), "10.31.18.16")
        h2 = Harvest("a4:17:31:50:73:2b", "10.31.16.253", "icmp", result[1][1].getHwsrc(), "10.31.18.16")

        print(result[0])
        '''sendp(Raw(p2))'''

    def send_receive(self, pkt, harvest):
        sendp(Raw(pkt))
        r = sniff(lfilter=harvest.farm, stop_filter=harvest.farm, timeout=10)
        if len(r) == 1:
            return self.__sniffery.sniff(str(r[0]))
        return None


    '''==================Exemple======================='''

    '''def forge(self):
        e = Ethernet()
        e.setDst('ab:cd:ef:01:23:45')
        e.setType(0x0806)
        a = Arp()
        p = self.__forgeArp(e, a)
        print(p, p.encode('HEX'))
        se = Ethernet()
        sa = Arp()
        data = se.fromSource(p)
        data = sa.fromSource(data)
        print("")
        print(se.getSrc(), se.getDst(), hex(se.getType()))
        print(
            hex(sa.getHwtype()), hex(sa.getPtype()), hex(sa.getHwlen()), hex(sa.getPlen()), hex(sa.getOp()), sa.getHwsrc(),
            sa.getPsrc(), sa.getHwdst(), sa.getPdst())
        print("data", data)'''

    '''sendp(Raw(p), iface="lo")'''

    '''def forge2(self):
        e = Ethernet()
        e.setDst('ab:cd:ef:01:23:45')
        e.setType(0x0806)
        a = Arp()
        p = e.build() + a.build()
        print(p, p.encode('HEX'))
        se = Ethernet()
        sa = Arp()
        data = se.fromSource(p)
        data = sa.fromSource(data)
        print("")
        print(se.getSrc(), se.getDst(), hex(se.getType()))
        print(
            hex(sa.getHwtype()), hex(sa.getPtype()), hex(sa.getHwlen()), hex(sa.getPlen()), hex(sa.getOp()), sa.getHwsrc(),
            sa.getPsrc(), sa.getHwdst(), sa.getPdst())
        print("data", data)'''

    '''sendp(Raw(p), iface="lo")'''

    '''p2 = Ethernet().setType(0x800).setDst("00:00:00:00:00:00").build() + Ip().setLen(8).setProto(6).setSrc(
            "127.0.0.1").setDst("127.0.0.1").build() + Tcp().build()

        print(p2, p2.encode('HEX'))
        sendp(Raw(p2), iface="lo")'''