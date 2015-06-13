__author__ = 'jitrixis'

from scapy.all import *
from TVpy.Frame.all import *
from TVpy.Packet.all import *
from TVpy.Segment.all import *

class Forgery:
    def __init__(self):
        pass

    def forge(self):
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
        print(hex(sa.getHwtype()), hex(sa.getPtype()), hex(sa.getHwlen()), hex(sa.getPlen()), hex(sa.getOp()), sa.getHwsrc(),
              sa.getPsrc(), sa.getHwdst(), sa.getPdst())
        print("data", data)

        '''sendp(Raw(p), iface="lo")'''

        p2 = Ethernet().setType(0x800).setDst("00:00:00:00:00:00").build() + Ip().setLen(8).setId(0x672f).setFlags(
            0x4000).setProto(1).setSrc("127.0.0.1").setDst("127.0.0.1").build() + Icmp().setId(0x35aa).setSeq(1).build()

        print(p2, p2.encode('HEX'))
        sendp(Raw(p2), iface="lo")