__author__ = 'jitrixis'

from Fatory.machinery import Engine

class Api:
    def __init__(self):
        self.__engine = Engine("wlan0")
        pass

    def send(self):
        self.__engine.sendICMP()

    '''==================Exemple======================='''

    '''return sniff(prn=lambda x: x.summary(), lfilter=h.farm, stop_filter=h.farm, timeout=10)'''

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