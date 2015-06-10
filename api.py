__author__ = 'jitrixis'

from scapy.all import *
from Fatory.all import *
import re


def __select_iface():
    pass


'''TODO: Select un interface'''
iface = ''
__select_iface()

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
print(hex(sa.getHwtype()), hex(sa.getPtype()), hex(sa.getHwlen()), hex(sa.getPlen()), hex(sa.getOp()), sa.getHwsrc(), sa.getPsrc(), sa.getHwdst(), sa.getPdst())
print("data", data)

'''after sniff str(a[1])[0].encode('hex')'''