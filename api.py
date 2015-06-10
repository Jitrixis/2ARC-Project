__author__ = 'jitrixis'

from scapy.all import *
from Fatory.all import *
import re
from Frame.Ethernet import *


def __select_iface():
    pass


'''TODO: Select un interface'''
iface = ''
__select_iface()

e = Ethernet()
e.setDst('ab:cd:ef:01:23:45')
e.setType(0x0806)
print(e.build(), e.build().encode('HEX'))
f = Ethernet()
t = f.fromSource(e.build())
print("")
print(f.getSrc(), f.getDst(), hex(f.getType()))
print("data", t)

'''after sniff str(a[1])[0].encode('hex')'''