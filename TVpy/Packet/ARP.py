__author__ = 'jitrixis'

from TVpy.Fatory.toolkit import *


class Arp:
    def __init__(self):
        self.__hwtype = 0x1
        self.__ptype = 0x800
        self.__hwlen = 6
        self.__plen = 4
        self.__op = 0x1
        self.__hwsrc = '00:00:00:00:00:00'
        self.__psrc = '0.0.0.0'
        self.__hwdst = '00:00:00:00:00:00'
        self.__pdst = '0.0.0.0'

    '''Hardware Type'''

    def getHwtype(self):
        return self.__hwtype

    def setHwtype(self, hwtype):
        self.__hwtype = hwtype
        return self

    def __buildHwtype(self):
        return buildInt2(self.__hwtype)

    def __consumeHwtype(self, data):
        val = consumeInt2(data)
        self.__hwtype = val[0]
        return val[1]

    '''IP Type'''

    def getPtype(self):
        return self.__ptype

    def setPtype(self, ptype):
        self.__ptype = ptype
        return self

    def __buildPtype(self):
        return buildInt2(self.__ptype)

    def __consumePtype(self, data):
        val = consumeInt2(data)
        self.__ptype = val[0]
        return val[1]

    '''Hardware length'''

    def getHwlen(self):
        return self.__hwlen

    def setHwlen(self, hwlen):
        self.__hwlen = hwlen
        return self

    def __buildHwlen(self):
        return buildInt1(self.__hwlen)

    def __consumeHwlen(self, data):
        val = consumeInt1(data)
        self.__hwlen = val[0]
        return val[1]

    '''IP length'''

    def getPlen(self):
        return self.__plen

    def setPlen(self, plen):
        self.__plen = plen
        return self

    def __buildPlen(self):
        return buildInt1(self.__plen)

    def __consumePlen(self, data):
        val = consumeInt1(data)
        self.__plen = val[0]
        return val[1]

    '''Operation'''

    def getOp(self):
        return self.__op

    def setOp(self, op):
        self.__op = op
        return self

    def __buildOp(self):
        return buildInt2(self.__op)

    def __consumeOp(self, data):
        val = consumeInt2(data)
        self.__op = val[0]
        return val[1]

    '''Hardware Source'''

    def getHwsrc(self):
        return self.__hwsrc

    def setHwsrc(self, hwsrc):
        self.__hwsrc = hwsrc
        return self

    def __buildHwsrc(self):
        return buildMAC(self.__hwsrc)

    def __consumeHwsrc(self, data):
        val = consumeMAC(data)
        self.__hwsrc = val[0]
        return val[1]

    '''IP Source'''

    def getPsrc(self):
        return self.__psrc

    def setPsrc(self, psrc):
        self.__psrc = psrc
        return self

    def __buildPsrc(self):
        return buildIPv4(self.__psrc)

    def __consumePsrc(self, data):
        val = consumeIPv4(data)
        self.__psrc = val[0]
        return val[1]

    '''Hardware Destination'''

    def getHwdst(self):
        return self.__hwdst

    def setHwdst(self, hwdst):
        self.__hwdst = hwdst
        return self

    def __buildHwdst(self):
        return buildMAC(self.__hwdst)

    def __consumeHwdst(self, data):
        val = consumeMAC(data)
        self.__hwdst = val[0]
        return val[1]

    '''IP Destination'''

    def getPdst(self):
        return self.__pdst

    def setPdst(self, pdst):
        self.__pdst = pdst
        return self

    def __buildPdst(self):
        return buildIPv4(self.__pdst)

    def __consumePdst(self, data):
        val = consumeIPv4(data)
        self.__pdst = val[0]
        return val[1]

    '''Building method'''

    def build(self):
        ret = self.__buildHwtype() + self.__buildPtype()
        ret += self.__buildHwlen() + self.__buildPlen()
        ret += self.__buildOp()
        ret += self.__buildHwsrc() + self.__buildPsrc()
        ret += self.__buildHwdst() + self.__buildPdst()
        return ret

    def fromSource(self, data):
        data = self.__consumeHwtype(data)
        data = self.__consumePtype(data)
        data = self.__consumeHwlen(data)
        data = self.__consumePlen(data)
        data = self.__consumeOp(data)
        data = self.__consumeHwsrc(data)
        data = self.__consumePsrc(data)
        data = self.__consumeHwdst(data)
        data = self.__consumePdst(data)
        return data