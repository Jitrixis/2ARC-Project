__author__ = 'jitrixis'

from Fatory.toolkit import *

class Ip:
    def __init__(self):
        self.__version = 0x45
        self.__tos = 0x0
        self.__len = 20
        self.__id = 1
        self.__flags = 0x0
        self.__ttl = 64
        self.__proto = 0x0
        self.__checksum = 0x0
        self.__src = '0.0.0.0'
        self.__dst = '0.0.0.0'

    '''Version and IHL'''
    def getVersion(self):
        return self.__version

    def setVersion(self, version):
        self.__version = version
        return self

    def __buildVersion(self):
        return buildInt1(self.__version)

    def __consumeVersion(self, data):
        val = consumeInt1(data)
        self.__version = val[0]
        return val[1]

    '''DSCP and ECN'''
    def getTos(self):
        return self.__tos

    def setTos(self, tos):
        self.__tos = tos
        return self

    def __buildTos(self):
        return buildInt1(self.__tos)

    def __consumeTos(self, data):
        val = consumeInt1(data)
        self.__tos = val[0]
        return val[1]

    '''Length'''
    def getLen(self):
        return self.__len

    def setLen(self, len):
        self.__len = 20 + len
        return self

    def __buildLen(self):
        return buildInt2(self.__len)

    def __consumeLen(self, data):
        val = consumeInt2(data)
        self.__len = val[0]
        return val[1]

    '''Identification'''
    def getId(self):
        return self.__id

    def setId(self, id):
        self.__id = id
        return self

    def __buildId(self):
        return buildInt2(self.__id)

    def __consumeId(self, data):
        val = consumeInt2(data)
        self.__id = val[0]
        return val[1]

    '''Flags and Fragment offset'''
    def getFlags(self):
        return self.__flags

    def setFlags(self, flags):
        self.__flags = flags
        return self

    def __buildFlags(self):
        return buildInt2(self.__flags)

    def __consumeFlags(self, data):
        val = consumeInt2(data)
        self.__flags = val[0]
        return val[1]

    '''Time to live'''
    def getTtl(self):
        return self.__ttl

    def setTtl(self, ttl):
        self.__ttl = ttl
        return self

    def __buildTtl(self):
        return buildInt1(self.__ttl)

    def __consumeTtl(self, data):
        val = consumeInt1(data)
        self.__ttl = val[0]
        return val[1]

    '''Protocole'''
    def getProto(self):
        return self.__proto

    def setProto(self, proto):
        self.__proto = proto
        return self

    def __buildProto(self):
        return buildInt1(self.__proto)

    def __consumeProto(self, data):
        val = consumeInt1(data)
        self.__proto = val[0]
        return val[1]

    '''Checksum'''
    def getChecksum(self):
        self.__setChecksum()
        return self.__checksum

    def __setChecksum(self):
        first_sum = 0
        first_sum += self.getVersion() * 0x100 + self.getTos()
        first_sum += self.getLen()
        first_sum += self.getId()
        first_sum += self.getFlags()
        first_sum += self.getTtl() * 0x100 + self.getProto()
        first_sum += int(self.__buildSrc()[:2].encode('hex'), 16)
        first_sum += int(self.__buildSrc()[2:].encode('hex'), 16)
        first_sum += int(self.__buildDst()[:2].encode('hex'), 16)
        first_sum += int(self.__buildDst()[2:].encode('hex'), 16)
        second_sum = first_sum % 0x10000
        second_sum += first_sum / 0x10000
        self.__checksum = second_sum ^ 0xffff
        return self

    def __buildChecksum(self):
        self.__setChecksum()
        return buildInt2(self.__checksum)

    def __consumeChecksum(self, data):
        val = consumeInt2(data)
        self.__checksum = val[0]
        return val[1]

    '''IP Source'''
    def getSrc(self):
        return self.__src

    def setSrc(self, src):
        self.__src = src
        return self

    def __buildSrc(self):
        return buildIPv4(self.__src)

    def __consumeSrc(self, data):
        val = consumeIPv4(data)
        self.__src = val[0]
        return val[1]

    '''IP Destination'''
    def getDst(self):
        return self.__dst

    def setDst(self, dst):
        self.__dst = dst
        return self

    def __buildDst(self):
        return buildIPv4(self.__dst)

    def __consumeDst(self, data):
        val = consumeIPv4(data)
        self.__dst = val[0]
        return val[1]

    '''Building method'''

    def build(self):
        ret = self.__buildVersion() + self.__buildTos() + self.__buildLen()
        ret += self.__buildId() + self.__buildFlags()
        ret += self.__buildTtl() + self.__buildProto() + self.__buildChecksum()
        ret += self.__buildSrc()
        ret += self.__buildDst()
        return ret

    def fromSource(self, data):
        data = self.__consumeVersion(data)
        data = self.__consumeTos(data)
        data = self.__consumeLen(data)
        data = self.__consumeId(data)
        data = self.__consumeFlags(data)
        data = self.__consumeTtl(data)
        data = self.__consumeProto(data)
        data = self.__consumeChecksum(data)
        data = self.__consumeSrc(data)
        data = self.__consumeDst(data)
        return data