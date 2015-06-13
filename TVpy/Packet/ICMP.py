__author__ = 'jitrixis'

from TVpy.Fatory.toolsheds import *


class Icmp:
    def __init__(self):
        self.__type = 8
        self.__code = 0
        self.__checksum = 0x0
        self.__id = 0x0
        self.__seq = 0x0

    '''Type'''

    def getType(self):
        return self.__type

    def setType(self, type):
        self.__type = type
        return self

    def __buildType(self):
        return Toolkit.buildInt1(self.__type)

    def __consumeType(self, data):
        val = Toolkit.consumeInt1(data)
        self.__type = val[0]
        return val[1]

    '''Code'''

    def getCode(self):
        return self.__code

    def setCode(self, code):
        self.__code = code
        return self

    def __buildCode(self):
        return Toolkit.buildInt1(self.__code)

    def __consumeCode(self, data):
        val = Toolkit.consumeInt1(data)
        self.__code = val[0]
        return val[1]

    '''Checksum'''

    def getChecksum(self):
        self.__setChecksum()
        return self.__checksum

    def __setChecksum(self):
        first_sum = 0
        first_sum += self.getType() * 0x100 + self.getCode()
        first_sum += self.getId()
        first_sum += self.getSeq()
        second_sum = first_sum % 0x10000
        second_sum += first_sum / 0x10000
        self.__checksum = second_sum ^ 0xffff
        return self

    def __buildChecksum(self):
        self.__setChecksum()
        return Toolkit.buildInt2(self.__checksum)

    def __consumeChecksum(self, data):
        val = Toolkit.consumeInt2(data)
        self.__checksum = val[0]
        return val[1]

    '''Id'''

    def getId(self):
        return self.__id

    def setId(self, id):
        self.__id = id
        return self

    def __buildId(self):
        return Toolkit.buildInt2(self.__id)

    def __consumeId(self, data):
        val = Toolkit.consumeInt2(data)
        self.__id = val[0]
        return val[1]

    '''Sequence'''

    def getSeq(self):
        return self.__seq

    def setSeq(self, seq):
        self.__seq = seq
        return self

    def __buildSeq(self):
        return Toolkit.buildInt2(self.__seq)

    def __consumeSeq(self, data):
        val = Toolkit.consumeInt2(data)
        self.__seq = val[0]
        return val[1]

    '''Building method'''

    def build(self):
        ret = self.__buildType() + self.__buildCode()
        ret += self.__buildChecksum()
        ret += self.__buildId()
        ret += self.__buildSeq()
        return ret

    def fromSource(self, data):
        data = self.__consumeType(data)
        data = self.__consumeCode(data)
        data = self.__consumeChecksum(data)
        data = self.__consumeId(data)
        data = self.__consumeSeq(data)
        return data

