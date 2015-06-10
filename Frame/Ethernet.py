__author__ = 'jitrixis'

from Fatory.toolkit import *

class Ethernet:
    def __init__(self):
        self.__src = '00:00:00:00:00:00'
        self.__dst = 'ff:ff:ff:ff:ff:ff'
        self.__type = 0x806

    '''Destination MAC Address'''
    def getDst(self):
        return self.__dst

    def setDst(self, dst):
        self.__dst = dst
        return self

    def __buildDst(self):
        return buildMAC(self.__dst)

    def __consumeDst(self, data):
        val = consumeMAC(data)
        self.__dst = val[0]
        return val[1]

    '''Source MAC Address'''
    def getSrc(self):
        return self.__src

    def setSrc(self, src):
        self.__src = src
        return self

    def __buildSrc(self):
        return buildMAC(self.__src)

    def __consumeSrc(self, data):
        val = consumeMAC(data)
        self.__src = val[0]
        return val[1]

    '''Type Ethernet Data'''
    def getType(self):
        return self.__type

    def setType(self, type):
        self.__type = type
        return self

    def __buildType(self):
        return buildInt2(self.__type)

    def __consumeType(self, data):
        val = consumeInt2(data)
        self.__type = val[0]
        return val[1]

    '''Building method'''
    def build(self):
        return self.__buildDst() + self.__buildSrc() + self.__buildType()

    def fromSource(self, data):
        data = self.__consumeDst(data)
        data = self.__consumeSrc(data)
        data = self.__consumeType(data)
        return data