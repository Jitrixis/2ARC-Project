__author__ = 'jitrixis'


class Ethernet:
    def __init__(self):
        self.__src = '00:00:00:00:00:00'
        self.__dst = 'ff:ff:ff:ff:ff:ff'
        self.__type = 0x0000

    def getDst(self):
        return self.__dst

    def setDst(self, dst):
        self.__dst = dst
        return self

    def getSrc(self):
        return self.__src

    def setSrc(self, src):
        self.__src = src
        return self

    def getType(self):
        return self.__type

    def setType(self, type):
        self.__type = type
        return self

    def build(self):
        pass

    def fromSource(self, source):
        pass