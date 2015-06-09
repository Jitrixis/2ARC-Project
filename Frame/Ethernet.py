__author__ = 'jitrixis'


class Ethernet:
    def __init__(self):
        self.__src = '00:00:00:00:00:00'
        self.__dst = 'ff:ff:ff:ff:ff:ff'
        self.__type = 0x0000

    '''Destination MAC Address'''
    def getDst(self):
        return self.__dst

    def setDst(self, dst):
        self.__dst = dst
        return self

    def buildDst(self):
        return self.buildMAC(self.__dst)

    def consumeDst(self, data):
        pass

    '''Source MAC Address'''
    def getSrc(self):
        return self.__src

    def setSrc(self, src):
        self.__src = src
        return self

    def buildSrc(self):
        return self.buildMAC(self.__src)

    def consumeSrc(self, data):
        pass

    '''Type Ethernet Data'''
    def getType(self):
        return self.__type

    def setType(self, type):
        self.__type = type
        return self

    def buildType(self):
        build = chr((self.__type & 0xff00) >> 8)
        build += chr((self.__type & 0x00ff))
        return build

    def consumeType(self, data):
        pass

    '''Misc.'''
    def buildMAC(self, mac):
        build = ""
        mac_array = mac.split(":")
        for octet in mac_array:
            build += octet.decode("HEX")
        return build

    def consumeMAC(self, data):
        pass

    '''Building method'''
    def build(self):
        return self.buildDst() + self.buildSrc() + self.buildType()

    def fromSource(self, data):
        pass