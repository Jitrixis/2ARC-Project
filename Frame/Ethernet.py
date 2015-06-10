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

    def __buildDst(self):
        return self.__buildMAC(self.__dst)

    def __consumeDst(self, data):
        val = self.__consumeMAC(data)
        self.__dst = val[0]
        return val[1]

    '''Source MAC Address'''
    def getSrc(self):
        return self.__src

    def setSrc(self, src):
        self.__src = src
        return self

    def __buildSrc(self):
        return self.__buildMAC(self.__src)

    def __consumeSrc(self, data):
        val = self.__consumeMAC(data)
        self.__src = val[0]
        return val[1]

    '''Type Ethernet Data'''
    def getType(self):
        return self.__type

    def setType(self, type):
        self.__type = type
        return self

    def __buildType(self):
        build = chr((self.__type & 0xff00) >> 8)
        build += chr((self.__type & 0x00ff))
        return build

    def __consumeType(self, data):
        self.__type = int(data[:2].encode('hex'), 16)
        return data[2:]

    '''Misc.'''
    def __buildMAC(self, mac):
        build = ""
        mac_array = mac.split(":")
        for octet in mac_array:
            build += octet.decode("HEX")
        return build

    def __consumeMAC(self, data):
        mac = ""
        for _ in range(6):
            mac += data[:1].encode('hex') + ":"
            data = data[1:]
        mac = mac[:-1]
        return [mac, data]

    '''Building method'''
    def build(self):
        return self.__buildDst() + self.__buildSrc() + self.__buildType()

    def fromSource(self, data):
        data = self.__consumeDst(data)
        data = self.__consumeSrc(data)
        data = self.__consumeType(data)
        return data