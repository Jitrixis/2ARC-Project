__author__ = 'jitrixis'

from TVpy.Fatory.toolsheds import Toolkit

class Tcp:
    def __init__(self):
        self.__sport = 0
        self.__dport = 0
        self.__seq = 0
        self.__ack = 0
        self.__reserved = 0x0
        self.__flags = 0x0
        self.__window = 0
        self.__checksum = 0x0
        self.__urgptr = 0

    '''Source port'''
    def getSport(self):
        return self.__sport

    def setSport(self, sport):
        self.__sport = sport
        return self

    def __buildSport(self):
        return Toolkit.buildInt2(self.__sport)

    def __consumeSport(self, data):
        val = Toolkit.consumeInt2(data)
        self.__Sport = val[0]
        return val[1]

    '''Destination port'''
    def getDport(self):
        return self.__dport

    def setDport(self, dport):
        self.__dport = dport
        return self

    def __buildDport(self):
        return Toolkit.buildInt2(self.__dport)

    def __consumeDport(self, data):
        val = Toolkit.consumeInt2(data)
        self.__Dport = val[0]
        return val[1]

    '''Sequence number'''
    def getSeq(self):
        return self.__seq

    def setSeq(self, seq):
        self.__seq = seq
        return self

    def __buildSeq(self):
        return Toolkit.buildInt4(self.__seq)

    def __consumeSeq(self, data):
        val = Toolkit.consumeInt4(data)
        self.__Seq = val[0]
        return val[1]

    '''Acknoledgment number'''
    def getAck(self):
        return self.__ack

    def setAck(self, ack):
        self.__ack = ack
        return self

    def __buildAck(self):
        return Toolkit.buildInt4(self.__ack)

    def __consumeAck(self, data):
        val = Toolkit.consumeInt4(data)
        self.__Ack = val[0]
        return val[1]

    '''Reserved'''
    def getReserved(self):
        return self.__reserved

    def setReserved(self, reserved):
        self.__reserved = reserved
        return self

    def __buildReserved(self):
        return Toolkit.buildInt1(self.__reserved)

    def __consumeReserved(self, data):
        val = Toolkit.consumeInt1(data)
        self.__Reserved = val[0]
        return val[1]

    '''Flags'''
    def getFlags(self):
        return self.__flags

    def setFlags(self, flags):
        self.__flags = flags
        return self

    def __buildFlags(self):
        return Toolkit.buildInt1(self.__flags)

    def __consumeFlags(self, data):
        val = Toolkit.consumeInt1(data)
        self.__Flags = val[0]
        return val[1]

    '''Window'''
    def getWindow(self):
        return self.__window

    def setWindow(self, window):
        self.__window = window
        return self

    def __buildWindow(self):
        return Toolkit.buildInt2(self.__window)

    def __consumeWindow(self, data):
        val = Toolkit.consumeInt2(data)
        self.__Window = val[0]
        return val[1]

    '''Checksum'''

    def getChecksum(self):
        self.__setChecksum()
        return self.__checksum

    def __setChecksum(self):
        first_sum = 0
        first_sum += self.getSport()
        first_sum += self.getDport()
        first_sum += int(self.__buildSeq()[:2].encode('hex'), 16)
        first_sum += int(self.__buildSeq()[2:].encode('hex'), 16)
        first_sum += int(self.__buildAck()[:2].encode('hex'), 16)
        first_sum += int(self.__buildAck()[2:].encode('hex'), 16)
        first_sum += self.getReserved() * 0x100 + self.getFlags()
        first_sum += self.getWindow()
        first_sum += self.getUrgptr()
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

    '''Urgence pointer'''
    def getUrgptr(self):
        return self.__urgptr

    def setUrgptr(self, urgptr):
        self.__urgptr = urgptr
        return self

    def __buildUrgptr(self):
        return Toolkit.buildInt2(self.__urgptr)

    def __consumeUrgptr(self, data):
        val = Toolkit.consumeInt2(data)
        self.__Urgptr = val[0]
        return val[1]

    '''Building method'''

    def build(self):
        ret = self.__buildSport() + self.__buildDport()
        ret += self.__buildSeq()
        ret += self.__buildAck()
        ret += self.__buildReserved() + self.__buildFlags() + self.__buildWindow()
        ret += self.__buildChecksum() + self.__buildUrgptr()
        return ret

    def fromSource(self, data):
        data = self.__consumeSport(data)
        data = self.__consumeDport(data)
        data = self.__consumeSeq(data)
        data = self.__consumeAck(data)
        data = self.__consumeReserved(data)
        data = self.__consumeFlags(data)
        data = self.__consumeWindow(data)
        data = self.__consumeChecksum(data)
        data = self.__consumeUrgptr(data)
        return data
