__author__ = 'jitrixis'

from Factory.machinery import *

class Api:
    def __init__(self, device="wlan0"):
        self.__engine = Engine(device)
        pass

    def getIP(self, mac):
        r = self.__engine.getArpIP(mac)
        return r

    def getMAC(self, ip):
        r = self.__engine.getArpMAC(ip)
        return r

    def sendPing(self, ip):
        r = self.__engine.ping(ip, 1)
        return r

    def sendManyPing(self, ip, salve):
        r = self.__engine.ping(ip, salve)
        return r

    def listen(self, ip, dport):
        self.__dport = dport
        self.__sport = randint(0x0, 0xffff)
        self.__ipdest = ip

    def connect(self):
        synack = self.__engine.sendSYNConn(self.__ipdest, self.__dport, self.__sport)
        self.__engine.sendACKConn(synack)

    def accept(self):
        f = "tcp and host "+self.__ipdest
        syn = sniff(filter=f, count=1)
        self.__engine.sendSYNACKConn(syn)

    def send(self, data):
        data = self.__engine.sendPSHACKData(self.__ipdest, self.__dport, self.__sport, data)
        return data

    def recv(self):
        f = "tcp and host "+self.__ipdest
        pshack = sniff(filter=f, count=1)
        self.__engine.sendACKData(pshack)

    def close(self):
        pass