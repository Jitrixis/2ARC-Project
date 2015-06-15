__author__ = 'jitrixis'

from sniffery import Sniffery

class Harvest:
    def __init__(self):
        self.__sniffery = Sniffery()

    def check(self, pks, pkt):
        pks = self.__sniffery.sniff(str(pks))
        pkt = self.__sniffery.sniff(str(pkt))
        if pks is None or pkt is None:
            return False
        return self.__findWay(pks, pkt)


    def __findWay(self, pks, pkt):
        if pks["type"] == "arp":
            return self.__wayArp(pks, pkt)
        elif pks["type"] == "icmp":
            return self.__wayIcmp(pks, pkt)
        elif pks["type"] == "tcp":
            return self.__wayTcp(pks, pkt)
        else:
            return False

    def __wayArp(self, pks, pkt):
        s = pks["packet"]
        d = pkt["packet"]

        if s["ethernet"].getSrc() != d["ethernet"].getDst():
            return False
        if s["ethernet"].getType() != d["ethernet"].getType():
            return False

        if s["arp"].getHwsrc() != d["arp"].getHwdst():
            return False
        if s["arp"].getHwlen() != d["arp"].getHwlen():
            return False
        if s["arp"].getHwtype() != d["arp"].getHwtype():
            return False

        if s["arp"].getPdst() != d["arp"].getPsrc():
            return False
        if s["arp"].getPsrc() != d["arp"].getPdst():
            return False
        if s["arp"].getPlen() != d["arp"].getPlen():
            return False
        if s["arp"].getPtype() != d["arp"].getPtype():
            return False

        if d["arp"].getOp() != 0x2:
            return False

        return True

    def __wayIcmp(self, pks, pkt):
        s = pks["packet"]
        d = pkt["packet"]

        if s["ethernet"].getSrc() != d["ethernet"].getDst():
            return False
        if s["ethernet"].getDst() != d["ethernet"].getSrc():
            return False
        if s["ethernet"].getType() != d["ethernet"].getType():
            return False

        if s["ip"].getDst() != d["ip"].getSrc():
            return False
        if s["ip"].getSrc() != d["ip"].getDst():
            return False
        if s["ip"].getProto() != d["ip"].getProto():
            return False
        if s["ip"].getVersion() != d["ip"].getVersion():
            return False

        if s["icmp"].getId() != d["icmp"].getId():
            return False
        if s["icmp"].getSeq() != d["icmp"].getSeq():
            return False
        if d["icmp"].getCode() != 0:
            return False
        if d["icmp"].getType() != 0:
            return False

        return True

    def __wayTcp(self, pks, pkt):
        return True