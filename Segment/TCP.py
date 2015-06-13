__author__ = 'jitrixis'


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