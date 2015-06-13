__author__ = 'jitrixis'

from Fatory.machinery import Engine

class Api:
    def __init__(self):
        self.__engine = Engine("wlan0")
        pass

    def send(self):
        self.__engine.sendICMP()