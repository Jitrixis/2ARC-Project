__author__ = 'jitrixis'

class Toolkit:
    @staticmethod
    def buildIPv4(ip):
        build = ""
        ip_array = ip.split(".")
        for octet in ip_array:
            build += chr(int(octet))
        return build

    @staticmethod
    def consumeIPv4(data):
        ip = ""
        for _ in range(4):
            ip += str(int(data[:1].encode('hex'), 16)) + "."
            data = data[1:]
        ip = ip[:-1]
        return [ip, data]

    @staticmethod
    def buildMAC(mac):
        build = ""
        mac_array = mac.split(":")
        for octet in mac_array:
            build += octet.decode("HEX")
        return build

    @staticmethod
    def consumeMAC(data):
        mac = ""
        for _ in range(6):
            mac += data[:1].encode('hex') + ":"
            data = data[1:]
        mac = mac[:-1]
        return [mac, data]

    @staticmethod
    def buildInt1(int):
        build = chr(int)
        return build

    @staticmethod
    def consumeInt1(data):
        value = int(data[:1].encode('hex'), 8)
        data = data[1:]
        return [value, data]

    @staticmethod
    def buildInt2(int):
        build = chr((int & 0xff00) >> 8)
        build += chr((int & 0x00ff))
        return build

    @staticmethod
    def consumeInt2(data):
        value = int(data[:2].encode('hex'), 16)
        data = data[2:]
        return [value, data]

    @staticmethod
    def buildInt4(int):
        build = chr((int & 0xff000000) >> 24)
        build += chr((int & 0x00ff0000) >> 16)
        build += chr((int & 0x0000ff00) >> 8)
        build += chr((int & 0x000000ff))
        return build

    @staticmethod
    def consumeInt4(data):
        value = int(data[:4].encode('hex'), 32)
        data = data[4:]
        return [value, data]