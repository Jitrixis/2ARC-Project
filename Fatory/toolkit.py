__author__ = 'jitrixis'


def buildIPv4(ip):
    build = ""
    ip_array = ip.split(".")
    for octet in ip_array:
        build += chr(int(octet))
    return build


def consumeIPv4(data):
    ip = ""
    for _ in range(4):
        ip += str(int(data[:1].encode('hex'), 16)) + "."
        data = data[1:]
    ip = ip[:-1]
    return [ip, data]


def buildMAC(mac):
    build = ""
    mac_array = mac.split(":")
    for octet in mac_array:
        build += octet.decode("HEX")
    return build


def consumeMAC(data):
    mac = ""
    for _ in range(6):
        mac += data[:1].encode('hex') + ":"
        data = data[1:]
    mac = mac[:-1]
    return [mac, data]


def buildInt1(int):
    build = chr(int)
    return build


def consumeInt1(data):
    value = int(data[:1].encode('hex'), 8)
    data = data[1:]
    return [value, data]


def buildInt2(int):
    build = chr((int & 0xff00) >> 8)
    build += chr((int & 0x00ff))
    return build


def consumeInt2(data):
    value = int(data[:2].encode('hex'), 16)
    data = data[2:]
    return [value, data]