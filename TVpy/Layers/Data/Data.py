__author__ = 'jitrixis'

class Data:
    def __init__(self):
        self.__data = ""

    '''Destination MAC Address'''

    def getData(self):
        return self.__data

    def setData(self, data):
        self.__data = data
        return self

    def __buildData(self):
        return self.__data

    def __consumeData(self, data):
        val = [data, ""]
        self.__data = val[0]
        return val[1]

    '''Building method'''

    def build(self):
        return self.__buildData()

    def fromSource(self, data):
        data = self.__consumeData(data)
        return data

    def getLength(self):
        return len(self.build())