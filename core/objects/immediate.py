class ImmediateValue:

    def __init__(self, value):
        self.__value = value

    def __str__(self):
        return str(self.__value)

    def __repr__(self):
        return "ImmediateValue(%s)" % repr(self.__value)

    def __hash__(self):
        return hash(self.__value)

    def __cmp__(self, other):
        if isinstance(other, ImmediateValue):
            return cmp(self.__value, other.__value)
        elif type(other) is int:
            return cmp(self.__value, other)
        raise NotImplementedError

    @property
    def value(self):
        return self.__value