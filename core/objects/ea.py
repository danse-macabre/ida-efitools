class EffectiveAddr:

    def __init__(self, op):
        self.__op = op

    def __str__(self):
        return str(self.__op)

    def __repr__(self):
        return "EffectiveAddr(%s)" % repr(self.__op)

    def __hash__(self):
        return hash(self.__op)

    @property
    def op(self):
        return self.__op