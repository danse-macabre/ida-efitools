from idaapi import *
from idautils import *
from idc import *

import core


class Pointer(object):

    USED_NAMES = {}

    def __init__(self, addr=None, name=None):
        if addr:
            self.__ea = addr
            if name is not None:
                self.name = name
        elif name:
            self.__ea = LocByName(name)
        else:
            raise ValueError

    def __hash__(self):
        return self.__ea

    def __cmp__(self, other):
        if isinstance(other, Pointer):
            return cmp(self.addr, other.addr)
        return False

    def __str__(self):
        return "%X %s" % (self.__ea, self.name)

    def __repr__(self):
        return "Pointer(0x%X, '%s')" % (self.__ea, self.name)

    @property
    def addr(self):
        return self.__ea

    @property
    def name(self):
        return Name(self.__ea)

    @name.setter
    def name(self, value):
        if value in Pointer.USED_NAMES.keys():
            Pointer.USED_NAMES[value] += 1
            value = "%s_%d" % (value, Pointer.USED_NAMES[value] - 1)
        else:
            Pointer.USED_NAMES.update({value: 0})
        if MakeNameEx(self.__ea, value, SN_PUBLIC) != 1:
            raise Exception("MakeName(0x%X, '%s') has failed" % (self.__ea, value))

    @property
    def type(self):
        type = GetType(self.__ea)
        if type is None:
            # raise Exception("GetType() has failed")
            type = ""
        return type

    @type.setter
    def type(self, value):
        if value is None or value == "":
            raise ValueError("value: %s" % value)
        if SetType(self.__ea, "%s %s" % (value, self.name)) == 0:
            raise Exception("SetType() has failed")

    def get_bytes(self, cnt):
        return get_many_bytes(self.__ea, cnt)