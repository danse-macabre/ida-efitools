from idaapi import *
from idautils import *
from idc import *


class Protocol:

    def __init__(self, guid, struc, interface, introduced_at):
        self.__guid = guid
        self.__struc = struc
        self.__interface = interface
        self.__introduced_at = introduced_at

    def __str__(self):
        return self.__struc.name

    def __repr__(self):
        return str(self)

    @property
    def struc(self):
        return self.__struc

    @property
    def guid(self):
        return self.__guid

    @property
    def interface(self):
        return self.__interface

    @property
    def introduced_at(self):
        return self.__introduced_at

    @property
    def name(self):
        return self.__struc.name


class ImportProtocol(Protocol):
    pass


class ExportProtocol(Protocol):
    pass


class Interface:

    def __init__(self, ptr_or_lvar, bind_point):
        self.__storage = ptr_or_lvar
        self.__bind_point = bind_point

    def __str__(self):
        return "%s bound at 0x%X" % (self.__storage, self.__bind_point)

    @property
    def storage(self):
        return self.__storage

    @property
    def bind_point(self):
        return self.__bind_point