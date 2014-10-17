from idaapi import *
from idautils import *
from idc import *


from .pointer import Pointer


class Structure:

    def __init__(self, name=None, sid=None, create_new=True):
        self.__create_new = create_new

        if name is None or name == "":
            raise ValueError("name")

        self.__sid = GetStrucIdByName(name)

        if self.__sid == BADNODE:
            self.__sid = Til2Idb(0, name)

        if self.__sid == BADNODE:
            if not create_new:
                raise Exception("Unknown strucure type: %s" % name)
            else:
                self.__sid = AddStruc(-1, name)
                AddStrucMember(self.__sid, "Dummy", 0, FF_BYTE | FF_DATA, -1, 1)

        if self.__sid == BADNODE:
            raise Exception("Can't define structure type because of bad "
                            "structure name: the name is ill-formed "
                            "or is already used in the program.")

    def __str__(self):
        return self.name

    def __repr__(self):
        return "Structure('%s', create_new=%b)" % (self.name, self.__create_new)

    def __iter__(self):
        # Check structure consistency
        return self.members()

    def __hash__(self):
        return self.__sid

    def __cmp__(self, other):
        if isinstance(other, Structure):
            return cmp(self.__sid, other.__sid)
        raise NotImplementedError

    @property
    def name(self):
        return GetStrucName(self.__sid)

    @property
    def sid(self):
        return self.__sid

    def members(self):
        m_off = GetFirstMember(self.__sid)
        while m_off != BADADDR and m_off != -1:
            if GetMemberFlag(self.__sid, m_off) != -1:
                yield StructureMember(self.__sid, m_off)
            m_off = GetStrucNextOff(self.__sid, m_off)

    def ptrs(self):
        for seg_beg in filter(lambda x: getseg(x).type == SEG_DATA, Segments()):
            seg_end = SegEnd(seg_beg)
            head = seg_beg
            while True:
                head = NextHead(head, seg_end)
                if head == BADADDR:
                    break
                head_ptr = Pointer(head)
                if head_ptr.type.rstrip(" *") == self.name:
                    yield head_ptr

    def add_member(self, offset, name, size):
        if GetMemberName(self.__sid, 0) == "Dummy":
            DelStrucMember(self.__sid, 0)
        flag = {1: FF_BYTE, 2: FF_WORD, 4: FF_DWRD, 8: FF_QWRD}.get(size)
        if flag is None:
            raise ValueError("size")
        err_code = AddStrucMember(self.__sid, name, offset, flag | FF_DATA, -1, size)
        if err_code != 0:
            raise Exception("err_code = %d" % err_code)


class StructureMember(object):

    def __init__(self, sid, offset):
        self.__sid = sid
        self.__offset = offset

        if self.mid == -1:
            raise ValueError("Bad structure type ID is passed or there "
                             "is no member at the specified offset")

    def __str__(self):
        return "%s.%s @ 0x%X" % \
               (GetStrucName(self.__sid), self.name, self.offset)

    @property
    def name(self):
        return GetMemberName(self.__sid, self.__offset)

    @name.setter
    def name(self, value):
        if SetMemberName(self.__sid, self.__offset, value) == 0:
            print "SetMemberName(0x%X, 0x%X, '%s') has failed" \
                  % (self.__sid, self.__offset, value)

    @property
    def offset(self):
        return self.__offset

    @property
    def type(self):
        return GetType(self.mid)

    # @type.setter
    # def type(self, value):
    #     if not SetType(self.mid, "%s %s" % (value, self.name)):
    #         raise Exception("SetType() has failed")

    @property
    def gap(self):
        return self.name is None

    @property
    def mid(self):
        return GetMemberId(self.__sid, self.__offset)