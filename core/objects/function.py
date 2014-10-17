from itertools import islice, takewhile, dropwhile

from idaapi import *
from idautils import *
from idc import *

from .instruction import Instruction
from .structure import Structure


class Function:

    def __init__(self, ea):
        self.__start = FirstFuncFchunk(ea)
        if self.__start == BADADDR:
            raise ValueError("Can't get the first function chunk of the specified function")

    def __str__(self):
        return self.name

    def __repr__(self):
        return "Function(0x%X)" % self.__start

    def __hash__(self):
        return self.__start

    def __cmp__(self, other):
        if isinstance(other, Function):
            return cmp(self.start, other.start)
        raise NotImplementedError

    @property
    def start(self):
        return self.__start

    @property
    def frame(self):
        frame_id = GetFrame(self.__start)
        if frame_id is not None:
            return Structure(GetStrucName(frame_id), create_new=False)

    @property
    def name(self):
        return GetFunctionName(self.__start)

    def args(self):
        lvar_size = GetFrameLvarSize(self.__start) - 8  # exclude return address
        return iter(takewhile(lambda x: x < lvar_size, self.frame))

    def lvars(self):
        return iter(self.frame)

    def items(self, start=0, stop=None):
        if stop is None:
            stop = FindFuncEnd(self.__start)
        for item_ea in dropwhile(lambda x: x < start, FuncItems(self.__start)):
            if item_ea >= stop:
                break
            yield Instruction(item_ea)

    def grow_frame(self, lvsize=None, argregs=None, argsize=None):
        new_lvsize = GetFrameLvarSize(self.__start) \
            if lvsize is None else lvsize
        new_argregs = GetFrameRegsSize(self.__start) \
            if argregs is None else argregs
        new_argsize = GetFrameRegsSize(self.__start) \
            if argsize is None else argsize

        if MakeFrame(self.__start, new_lvsize, new_argregs, new_argsize) == -1:
            raise Exception("MakeFrame(0x%X, 0x%X, 0x%X, 0x%X) has failed" %
                            (self.__start, new_lvsize, new_argregs, new_argsize))