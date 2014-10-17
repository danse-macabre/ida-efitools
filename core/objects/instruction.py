import re
from itertools import count

from idaapi import *
from idautils import *
from idc import *

from .register import Register


class Instruction:
    
    def __init__(self, ea):
        self.__ea = ea

    def __getitem__(self, item):
        if GetOpType(self.__ea, item) not in [o_void, -1]:
            return _Operand(self.__ea, item)
        return None

    def __str__(self):
        return "%s @ 0x%X" % (GetDisasm(self.__ea), self.__ea)

    def __repr__(self):
        return "Instruction(0x%X)" % self.__ea

    @property
    def ea(self):
        return self.__ea

    @property
    def mnem(self):
        return GetMnem(self.__ea)

    @property
    def operands_num(self):
        if GetOpType(self.__ea, 0) == o_void:
            return 0
        if GetOpType(self.__ea, 1) == o_void:
            return 1
        return 2

    def operands(self):
        for op_n in count():
            op = self[op_n]
            if op is not None:
                yield op
            else:
                break


class _Operand:

    def __init__(self, ea, n):
        self.__ea = ea
        self.__n = n

        if self.type == o_reg and str(self) != "":
            self.__reg = Register(str(self))
        elif self.type in [o_phrase, o_displ] and str(self) != "":
            name = _REG_FROM_DISPL_RE.match(str(self)).group(1)
            self.__reg = Register(name)
        else:
            self.__reg = None


    def __str__(self):
        return GetOpnd(self.__ea, self.__n)

    def __repr__(self):
        return "_InstructionOperand(0x%X, %d)" % (self.__ea, self.__n)

    def __hash__(self):
        return hash(self.__ea)

    @property
    def ea(self):
        return self.__ea

    @property
    def n(self):
        return self.__n

    @property
    def type(self):
        return GetOpType(self.__ea, self.__n)

    @property
    def value(self):
        return GetOperandValue(self.__ea, self.__n)

    @property
    def reg(self):
        return self.__reg

    @property
    def displ(self):
        if self.type == o_displ:
            value = self.value
            off_str = _OFF_FROM_DISPL_RE.match(str(self)).group(1)
            if off_str.startswith("-"):
                value *= -1
            return value
        if self.type == o_phrase:
            try:
                return _OFF_FROM_DISPL_RE.match(str(self)).group(1)
            except AttributeError:
                return 0
        else:
            return None

    @property
    def lvar(self):
        if self.type == o_displ:
            try:
                return _LVAR_FROM_DISPL_RE.match(str(self)).group(2)
            except AttributeError:
                pass
        return None

    @property
    def stroff(self):
        if self.type in [o_displ, o_phrase]:
            try:
                return _LVAR_FROM_DISPL_RE.match(str(self)).group(2)
            except AttributeError:
                pass
        return None

_REG_FROM_DISPL_RE = re.compile(r'.*\[([a-z0-9]*)')
_OFF_FROM_DISPL_RE = re.compile(r'.*?\[.*?([\+\-].*?)]')
_LVAR_FROM_DISPL_RE = re.compile(r'.*?\[\w*([\+\-][0-9A-F]*h?)?[\+\-]([\w\.]*)\]')
