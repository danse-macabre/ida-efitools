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
        return _OperandType(GetOpType(self.__ea, self.__n))

    @property
    def value(self):
        # operand is an immediate value  => immediate value
        # operand has a displacement     => displacement
        # operand is a direct memory ref => memory address
        # operand is a register          => register number
        # operand is a register phrase   => phrase number
        # otherwise                      => -1
        value = GetOperandValue(self.__ea, self.__n)
        if value == -1:
            raise Exception("GetOperandValue() for %s has failed" % self)
        return value

    @property
    def reg(self):
        if self.type == o_reg and str(self) != "":
            return Register(str(self))
        elif self.type in [o_phrase, o_displ] and str(self) != "":
            name = _REG_FROM_DISPL_RE.match(str(self)).group(1)
            return Register(name)
        else:
            return None

    @property
    def displ(self):
        if self.type == o_displ:
            return self.value
        elif self.type == o_phrase:
            return 0
        else:
            return None

    @property
    def index_reg(self):
        if "(" in str(self):
            return None
        try:
            return _INDEX_REG_FROM_PHRASE_RE.match(str(self)).group(1)
        except AttributeError:
            return None

    @property
    def displ_str(self):
        if "(" in str(self):
            return None
        try:
            return _DISPL_STR_FROM_DISPL_RE.match(str(self)).group(2)
        except AttributeError:
            return None


class _OperandType:

    def __init__(self, op_type):
        self.__op_type = op_type

    def __str__(self):
        return _OP_TYPE_STR[self.__op_type]

    def __repr__(self):
        return "_OperandType(%d)" % self.__op_type

    def __hash__(self):
        return self.__op_type

    def __cmp__(self, other):
        if isinstance(other, _OperandType):
            return cmp(self.__op_type, other.__op_type)
        elif type(other) is int:
            return cmp(self.__op_type, other)
        raise NotImplementedError


_REG_FROM_DISPL_RE = re.compile(r'.*\[([a-z0-9]*)')
_INDEX_REG_FROM_PHRASE_RE = re.compile(r'.*\[[a-z0-9]*([\+\-].*?)[\+\-]+')
_DISPL_STR_FROM_DISPL_RE = re.compile(r'.*?\[.*?([\+\-].*)?[\+\-](.*)\]')
# _OFF_FROM_DISPL_RE = re.compile(r'.*?\[.*?([\+\-].*?)]')
# _LVAR_FROM_DISPL_RE = re.compile(r'.*?\[\w*([\+\-][0-9A-F]*h?)?[\+\-]([\w\.]*)\]')

_OP_TYPE_STR = {
    0: "o_void",
    1: "o_reg",
    2: "o_mem",
    3: "o_phrase",
    4: "o_displ",
    5: "o_imm",
    6: "o_far",
    7: "o_near",
}