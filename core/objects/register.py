REG_SIZE = {
    "rax": 64, "eax": 32, "ax": 16, "al": 8,
    "rbx": 64, "ebx": 32, "bx": 16, "bl": 8,
    "rcx": 64, "ecx": 32, "cx": 16, "cl": 8,
    "rdx": 64, "edx": 32, "dx": 16, "dl": 8,
    "rsi": 64, "esi": 32, "si": 16, "sil": 8,
    "rdi": 64, "edi": 32, "di": 16, "dil": 8,
    "rbp": 64, "ebp": 32, "bp": 16, "bpl": 8,
    "rsp": 64, "esp": 32, "sp": 16, "spl": 8,
    "r8": 64, "r8d": 32, "r8w": 16, "r8b": 8,
    "r9": 64, "r9d": 32, "r9w": 16, "r9b": 8,
    "r10": 64, "r10d": 32, "r10w": 16, "r10b": 8,
    "r11": 64, "r11d": 32, "r11w": 16, "r11b": 8,
    "r12": 64, "r12d": 32, "r12w": 16, "r12b": 8,
    "r13": 64, "r13d": 32, "r13w": 16, "r13b": 8,
    "r14": 64, "r14d": 32, "r14w": 16, "r14b": 8,
    "r15": 64, "r15d": 32, "r15w": 16, "r15b": 8,
    "fs": 64, "gs": 64, "cs": 64, "ss": 64, "ds": 64, "es": 64
}

REG_GROUPS = (
    ("rax", "eax", "ax", "al",),
    ("rbx", "ebx", "bx", "bl",),
    ("rcx", "ecx", "cx", "cl",),
    ("rdx", "edx", "dx", "dl",),
    ("rsi", "esi", "si", "sil",),
    ("rdi", "edi", "di", "dil",),
    ("rbp", "ebp", "bp", "bpl",),
    ("rsp", "esp", "sp", "spl",),
    ("r8", "r8d", "r8w", "r8b",),
    ("r9", "r9d", "r9w", "r9b",),
    ("r10", "r10d", "r10w", "r10b",),
    ("r11", "r11d", "r11w", "r11b",),
    ("r12", "r12d", "r12w", "r12b",),
    ("r13", "r13d", "r13w", "r13b",),
    ("r14", "r14d", "r14w", "r14b",),
    ("r15", "r15d", "r15w", "r15b",),
    ('fs',),
    ('gs',),
    ('cs',),
    ('ss',),
    ('ds',),
    ('es',),
)

REG_VOLATILE = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
REG_NONVOLATILE = ("rbx", "rsi", "rdi", "rbp", "rsp", "r12", "r13", "r14", "r15")


class Register:

    REGS = tuple(reg_group[0] for reg_group in REG_GROUPS)

    def __init__(self, name):
        for reg_group in REG_GROUPS:
            if name in reg_group:
                self.__name = reg_group[0]
                break
        else:
            raise ValueError("Invalid register: %s" % name)

        self.__size = REG_SIZE[name]
        self.__name_ex = name

    def __str__(self):
        return self.__name_ex

    def __repr__(self):
        return "Register('%s')" % self.__name_ex

    def __hash__(self):
        return self.REGS.index(self.name)

    def __cmp__(self, other):
        if isinstance(other, Register):
            return cmp(self.name, other.name)
        raise NotImplementedError(other.__class__)

    @property
    def name(self):
        return self.__name

    @property
    def size(self):
        return self.__size

    @property
    def name_ex(self):
        return self.__name_ex

    @property
    def size_bytes(self):
        return self.__size // 8

    @property
    def volatile(self):
        return self.name in REG_VOLATILE