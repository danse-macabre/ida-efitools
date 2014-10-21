from idaapi import *
from idautils import *
from idc import *


from core import project
from core.objects import *
from core.utils import *
from core.tracking import *


def update_structs_from_regs(function, **reg_struc):

    track = start_track(function,
                        dict((Register(reg), struc)
                             for reg, struc in reg_struc.items()),
                        types_to_track=(Register, Structure,
                                        StructureMember, Pointer),
                        allow_members=True)

    _update_structs_from_track(track)


def update_structs_from_xrefs(track_members=True):
    """
    Find xrefs to a struct pointer and change all the offsets to be struct offsets. This is useful for updating
    references to function pointers in EFI tables.

    For example:
    mov     rax, cs:qword_whatever
    call    qword ptr [rax+150h]

    Becomes:
    mov     rax, cs:gBootServices
    call    [rax+EFI_BOOT_SERVICES.UninstallMultipleProtocolInterfaces]
    """

    for seg_beg in filter(lambda x: getseg(x).type == SEG_DATA, Segments()):
        seg_end = SegEnd(seg_beg)
        head = NextHead(seg_beg, seg_end)
        while head != BADADDR:
            head_ptr = Pointer(head)
            if is_structure_type(head_ptr.type.rstrip(" *")):
                print "Updating structures for xref: %s" % head_ptr
                struc = Structure(head_ptr.type.rstrip(" *"))
                _update_from_ptr(head_ptr, struc, track_members)
            head = NextHead(head, seg_end)


def update_struct_from_lvar(start, lvar, struc, track_members=True):
    print "Working on lvar %s at 0x%X" % (lvar, start)
    track = start_track(start,
                        {lvar: struc},
                        types_to_track=(Register, Structure,
                                        StructureMember, LocalVariable),
                        allow_members=True)
    _update_structs_from_track(track)


def _update_from_ptr(ptr, struc, track_members):
    for xref in map(lambda x: Instruction(x), DataRefsTo(ptr.addr)):
        if xref.mnem == 'mov' and xref[0].type == o_reg and \
                xref[1].type == o_mem:
            if xref[0].type == o_reg:
                print "Working on xref: %s" % xref
                track = start_track(NextAddr(xref.ea),
                                    {xref[0].reg: struc},
                                    types_to_track=(Register, Structure,
                                                    StructureMember),
                                    allow_members=True)
                _update_structs_from_track(track)
            else:
                print "Skipping xref: %s" % xref


def _update_structs_from_track(track):
    for item, track in track:

        for op in item.operands():
            if op.type in [o_displ, o_phrase] and op.reg in track and \
                    isinstance(track[op.reg], Structure):
                if track[op.reg].dummy:
                    _guess_struct_field(item, op, track[op.reg])
                OpStroff(item.ea, op.n, track[op.reg].sid)

        for obj, state in track.items():

            if isinstance(obj, Pointer) and isinstance(state, Structure):
                obj.name = underscore_to_global(state.name)
                obj.type = state.name + " *"
                track.pop(obj)

            if isinstance(state, StructureMember):
                if state.type is not None and \
                        is_structure_type(state.type.rstrip(" *")):
                    struc = Structure(state.type.rstrip(" *"))
                    if isinstance(obj, Pointer):
                        obj.name = underscore_to_global(struc.name)
                        obj.type = struc.name + " *"
                    track[obj] = struc


def _guess_struct_field(item, op, struc):
    if op.displ_str is not None and not struc.dummy:
        return
    
    # if op.index_reg is not None:
    #     raise Exception("Look at this: 0x%X" % op.ea)

    member = find_object(struc.members(), offset=op.displ)
    if member is not None and not struc.dummy:
        return

    if item.mnem == 'call':
        member_size = 8
        member_name = "Method_%X" % op.displ

    elif item.mnem == 'lea' and op.n == 1:
        member_size = 1
        member_name = "Field_%X_lea" % op.displ

    else:
        another_op = item[abs(op.n - 1)]
        if another_op.type == o_reg:
            member_size = another_op.reg.size // 8
        else:
            for ptr_str, bit_size in PTR_SIZE_BITS.items():
                if ptr_str in str(another_op):
                    member_size = bit_size // 8
                    break
            else:
                print "Can not determine pointer type for %s" % op
                return
        member_name = "Field_%X" % op.displ

    struc.add_member(op.displ, member_name, member_size)

