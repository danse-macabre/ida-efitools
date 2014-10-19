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
                        allow_members=True,
                        stubborn_tracking=True,
                        leave_comments=True)

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
    tracks = _create_tracks()
    tracks[lvar] = struc
    processed_functions = list()
    _update_structs_from_tracks(start, tracks, processed_functions,
                                track_members, stubborn_tracks=False)


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
                                    allow_members=True,
                                    stubborn_tracking=False,
                                    leave_comments=True)
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


def _update_structs_from_tracks(start, tracks, processed_functions,
                                track_members, stubborn_tracks):
    rsp = [Register('rsp')]
    preserved_tracks = {}

    try:
        function = Function(start)
    except ValueError:
        print "Attempt to update structure " \
              "offsets in non-function at 0x%X" % start
        return

    if function in processed_functions:
        #print "Leaving already processed function %s" % function
        return

    processed_functions.append(function)

    for item in function.items(start):

        # Track rsp copies
        if item.mnem == 'mov' and item[0].type == o_reg and \
                item[1].type == o_reg and item[1].reg in rsp:
            rsp.append(item[0].reg)

        # Update any instruction with a displacement from our register
        for op in item.operands():
            if op.type in [o_displ, o_phrase] and tracks.get(op.reg):
                if tracks[op.reg].dummy:
                    _guess_struct_field(item, op, tracks[op.reg])
                OpStroffEx(item.ea, op.n, tracks[op.reg].sid, 0)

        if item.mnem == 'mov':

            # mov o_reg, o_reg
            if item[0].type == o_reg and item[1].type == o_reg:
                tracks.update({item[0].reg: tracks[item[1].reg]})
                if tracks.get(item[0].reg) is not None:
                    comm = "%s <- %s" % (item[0].reg, tracks[item[1].reg])
                    MakeComm(item.ea, comm)

            # mov o_mem, o_reg
            elif item[0].type == o_mem and item[1].type == o_reg:
                if tracks.get(item[1].reg) is not None:
                    ptr = Pointer(item[0].value)
                    struc = tracks[item[1].reg]
                    ptr.name = underscore_to_global(struc.name)
                    ptr.type = struc.name + " *"
                    pass

            # mov o_reg, o_mem
            elif item[0].type == o_reg and item[1].type == o_mem:
                ptr = Pointer(item[1].value)
                ptr_base_type = ptr.type.rstrip(" *")
                if stubborn_tracks and is_structure_type(ptr_base_type):
                    struc = Structure(ptr_base_type, create_new=False)
                    tracks.update({item[0].reg: struc})
                else:
                    tracks.update({item[0].reg: None})

            # mov o_reg, [o_displ|o_phrase]
            elif item[0].type == o_reg and item[1].type in [o_displ, o_phrase]:
                if item[0].reg in rsp:
                    rsp.remove(item[0].reg)
                if item[1].reg in rsp:
                    lvar = find_object(function.frame.lvars(), name=item[1].displ_str)
                    tracks.update({item[0].reg: tracks.get(lvar)})
                if tracks.get(item[1].reg) is not None and track_members:
                    base_struc = tracks[item[1].reg]
                    off = item[1].displ
                    member = find_object(base_struc.members(), offset=off)
                    if member and member.type is not None and \
                            is_structure_type(member.type.rstrip(" *")):
                        tracks.update({item[0].reg:
                                      Structure(member.type.rstrip(" *"))})

            # mov [o_displ|o_phrase], o_reg
            elif item[0].type in [o_displ, o_phrase] and item[1].type == o_reg:
                if item[0].reg in rsp:
                    lvar = find_object(function.frame.lvars(), name=item[0].displ_str)
                    if lvar is not None:
                        tracks.update({lvar: tracks[item[1].reg]})
                        if tracks[item[1].reg] is not None:
                            lvar.name = \
                                underscore_to_global(tracks[item[1].reg].name)\
                                .lstrip("g")
                else:
                    pass  # Nothing to do here

            # mov o_reg, whatever
            elif item[0].type == o_reg:
                tracks.update({item[0].reg: None})

        elif item.mnem == 'lea':

            # lea o_reg, whatever
            if item[0].type == o_reg:
                tracks.update({item[0].reg: None})

            # lea [o_displ|o_phrase], whatever
            if item[0].type in [o_displ, o_phrase]:
                if item[0].reg in rsp:
                    lvar = find_object(function.frame.lvars(), name=item[0].displ_str)
                    if lvar is not None:
                        tracks.update({lvar: None})

        elif item.mnem == 'call':
            if item[0].type in [o_imm, o_far, o_near]:
                _preserve_tracks(tracks, preserved_tracks)
                _update_structs_from_tracks(item[0].value, tracks, processed_functions,
                                            track_members, stubborn_tracks)
                _restore_tracks(tracks, preserved_tracks)
            else:
                for reg in filter(lambda x: isinstance(x, Register), tracks):
                    if reg.volatile:
                        tracks[reg] = None

        elif item.mnem not in ['cmp', 'test'] and item.operands_num > 0:

            # mnem o_reg, whatever
            if item[0].type == o_reg and item[0].reg is not None:
                tracks.update({item[0].reg: None})

            # mnem [o_displ|o_phrase], whatever
            if item[0].type in [o_displ, o_phrase]:
                if item[0].reg is not None and item[0].reg in rsp:
                    lvar = find_object(function.frame.lvars(), name=item[0].displ_str)
                    if lvar is not None:
                        tracks.update({lvar: None})

        if not (stubborn_tracks or any(tracks.values())):
            # print "Lost tracks at 0x%X in %s" % (item.ea, function)
            break


def _preserve_tracks(tracks, preserved_tracks):
    preserved_tracks = {}
    for track in tracks:
        if isinstance(track, Register):
            if not track.volatile:
                preserved_tracks.update({track: tracks[track]})
        elif isinstance(track, LocalVariable):
            preserved_tracks.update({track: tracks[track]})


def _restore_tracks(tracks, preserved_tracks):
    for track in preserved_tracks:
        tracks.update({track: preserved_tracks[track]})


def _create_tracks():
    return dict((Register(reg), None) for reg in Register.REGS)


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

