from idaapi import *
from idautils import *
from idc import *

from core import project
from core.objects import *
from core.utils import *


def start_track(start, track, types_to_track, **kwargs):
    skip_functions = []
    for item, track in _do_track(start, track, types_to_track,
                                 skip_functions, **kwargs):
        yield item, track


def _do_track(start, track, types_to_track, skip_functions, **kwargs):
    allow_members = kwargs.get('allow_members', False)
    die_hard = kwargs.get('die_hard', False)

    try:
        function = Function(start)
    except ValueError:
        print "Attempt to track objects in non-function at 0x%X" % start
        return

    if function in skip_functions:
        return

    skip_functions.append(function)

    rsp = [Register('rsp')]
    has_jumps = False

    for item in function.items(start):

        yield item, track

        if item.mnem == 'mov':

            # mov o_reg, o_reg
            if item[0].type == o_reg and item[1].type == o_reg:
                if item[1].reg in rsp:
                    rsp.append(item[0].reg)
                _update_track(track, item[0].reg, track.get(item[1].reg))

            # mov o_mem, o_reg
            elif item[0].type == o_mem and item[1].type == o_reg:
                if item[1].reg in track:
                    _update_track(track, Pointer(item[0].value), item[1].reg)

            # mov o_reg, o_mem
            elif item[0].type == o_reg and item[1].type == o_mem:
                if Pointer in types_to_track:
                    _update_track(track, item[0].reg, Pointer(item[1].value))

            # mov o_reg, [o_displ|o_phrase]
            elif item[0].type == o_reg and item[1].type in [o_displ, o_phrase]:
                if item[0].reg in rsp:
                    rsp.remove(item[0].reg)
                if item[1].reg in rsp:
                    lvar = find_object(function.frame, name=item[1].displ_str)
                    _update_track(track, item[0].reg, lvar)
                if allow_members and item[1].reg in track and \
                        isinstance(track[item[1].reg], Structure) and \
                        StructureMember in types_to_track:
                    member = find_object(track[item[1].reg].members(),
                                         offset=item[1].displ)
                    _update_track(track, item[0].reg, member)

            # mov [o_displ|o_phrase], o_reg
            elif item[0].type in [o_displ, o_phrase] and item[1].type == o_reg:
                if item[0].reg in rsp:
                    lvar = find_object(function.frame, name=item[0].displ_str)
                    if lvar is not None:
                        _update_track(track, lvar, item[1].reg)

            # mov o_reg, o_imm
            elif item[0].type == o_reg and item[1].type == o_imm:
                _update_track(track, item[0].reg,
                              ImmediateValue(item[1].value))

            # mov [o_displ|o_phrase], o_imm
            elif item[0].type in [o_displ, o_phrase] and item[1].type == o_reg:
                if item[0].reg in rsp:
                    lvar = find_object(function.frame, name=item[0].displ_str)
                    if lvar is not None:
                        _update_track(track, lvar, ImmediateValue(item[1].value))

        elif item.mnem == 'lea':

            # lea o_reg, whatever
            if item[0].type == o_reg:
                _update_track(track, item[0].reg, EffectiveAddr(item[1]))

            # lea [o_displ|o_phrase], whatever
            if item[0].type in [o_displ, o_phrase]:
                if item[0].reg in rsp:
                    lvar = find_object(function.frame, name=item[0].displ_str)
                    if lvar is not None:
                        _update_track(track, lvar, EffectiveAddr(item[1]))

        elif item.mnem == 'call':
            if item[0].type in [o_imm, o_far, o_near]:
                preserved = _preserve_track(track)
                callee_track = _build_callee_track(track)
                for item, track in _do_track(item[0].value, callee_track,
                                             types_to_track, skip_functions,
                                             **kwargs):
                    yield item, track
                _restore_track(track, preserved)
            else:
                _purge_volatile_states(track)

        elif item.mnem == 'jmp':
            has_jumps = True

        # Workarounds for some special trivial cases
        else:

            if item.mnem == 'xor' and item[0].type == o_reg and \
                    item[1].type == o_reg:
                _update_track(track, item[0].reg, ImmediateValue(0))

            if item.mnem == 'and' and item[1].type == o_imm and \
                    item[1].value == 0:
                if item[0].type == o_reg:
                    _update_track(track, item[0].reg, 0)
                elif item[0].type in [o_displ, o_phrase]:
                    if item[0].reg in rsp:
                        lvar = find_object(function.frame, name=item[0].displ_str)
                        if lvar is not None:
                            _update_track(track, lvar, ImmediateValue(0))

        if not (die_hard or any(map(lambda x: x.__class__ in
                                    types_to_track, track))):
            break

    if has_jumps:
        _purge_volatile_states(track)

    _purge_local_variables(track)


def _update_track(track, old, new):
    if not isinstance(new, ImmediateValue) and \
            new in track:
        track[old] = track[new]
    elif new is not None:
        track[old] = new
    elif old in track:
        track.pop(old)


def _preserve_track(track):
    preserved = dict()
    for obj, state in track.items():
        if isinstance(obj, Register):
            if not obj.volatile:
                preserved[obj] = state
        elif isinstance(obj, LocalVariable):
            preserved[obj] = state
    return preserved


def _purge_volatile_states(track):
    for obj in filter(lambda x: isinstance(x, Register) and x.volatile, track):
        _update_track(track, obj, None)


def _purge_local_variables(track):
    for obj in filter(lambda x: isinstance(x, LocalVariable), track):
        _update_track(track, obj, None)


def _restore_track(track, preserved):
    for obj, state in preserved.items():
        track[obj] = state


def _build_callee_track(track):
    callee_track = dict()
    for obj in filter(lambda x: not isinstance(x, LocalVariable), track):
        callee_track[obj] = track[obj]
    return callee_track


def _make_comment(track, item, left, right):
    if right is not None:
        MakeComm(item.ea, "%s <- %s" % (left, right))