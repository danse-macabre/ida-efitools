from idaapi import *
from idautils import *
from idc import *

from core import project
from core.objects import *
from core.utils import *


def update_protocols():
    discovered_protocols = []

    for seg_beg in filter(lambda x: getseg(x).type == SEG_CODE, Segments()):
        seg_end = SegEnd(seg_beg)
        for function in map(lambda x: Function(x), Functions(seg_beg, seg_end)):
            protocols = _process_function(function)
            discovered_protocols.extend(protocols)

    return discovered_protocols


def _process_function(function):
    discovered_protocols = []

    for item in filter(lambda x: x.mnem == "call", function.items()):
        if item[0].type in [o_displ, o_phrase] and \
                item[0].stroff in _PROTOCOL_IMPORT_EXPORT_HANDLERS:
            method_handler, guid_reg, interface_reg = \
                _PROTOCOL_IMPORT_EXPORT_HANDLERS[item[0].stroff]
            protocol = method_handler(function, item, guid_reg, interface_reg)
            if protocol:
                discovered_protocols.append(protocol)

    return discovered_protocols


def _process_single_call(function, call_instr, guid_reg, interface_reg):
    reg_args = _get_call_lea_args(function, call_instr,
                                  guid_reg, interface_reg)

    if reg_args[guid_reg] is None:
        print "Can not determine GUID ptr: %s" % call_instr
        return

    if reg_args[interface_reg] is None:
        print "No interface argument found: %s" % call_instr

    guid = _prepare_guid(reg_args[guid_reg], project.export_protocol_name_prefix)
    if guid is None:
        return

    struc = _prepare_struc(guid)
    if struc is None:
        return

    interface = None
    if reg_args[interface_reg] is not None:
        interface = _prepare_interface(reg_args[interface_reg], struc.name,
                                       function, call_instr.ea)

    protocol = find_object(project.protocols, guid=guid)
    if protocol is None:
       project.protocols.register(guid, struc, interface, call_instr.ea, project.EXPORT_PROTOCOL)

    return protocol


def _process_install_multiple_call(function, call_instr):
    pass


def _get_call_lea_args(function, call_instr, *regs):
    reg_args = dict((reg, None) for reg in regs)

    for item in function.items(stop=call_instr.ea):
        if item.operands_num > 0 and item[0].type == o_reg and \
                item[0].reg.name_ex in reg_args:
            if item.mnem == 'lea':
                reg_args[item[0].reg.name_ex] = item[1]
            elif item.mnem not in ["cmp", "test"]:
                reg_args[item[0].reg.name_ex] = None

    return reg_args


def _prepare_guid(op, prefix):
    if op.type == o_mem:
        guid_ptr = Pointer(op.value)
        if guid_ptr.type != "GUID":
            guid_data1 = str("%.8x" % Dword(op.value)).upper()
            guid_ptr.name = "%s_PROTOCOL_%s_GUID" % (prefix, guid_data1)
    else:
        print "Do not know how to extract GUID ptr from %s at 0x%X" % (op, op.ea)
        return

    return GUID(ptr=guid_ptr)


def _prepare_struc(guid):
    if project.autogen_struct_prefix:
        struc_name = strip_end(guid.name.rstrip("_0123456789"), "_GUID")
    else:
        struc_name = strip_end(guid.name, "_GUID")
    return Structure(name=struc_name)


def _prepare_interface(op, struc_name, function, bind_point):
    if op.type == o_mem:
        ptr = Pointer(op.value)
        ptr.name = underscore_to_global(struc_name)
        ptr.type = struc_name + " *"
        return Interface(ptr, bind_point)
    elif op.type == o_displ:
        lvar_name = op.lvar
        if lvar_name is not None:
            lvar = find_object(function.lvars(), name=lvar_name)
            if lvar is not None:
                lvar.name = underscore_to_global(struc_name).lstrip('g')
                return Interface(lvar, bind_point)
            else:
                print "Lvar %s not found in function %s frame" % (lvar_name, function)
        else:
            print "Can not extract lvar name from %s at 0x%X" % (op, op.ea)
    else:
        print "Do not know how to extract interface from %s at 0x%X" % (op, op.ea)


_PROTOCOL_IMPORT_EXPORT_HANDLERS = {
    "EFI_BOOT_SERVICES.LocateProtocol": (_process_single_call, 'rcx', 'r8'),
    "EFI_SMM_RUNTIME_PROTOCOL.LocateProtocol": (_process_single_call, 'rcx', 'r8'),
    "EFI_BOOT_SERVICES.HandleProtocol": (_process_single_call, 'rdx', 'r8'),
    "EFI_BOOT_SERVICES.OpenProtocol": (_process_single_call, 'rdx', 'r8'),
    "EFI_BOOT_SERVICES.InstallProtocolInterface": (_process_single_call, 'rdx', 'r9'),
    "EFI_SMM_RUNTIME_PROTOCOL.InstallProtocolInterface": (_process_single_call, 'rdx', 'r9'),
    "EFI_BOOT_SERVICES.InstallMultipleProtocolInterfaces": (_process_install_multiple_call, None, None),
    "EFI_SMM_RUNTIME_PROTOCOL.InstallMultipleProtocolInterfaces": (_process_install_multiple_call, None, None),
}
