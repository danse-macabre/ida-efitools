from ConfigParser import ConfigParser
from itertools import repeat
from uuid import UUID

from idaapi import *
from idautils import *
from idc import *

from core.objects import GUID, Pointer


def update_guids(path_to_db):
    _load_guids_db(path_to_db)
    for seg_beg in filter(lambda x: getseg(x).type == SEG_DATA, Segments()):
        seg_end = SegEnd(seg_beg)
        _process_segment(seg_beg, seg_end)


def _process_segment(seg_beg, seg_end):
    for addr in range(seg_beg, seg_end, 8):
        guid_bytes_le = get_many_bytes(addr, _GUID_SIZE)
        if guid_bytes_le != _zero_guid_bytes and guid_bytes_le != _ffff_guid_bytes:
            guid_name = _guids_db.get(guid_bytes_le, None)
            if guid_name:
                GUID(addr=addr, name=guid_name)


_zero_guid_bytes = b''.join(repeat(b'\x00', 16))
_ffff_guid_bytes = b''.join(repeat(b'\xFF', 16))
_guids_db = dict()

_GUID_SIZE = 16


def _load_guids_db(path_to_db):
    parser = ConfigParser()

    if not parser.read(path_to_db):
        raise IOError("Can not read %s" % path_to_db)

    for section in parser.sections():
        for guid_name, guid_hex in parser.items(section):
            _guids_db.update({UUID(hex=guid_hex).bytes_le: guid_name.upper()})