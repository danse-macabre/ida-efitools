import guids
import structures
import protocols

reload(guids)
reload(structures)
reload(protocols)

from guids import update_guids
from structures import update_structs_from_regs, \
    update_structs_from_xrefs, update_struct_from_lvar
from protocols import update_protocols