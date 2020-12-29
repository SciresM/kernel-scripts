from idautils import *
from idaapi import *
from idc import *
from ida_hexrays import *
from ida_frame import *
from ida_struct import *

class x18_modifier_t(user_lvar_modifier_t):
    def __init__(self, funcea):
        user_lvar_modifier_t.__init__(self)
        self.funcea = funcea
        
    def modify_lvars(self, lvars):
        found = False
        tif = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(tif, None, 'KThread *;', 0)
        for idx, var in enumerate(lvars.lvvec):
            if var.ll.is_reg_var() and var.ll.get_reg1() == 152:
                found = True
                var.type = tif
                var.name = 'cur_thread'
                break
        if not found:
            v = lvar_saved_info_t()
            v.name = 'cur_thread'
            v.type = tif
            v.size = -1
            loc = vdloc_t()
            loc.set_reg1(152)
            v.ll = lvar_locator_t(loc, self.funcea)
            lvars.lvvec.append(v)
        return True

def ProcessFunction(ea):
    func = get_func(ea)
    name = get_func_name(ea)
    for v in decompile(ea).get_lvars():
        if v.location.is_reg() and v.location.reg1() == 152:
            if v.name != 'cur_thread':
                modify_user_lvars(ea, x18_modifier_t(ea))
                break
    for v in decompile(ea).get_lvars():
        if v.location.is_reg() and v.location.reg1() == 152:
            assert v.name == 'cur_thread'
    

for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
        ProcessFunction(funcea)