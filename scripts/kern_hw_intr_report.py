from idautils import *
from idaapi import *
from idc import *
from ida_hexrays import *
import pprint

def get_disasm(head):
    disasm = GetDisasm(head).lower().lstrip().rstrip().replace(',',' ')
    if ';' in disasm:
        disasm = disasm[:disasm.index(';')]
    return tuple(disasm.split())

def get_integral_constant(constant):
    if constant.startswith('#'):
        constant = constant[1:]
    return int(constant, 0)

def is_maintenance_instruction(disasm):
    mnemonic = disasm[0]
    if mnemonic == 'mrs':
        assert len(disasm) == 3
        return disasm[2] == 'daif'
    elif mnemonic == 'msr':
        assert len(disasm) == 3
        return disasm[1].startswith('daif')
    else:
        return False

FUNCTIONS = { }
for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
        func_name = get_func_name(funcea)
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                disasm = get_disasm(head)
                if is_maintenance_instruction(disasm):
                    if func_name not in FUNCTIONS.keys():
                        FUNCTIONS[func_name] = { }
                    if disasm not in FUNCTIONS[func_name].keys():
                        FUNCTIONS[func_name][disasm] = 0
                    FUNCTIONS[func_name][disasm] += 1

pprint.pprint(FUNCTIONS)