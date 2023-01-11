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
    if mnemonic == 'dc':
        return True
    elif mnemonic == 'ic':
        return True
    elif mnemonic == 'tlbi':
        return True
    elif mnemonic == 'dsb':
        return True
    elif mnemonic == 'dmb':
        return True
    elif mnemonic == 'isb':
        return True
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