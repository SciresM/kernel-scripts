from idautils import *
from idaapi import *
from idc import *
from ida_hexrays import *

def get_disasm(head):
    disasm = GetDisasm(head).lower().lstrip().rstrip().replace(',',' ')
    if ';' in disasm:
        disasm = disasm[:disasm.index(';')]
    return disasm.split()

def get_integral_constant(constant):
    if constant.startswith('#'):
        constant = constant[1:]
    return int(constant, 0)

def get_udc(head):
    disasm = get_disasm(head)
    mnem = disasm[0]
    if mnem == 'dc':
        assert len(disasm) == 3
        assert disasm[2].startswith('x')
        return 'void __usercall __dc_%s(_QWORD address@<%s>);' % (disasm[1], disasm[2])
    elif mnem == 'tlbi':
        if len(disasm) == 3:
            assert disasm[2].startswith('x')
            return 'void __usercall __tlbi_%s(_QWORD address@<%s>);' % (disasm[1], disasm[2])
        elif len(disasm) == 2:
            return 'void __tbli_%s();' % disasm[1]
    elif mnem == 'ic':
        if len(disasm) == 3:
            assert disasm[1] == 'ivau'
            assert disasm[2].startswith('x')
            return 'void __usercall __ic_%s(_QWORD address@<%s>);' % (disasm[1], disasm[2])
        else:
            assert len(disasm) == 2
            return 'void __ic_%s();' % disasm[1]
    elif mnem == 'dsb':
        assert len(disasm) == 2
        if disasm[1] not in ['sy', 'ish', 'ishst', 'ishld']:
            print disasm[1]
        assert disasm[1] in ['sy', 'ish', 'ishst', 'ishld']
        return 'void __dsb_%s();' % disasm[1]
    elif mnem == 'prfm':
        assert len(disasm) == 3
        assert len(disasm[2]) in [4, 5] and disasm[2].startswith('[x') and disasm[2].endswith(']')
        assert disasm[1] == '#0x10'
        return 'void __usercall __prefetch_memory_pstl1keep(void *address@<%s>);' % (disasm[2][1:-1])
    elif mnem == 'ldtr':
        if len(disasm) == 3 and len(disasm[2]) in [4, 5] and disasm[2].startswith('[x') and disasm[2].endswith(']'):
            assert disasm[1][0] in ['w', 'x']
            if disasm[1].startswith('w'):
                return 'uint32_t __usercall __ldtr@<%s>(uint32_t *address@<%s>);' % (disasm[1], disasm[2][1:-1])
            elif disasm[1].startswith('x'):
                return 'uint64_t __usercall __ldtr@<%s>(uint64_t *address@<%s>);' % (disasm[1], disasm[2][1:-1])
        else:
            # how to handle ldtr ?, [x#, #0x?]?
            assert len(disasm) == 4
            pass
    return None

for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
        udc_map = udcall_map_new()
        restore_user_defined_calls(udc_map, funcea)
        func_name = get_func_name(funcea)
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                udc = get_udc(head)
                if udc != None:
                    existing = udcall_map_find(udc_map, head)
                    if existing != udcall_map_end(udc_map):
                        udcall_map_erase(udc_map, existing)
                    c = udcall_t()
                    parse_user_call(c, udc, False)
                    udcall_map_insert(udc_map, head, c)
                    decompile(funcea)
        save_user_defined_calls(funcea, udc_map)