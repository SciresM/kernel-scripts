from idautils import *
from idaapi import *
from idc import *
from ida_hexrays import *

SMC_CALLING_CONVENTION = '__usercall __spoils<X1, X2, X3, X4, X5, X6, X7>'

def make_smc_prototype_args(args):
    if len(args) == 0:
        return 'void'
    return ', '.join('%s@<X%d>' % (arg,i+1) for i,arg in enumerate(args))

def make_smc_prototype(name, *args):
    return '_DWORD %s smc_%s@<X0>(%s);' % (SMC_CALLING_CONVENTION, name, make_smc_prototype_args(list(args)))

PRIV_SMCS = {
    0xC4000001 : make_smc_prototype('cpu_suspend', '_QWORD power_state', '_QWORD entrypoint', '_QWORD context_id'),
    0x84000002 : make_smc_prototype('cpu_off'),
    0xC4000003 : make_smc_prototype('cpu_on', '_QWORD core_id', '_QWORD entrypoint', '_QWORD context_id'),
    0xC3000004 : make_smc_prototype('get_config', '_QWORD which'),
    0xC3000005 : make_smc_prototype('generate_random_bytes', '_QWORD size'),
    0xC3000006 : make_smc_prototype('panic', '_QWORD color'),
    0xC3000007 : make_smc_prototype('configure_carveout', '_QWORD which', '_QWORD address', '_QWORD size'),
    0xC3000008 : make_smc_prototype('read_write_register', '_QWORD address', '_DWORD mask', '_DWORD value'),
}

def get_integral_constant(constant):
    if constant.startswith('#'):
        constant = constant[1:]
    return int(constant, 0)

def get_smc(head):
    disasm = GetDisasm(head).lower()
    if 'smc ' not in disasm:
        return None
    disasm = disasm[disasm.index('smc ')+3:].lstrip()
    if ' ' in disasm:
        disasm = disasm[:disasm.index(' ')]
    if ';' in disasm:
        disasm = disasm[:disasm.index(';')]
    return get_integral_constant(disasm)

def get_mov_constant(startea, h, head, regs):
    disasm = GetDisasm(head).lower().lstrip().rstrip().replace(',',' ')
    if ';' in disasm:
        disasm = disasm[:disasm.index(';')]
    disasm = disasm.split()
    if len(disasm) < 2:
        return None
    if disasm[1] in regs:
        if disasm[0] in ['cbz', 'cbnz']:
            return None
        elif disasm[0] in ['mrs', 'add', 'sub', 'and', 'orr', 'ldr']:
            return -1
        print '%X' % head
        assert disasm[0] == 'mov' and len(disasm) == 3
        if disasm[2].startswith('#'):
            return get_integral_constant(disasm[2])
        else:
            print disasm[2]
            assert disasm[2].startswith('x')
            mov_constant = None
            for new_head in Heads(startea, h):
                if new_head >= mov_head:
                    return mov_constant
                cur_mov_constant = get_mov_constant(startea, head, mov_head, [disasm[2], disasm[2].replace('x','w')])
                if cur_mov_constant != None:
                    mov_constant = cur_mov_constant
            return mov_constant
    return None

for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):
        udc_map = udcall_map_new()
        restore_user_defined_calls(udc_map, funcea)
        func_name = get_func_name(funcea)
        for (startea, endea) in Chunks(funcea):
            for head in Heads(startea, endea):
                smc = get_smc(head)
                if smc == 0:
                    print '%s: 0x%x Found User SMC, currently not supported' % (func_name, head)
                elif smc == 1:
                    mov_constant = None
                    for mov_head in Heads(startea, head):
                        cur_mov_constant = get_mov_constant(startea, head, mov_head, ['x0', 'w0'])
                        if cur_mov_constant != None:
                            mov_constant = cur_mov_constant
                    if mov_constant == None:
                        print '%s: 0x%x Found Priv SMC with unknown constant' % (func_name, head)
                    elif mov_constant not in PRIV_SMCS.keys():
                        print '%s: 0x%x Found Priv SMC with unknown constant %x' % (func_name, head, mov_constant)
                    else:
                        print '%s: 0x%x Found Priv SMC' % (func_name, head)
                        existing = udcall_map_find(udc_map, head)
                        if existing != udcall_map_end(udc_map):
                            udcall_map_erase(udc_map, existing)
                        c = udcall_t()
                        parse_user_call(c, PRIV_SMCS[mov_constant], False)
                        udcall_map_insert(udc_map, head, c)
                elif smc is not None:
                    print 'Found unknown SMC (%d)' % smc
        save_user_defined_calls(funcea, udc_map)