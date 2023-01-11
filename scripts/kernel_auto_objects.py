from idautils import *
from idaapi import *
from ida_name import *
from idc import *
from ida_hexrays import *
from ida_frame import *
from ida_struct import *

INHERITANCE = {
    # Auto Object base classes.
    'KAutoObject' : None,
    'KAutoObjectWithList'                       : 'KAutoObject',
    'KAutoObjectWithListAllocatorAdapter'       : 'KAutoObjectWithList',
    'KSynchronizationObject'                    : 'KAutoObjectWithList',
    'KSynchronizationObjectAllocatorAdapter'    : 'KSynchronizationObject',
    'KReadableEvent'                            : 'KSynchronizationObject',
    'KReadableEventAllocatorAdapter'            : 'KReadableEvent',
    'KDebugBase'                                : 'KSynchronizationObject',
    'KDebugBaseAllocatorAdapter'                : 'KDebugBase',

    # Auto Object final classes
    'KClientPort'           : 'KSynchronizationObject',
    'KClientSession'        : 'KAutoObject',
    'KCodeMemory'           : 'KAutoObjectWithListAllocatorAdapter',
    'KDebug'                : 'KDebugBaseAllocatorAdapter',
    'KDeviceAddressSpace'   : 'KAutoObjectWithListAllocatorAdapter',
    'KSystemResource'       : 'KAutoObject',
    'KEvent'                : 'KAutoObjectWithListAllocatorAdapter',
    'KInterruptEvent'       : 'KReadableEventAllocatorAdapter',
    'KLightClientSession'   : 'KAutoObject',
    'KLightServerSession'   : 'KAutoObject',
    'KLightSession'         : 'KAutoObjectWithListAllocatorAdapter',
    'KPort'                 : 'KAutoObjectWithListAllocatorAdapter',
    'KProcess'              : 'KSynchronizationObjectAllocatorAdapter',
    'KResourceLimit'        : 'KAutoObjectWithListAllocatorAdapter',
    'KServerPort'           : 'KSynchronizationObject',
    'KServerSession'        : 'KSynchronizationObject',
    'KSession'              : 'KAutoObjectWithListAllocatorAdapter',
    'KSessionRequest'       : 'KAutoObject',
    'KSharedMemory'         : 'KAutoObjectWithListAllocatorAdapter',
    'KThread'               : 'KSynchronizationObjectAllocatorAdapter',
    'KTransferMemory'       : 'KAutoObjectWithListAllocatorAdapter',
    'KIoPool'               : 'KAutoObjectWithListAllocatorAdapter',
    'KIoRegion'             : 'KAutoObjectWithListAllocatorAdapter',
}

CLASS_TOKENS = {
  #'KAutoObject'            : 0x0,
  'KClientSession'         : 0xD00,
  'KResourceLimit'         : 0x2500,
  'KLightSession'          : 0x4500,
  'KPort'                  : 0x8500,
  'KSession'               : 0x1900,
  'KSharedMemory'          : 0x2900,
  'KSystemResource'        : 0x4600,
  'KEvent'                 : 0x4900,
  'KLightClientSession'    : 0x8900,
  'KLightServerSession'    : 0x3100,
  'KTransferMemory'        : 0x5100,
  'KDeviceAddressSpace'    : 0x9100,
  'KSessionRequest'        : 0x6100,
  'KCodeMemory'            : 0xA100,
  'KIoPool'                : 0xC100,
  'KIoRegion'              : 0xE00,

  'KSynchronizationObject' : 0x1,
  'KDebug'                 : 0xB01,
  'KThread'                : 0x1301,
  'KServerPort'            : 0x2301,
  'KServerSession'         : 0x4301,
  'KClientPort'            : 0x8301,
  'KProcess'               : 0x1501,

  'KReadableEvent'         : 0x3,
  'KInterruptEvent'        : 0x703,
}

INVERSE_CLASS_TOKENS = {v : k for k,v in CLASS_TOKENS.items()}

def MakeClassFunction(ret, name):
    return (name, lambda cn: '%s %s::%s(%s *__hidden this)' % (ret, cn, name, cn), lambda cn: '%s::%s' % (cn, name))

def MakeClassFunctionWithArgs(ret, name, *args):
    if len(args) == 0:
        return MakeClassFunction(ret, name)
    else:
        return (name, lambda cn: '%s %s::%s(%s *__hidden this, %s)' % (ret, cn, name, cn, ', '.join(args)), lambda cn: '%s::%s' % (cn, name))

VTABLES = {
    # Auto Object base classes.
    'KAutoObject' : [
        MakeClassFunction('void',           'Destroy'),
        MakeClassFunction('void',           'Finalize'),
        MakeClassFunction('KProcess *',     'GetOwnerProcess'),
        MakeClassFunction('KTypeObj',       'GetTypeObj'),
        MakeClassFunction('const char *',   'GetName'),
    ],
    'KAutoObjectWithList': [
        MakeClassFunction('_QWORD', 'GetId'),
    ],
    'KSynchronizationObject': [
        MakeClassFunction('void', 'OnFinalizeSynchronization'),
        MakeClassFunction('bool', 'IsSignaled'),
        #MakeClassFunction('void', 'DumpWaiters'),
    ],
    'KReadableEvent': [
        #MakeClassFunction('Result', 'Signal'),
        #MakeClassFunction('Result', 'Clear'),
        MakeClassFunction('Result', 'Reset'),
    ],
    'KAutoObjectWithListAllocatorAdapter': [
        MakeClassFunction('bool',      'IsInitialized'),
        MakeClassFunction('uintptr_t', 'GetPostFinalizeArgument'),
    ],
    'KSynchronizationObjectAllocatorAdapter': [
        MakeClassFunction('bool',      'IsInitialized'),
        MakeClassFunction('uintptr_t', 'GetPostFinalizeArgument'),
    ],
    'KReadableEventAllocatorAdapter': [
        MakeClassFunction('bool',      'IsInitialized'),
        MakeClassFunction('uintptr_t', 'GetPostFinalizeArgument'),
    ],
    'KDebugBase' : [
        MakeClassFunctionWithArgs('Result', 'GetThreadContextImpl', 'ThreadContext *ctx', 'KThread *thread', 'uint32_t flags'),
        MakeClassFunctionWithArgs('Result', 'SetThreadContextImpl', 'const ThreadContext *ctx', 'KThread *thread', 'uint32_t flags'),
    ],
    'KDebugBaseAllocatorAdapter': [
        MakeClassFunction('bool',      'IsInitialized'),
        MakeClassFunction('uintptr_t', 'GetPostFinalizeArgument'),
    ],

    # Auto Object final classes
    'KThread' : [
        MakeClassFunction('void', 'OnTimer'), # Really from multiple inheritance KTimerTask
        MakeClassFunction('void', 'DoTask'),  # Really from multiple inhertiance KWorkerTask
    ]
}

def GetVT(cls):
    assert cls in INHERITANCE
    funcs = []
    if INHERITANCE[cls] in INHERITANCE:
        funcs += GetVT(INHERITANCE[cls])
    if cls in VTABLES:
        funcs += VTABLES[cls]
    return funcs

LABELED = {

}

NAMES = {

}

seg_mapping = {idc.get_segm_name(x): (idc.get_segm_start(x), idc.get_segm_end(x)) for x in Segments()}

text_start, text_end             = seg_mapping['.text']
ro_start, ro_end                 = seg_mapping['.rodata']

def IsInText(ea):
    return text_start <= ea and ea < text_end

def IsAncestorOf(cls, other):
    if cls == other:
        return True
    elif INHERITANCE[other] in INHERITANCE:
        return IsAncestorOf(cls, INHERITANCE[other])
    else:
        return False

def TestCommonAncestor(ancestor, classes):
    for cls in classes:
        if not IsAncestorOf(ancestor, cls):
            return False
    return True

def GetShallowestCommonAncestorOfFunction(cls, others, func_id):
    if TestCommonAncestor(cls, others):
        for (vt_func_id, _, _) in GetVT(cls):
            if vt_func_id == func_id:
                return cls
    if INHERITANCE[cls] in INHERITANCE:
        ancestor = GetShallowestCommonAncestorOfFunction(INHERITANCE[cls], others, func_id)
        if ancestor != None:
            return ancestor
    return None

def ApplyFunction(func_ea, get_type, get_name, cls):
    func_type = get_type(cls)
    func_name = get_name(cls)
    idc.set_name(func_ea, func_name, SN_CHECK)
    idc.SetType(func_ea, func_type)
    if func_ea not in LABELED:
        LABELED[func_ea] = [cls]
    else:
        LABELED[func_ea].append(cls)
    NAMES[func_name] = func_ea
    #print 'Labeled %s (%x)' % (func_name, func_ea)

def ResolveAncestryConflict(cls, func_ea, func_id, get_type, get_name):
    common_ancestor = GetShallowestCommonAncestorOfFunction(cls, LABELED[func_ea], func_id)
    assert common_ancestor != None
    # Simple case, common ancestor name not in use.
    anc_name = get_name(common_ancestor)
    if anc_name not in NAMES or NAMES[anc_name] == func_ea:
        ApplyFunction(func_ea, get_type, get_name, common_ancestor)
    else:
        print common_ancestor
        print anc_name
        print NAMES
        print '%X' % NAMES[anc_name]
        print '%X' % func_ea
        # Common ancestor name is in use.
        # TODO: Resolve more complicated ancestry conflict.
        assert False

def ApplyVirtualTable(cls, vt, vt_ea):
    for i in xrange(len(vt)):
        #print '%X' % (vt_ea + 8 * i)
        assert IsInText(ida_bytes.get_64bit(vt_ea + 8 * i))
    for i, (func_id, get_func_type, get_func_name) in enumerate(vt):
        func_ea = ida_bytes.get_64bit(vt_ea + 8 * i)
        if func_ea not in LABELED:
            ApplyFunction(func_ea, get_func_type, get_func_name, cls)
        else:
            ResolveAncestryConflict(cls, func_ea, func_id, get_func_type, get_func_name)

def ProcessClass(cls):
    if INHERITANCE[cls] in INHERITANCE:
        ProcessClass(INHERITANCE[cls])
    vt = GetVT(cls)
    ea = get_name_ea(BADADDR, '%s::vt' % cls)
    if ea != BADADDR:
        # print '%s: %x' % (cls, ea)
        ApplyVirtualTable(cls, vt, ea)

def Disassemble(head):
    disasm = GetDisasm(head).lower().lstrip().rstrip().replace(',',' ')
    if ';' in disasm:
        disasm = disasm[:disasm.index(';')]
    return disasm.split()

def IsGetTypeObj(disasms):
    if len(disasms) == 3:
        if len(disasms[0]) != 3:
            return False
        if disasms[0][0] != 'adrl' and disasms[0][0] != 'adr':
            return False
        if disasms[0][1] != 'x0':
            return False
        if len(disasms[1]) != 3:
            return False
        if disasms[1][0] != 'mov':
            return False
        if disasms[1][1] == 'w1':
            if disasms[1][2].startswith('#'):
                pass
            elif disasms[1][2] == 'wzr':
                pass
            else:
                return False
        elif disasms[1][1] == 'x1':
            if disasms[1][2].startswith('#'):
                pass
            elif disasms[1][2] == 'xzr':
                pass
            else:
                return False
        if len(disasms[2]) != 1:
            return False
        return disasms[2][0] == 'ret'
    elif len(disasms) == 4:
        if len(disasms[0]) != 1:
            return False
        if disasms[0][0] != 'nop':
            return False
        return IsGetTypeObj(disasms[1:])
    elif len(disasms) == 5:
        if len(disasms[0]) != 3:
            return False
        if disasms[0][0] != 'adrp':
            return False
        if disasms[0][1] != 'x8':
            return False
        if len(disasms[1]) == 3 and disasms[1][0] == 'mov' and disasms[1][1] == 'w1':
            if disasms[1][2].startswith('#'):
                pass
            elif disasms[1][2] == 'xzr':
                pass
            else:
                return False
            x = disasms[1]
            disasms[1] = disasms[2]
            disasms[2] = disasms[3]
            disasms[3] = x
        if len(disasms[1]) != 4:
            return False
        if disasms[1][0] != 'ldr':
            return False
        if disasms[1][1] != 'x8':
            return False
        if disasms[1][2] != '[x8':
            return False
        if disasms[1][3] != '%soff]' % disasms[0][2]:
            return False
        if len(disasms[2]) != 3:
            return False
        if disasms[2][0] != 'ldr':
            return False
        if disasms[2][1] != 'x0':
            return False
        if disasms[2][2] != '[x8]':
            return False
        if len(disasms[3]) != 3:
            return False
        if disasms[3][0] != 'mov':
            return False
        if disasms[3][1] == 'w1':
            if disasms[3][2].startswith('#'):
                pass
            elif disasms[3][2] == 'wzr':
                pass
            else:
                return False
        elif disasms[3][1] == 'x1':
            if disasms[3][2].startswith('#'):
                pass
            elif disasms[3][2] == 'xzr':
                pass
            else:
                return False
        else:
            return False
        if len(disasms[4]) != 1:
            return False
        return disasms[4][0] == 'ret'


def GetVtableAddress(get_type_obj_ea):
    global ID_OBJECT_HELPER_VT
    candidates = []
    ofs = ro_start & ~7
    while ofs < ro_end:
        val = ida_bytes.get_64bit(ofs)
        if val == get_type_obj_ea:
            candidates.append(ofs - 0x18)
        ofs += 8
    if len(candidates) == 1:
        return candidates[0]
    elif len(candidates) == 2:
        assert False
        # KAutoObject
        assert ID_OBJECT_HELPER_VT is None
        if ida_bytes.get_64bit(candidates[0] + 0x28) == 0:
            ID_OBJECT_HELPER_VT = candidates[1]
            return candidates[0]
        else:
            assert ida_bytes.get_64bit(candidates[1] + 0x28) == 0
            ID_OBJECT_HELPER_VT = candidates[0]
            return candidates[1]
    return None

# Identify vtables
TYPE_OBJS = {}
INVERSE_TYPE_OBJS = {}
for segea in [text_start]:
    for funcea in Functions(segea, get_segm_end(segea)):
        chunks = [chunk for chunk in Chunks(funcea)]
        if len(chunks) != 1:
            continue
        startea, endea = chunks[0]
        heads = [head for head in Heads(startea, endea)]
        if len(heads) not in [3, 4, 5]:
            continue
        disasms = [Disassemble(head) for head in heads]
        if not IsGetTypeObj(disasms):
            continue
        token = disasms[-2][2][1:]
        if len(disasms) == 5 and disasms[1][0] == 'mov':
            token = disasms[1][2][1:]
        token = int(token, 0) if token != 'zr' else 0
        assert token not in INVERSE_TYPE_OBJS
        #print 'token %08X @ %X' % (token, funcea)
        if token == 0x4600 or token == 0:
            continue
        vt_ea = GetVtableAddress(funcea)
        assert vt_ea is not None
        TYPE_OBJS[vt_ea] = token
        INVERSE_TYPE_OBJS[token] = vt_ea
#print set(INVERSE_TYPE_OBJS.keys())
#print set(INVERSE_CLASS_TOKENS.keys())
#print set(INVERSE_CLASS_TOKENS.keys()) - set(INVERSE_TYPE_OBJS.keys())
assert set(INVERSE_TYPE_OBJS.keys() + [0x4600]) == set(INVERSE_CLASS_TOKENS.keys())
#assert ID_OBJECT_HELPER_VT is not None

for token in INVERSE_CLASS_TOKENS.keys():
    if token == 0x4600:
        continue
    vt_name = '%s::vt' % INVERSE_CLASS_TOKENS[token]
    vt_ea   = INVERSE_TYPE_OBJS[token]
    cur_ea  = get_name_ea(BADADDR, vt_name)
    if cur_ea != BADADDR:
        idc.set_name(cur_ea, '', SN_CHECK)
    idc.set_name(vt_ea, vt_name, SN_CHECK)
    print 'Found vtable for %s at 0x%x' % (INVERSE_CLASS_TOKENS[token], vt_ea)
#idc.set_name(ID_OBJECT_HELPER_VT, 'IdObjectHelper::vt', SN_CHECK)

# Label identified vtables
for cls in INHERITANCE.keys():
   ProcessClass(cls)