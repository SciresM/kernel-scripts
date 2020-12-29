def decompile_func(ea):
    if not idaapi.init_hexrays_plugin():
        return False

    f = idaapi.get_func(ea)
    if f is None:
        return False

    cfunc = idaapi.decompile(f, flags=idaapi.DECOMP_NO_CACHE);
    if cfunc is None:
        # Failed to decompile
        return False

    lines = []
    sv = cfunc.get_pseudocode();
    for sline in sv:
        line = idaapi.tag_remove(sline.line);
        lines.append(line)
    return lines

seg_mapping = {idc.get_segm_name(x): (idc.get_segm_start(x), idc.get_segm_end(x)) for x in Segments()}

init_array_start, init_array_end = seg_mapping['.init_array']

bss_start, bss_end = seg_mapping['.bss']

def is_bss_address(name):
    try:
        x = int(name, 16)
        return bss_start <= x and x < bss_end
    except ValueError:
        return False

OBJECT_CONTAINERS = {

}

SLAB_HEAPS = {

}

def process_bool(obj, suffix, line):
    assert line.startswith('  if ( ') and line.endswith(' )')
    init_cond = line[len('  if ( '):-len(' )')]
    assert ('!' in init_cond) ^ ('== 0' in init_cond)
    if '!' in init_cond:
        assert '(' not in init_cond and ')' not in init_cond
        init_var = init_cond[1:]
        assert init_var.count('_') == 1
        var_addr = init_var.split('_')[1]
        if is_bss_address(var_addr):
            var_addr = int(var_addr, 16)
            var_name = 'g_Initialized%s%s' % (obj, suffix)
            print '%08x: %s' % (var_addr, var_name)
            idc.SetType(var_addr, 'bool %s;' % var_name)
            idc.set_name(var_addr, var_name, SN_CHECK)
    else:
        assert ' == 0' in init_cond
        assert '(' in init_cond and ')' in init_cond
        init_var = init_cond[1:-len(' == 0')-1]
        assert init_var.endswith(' & 1')
        init_var = init_var[:-len(' & 1')]
        assert init_var.count('_') == 1
        var_addr = init_var.split('_')[1]
        if is_bss_address(var_addr):
            var_addr = int(var_addr, 16)
            var_name = 'g_Initialized%s%s' % (obj, suffix)
            print '%08x: %s' % (var_addr, var_name)
            idc.SetType(var_addr, 'bool %s;' % var_name)
            idc.set_name(var_addr, var_name, SN_CHECK)

def process_object_container(obj, line):
    assert line.startswith('    KObjectContainer::KObjectContainer(') and line.endswith(');')
    arg = line[len('    KObjectContainer::KObjectContainer('):-len(');')]
    assert ',' not in arg and ' ' not in arg
    if arg.startswith('&'):
        arg = arg[len('&'):]
    assert arg.count('_') == 1
    var_addr = get_name_ea(BADADDR, arg)
    assert is_bss_address('%x' % var_addr)
    var_name = 'g_%sObjectContainer' % obj
    idc.SetType(var_addr, 'KObjectContainer %s;' % var_name)
    idc.set_name(var_addr, var_name, SN_CHECK)
    print '%08x: %s' % (var_addr, var_name)
    global OBJECT_CONTAINERS
    OBJECT_CONTAINERS[var_addr] = obj

def process_slab_heap(obj, line):
    assert line.startswith('    ') and line.endswith(' = 0LL;')
    var = line[len('    '):-len(' = 0LL;')]
    if '.' in var:
        assert var.endswith('.atomic_heap_head')
        var = var[:-len('.atomic_heap_head')]
    if '.' in var:
        assert var.endswith('.slab_heap')
        var = var[:-len('.slab_heap')]
        var_ofs = 0x10
    else:
        var_ofs = 0x0
    var_addr = get_name_ea(BADADDR, var) - var_ofs
    assert is_bss_address('%x' % var_addr)
    var_name = 'g_%sSlabHeap' % obj
    idc.SetType(var_addr, 'KSlabHeap %s;' % var_name)
    idc.set_name(var_addr, var_name, SN_CHECK)
    print '%08x: %s' % (var_addr, var_name)
    global SLAB_HEAPS
    SLAB_HEAPS[var_addr] = obj

addr = init_array_start
while addr < init_array_end:
    funcea = ida_bytes.get_64bit(addr)
    name = get_name(funcea)
    if name.endswith('Allocator::ConstructObjectContainer'):
        obj = name[:-len('Allocator::ConstructObjectContainer')]
        pseudocode = decompile_func(funcea)
        assert len(pseudocode) == 8
        process_bool(obj, 'Allocator', pseudocode[2])
        process_object_container(obj, pseudocode[4])
    elif name.endswith('Allocator::ConstructSlabHeap'):
        obj = name[:-len('Allocator::ConstructSlabHeap')]
        pseudocode = decompile_func(funcea)
        assert len(pseudocode) == 12
        process_bool(obj, 'SlabHeap', pseudocode[2])
        process_slab_heap(obj, pseudocode[4])
    elif name.endswith('SlabHeap::ConstructStaticObjects') and not name.startswith('KPageBufferSlabHeap'):
        obj = name[:-len('SlabHeap::ConstructStaticObjects')]
        pseudocode = decompile_func(funcea)
        assert len(pseudocode) == 12
        process_bool(obj, 'SlabHeap', pseudocode[2])
        process_slab_heap(obj, pseudocode[4])
    addr += 8

for var_addr in OBJECT_CONTAINERS:
    if (var_addr + 0x10) not in SLAB_HEAPS:
        continue
    if OBJECT_CONTAINERS[var_addr] == SLAB_HEAPS[var_addr + 0x10]:
        var_name = 'g_%sAllocator' % OBJECT_CONTAINERS[var_addr]
        idc.SetType(var_addr, 'KObjectAllocator %s;' % var_name)
        idc.set_name(var_addr, var_name, SN_CHECK)
        print '%08x: %s' % (var_addr, var_name)