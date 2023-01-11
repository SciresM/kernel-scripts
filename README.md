# kernel-scripts
![License](https://img.shields.io/badge/license-ISC-blue.svg)

This is a collection of reverse engineering utility scripts for the Horizon Kernel.

## Usage

Recommended usage flow is as follows:

* Import types from previous reverse engineering database for older kernel revision.
  * SVC types and KAutoObject derivations are the most important ones. Types don't need to be correct per se, but they should exist.
* Run `kernel_svc_tables.py`.
  * This will auto-label all SVC functions, covering ~550-600/~1550-1650 functions.
* Run `kernel_auto_objects.py`.
  * This will auto-label all KAutoObject derivations' virtual function tables, covering an additional ~150-200 functions, for ~750/~1550-1650.
* Run `kernel_asm_decomp.py` and `kernel_priv_smc.py`.
  * This will improve decompiler output for certain aarch64 instructions, and many supervisor smc calls.
* Periodically run `kernel_x18.py` while reversing, and again when done creating the database.
  * This sets the "uninitialized" x18 platform register to `KThread *cur_thread;` in the decompiler output for all functions.
  * This is mostly not worth running when actually doing reversing, as making a change to a function prototype will undo the modifier.
* After the object container/allocator initialization functions are labeled, run `kernel_init_array.py`
  * This script is an enormous hack, ymmv, but with container/allocator ctor funcs labeled, it auto-recognizes + names all the allocator/slabheap data.
  * Saves ~30 minutes of mindless manual labeling, so I consider it a must.
  * NOTE: This script is defunct/no longer necessary since these objects became constant initialized in 13.0.0 and are no longer emitted in .init_array

In addition, two "report" scripts are provided, and may be run after the kernel has been labeled to one's satisfaction:

* `kern_hw_intr_report.py` prints all usages (functions + instruction counts) of instructions which enable or disable interrupts.
* `kern_hw_maint_report.py` prints all usages (functions + instruction counts) of instructions which engage in cache maintenance/synchronization.

These "report" scripts are intended to aid decompilation projects (like mesosphere) in accurately reflecting changes to how interrupt/cache maintenance is performed, and especially to notice changes in updates.