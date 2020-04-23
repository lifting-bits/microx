#!/usr/bin/env python3
# Copyright (c) 2019 Trail of Bits, Inc., all rights reserved.

import microx
import traceback

if __name__ == "__main__":

    # Disassembly:
    # push   rbp
    # mov    rbp,rsp
    # push   rcx
    # mov    rax,QWORD PTR [rbp+0x8]
    # mov    cl,BYTE PTR [rax]
    # mov    BYTE PTR [rbp-0x1],cl
    # mov    rsp,rbp
    # pop    rbp
    # ret    0x0
    o = microx.Operations()

    code = microx.ArrayMemoryMap(o, 0x100001000, 0x100002000, can_write=False, can_execute=True)
    stack = microx.ArrayMemoryMap(o, 0x200080000, 0x200082000)

    code.store_bytes(
        0x100001000,
        b"\x55\x48\x89\xe5\x51\x48\x8b\x45\x08\x8a\x08\x88\x4d\xff\x48\x89\xec\x5d\xc2\x00\x00",
    )

    m = microx.Memory(o, 64)
    m.add_map(code)
    m.add_map(stack)

    t = microx.EmptyThread(o)
    t.write_register("RIP", 0x100001000)
    t.write_register("RSP", 0x200081000)

    p = microx.Process(o, m)

    try:
        while True:
            pc = t.read_register("RIP", t.REG_HINT_PROGRAM_COUNTER)
            print("Emulating instruction at {:016x}".format(pc))
            p.execute(t, 1)
    except Exception as e:
        print(e)
        print(traceback.format_exc())

