#!/usr/bin/env python3
# Copyright (c) 2019 Trail of Bits, Inc., all rights reserved.

import microx
import traceback

if __name__ == "__main__":

    # Disassembly:
    # mov eax, 0x55555555
    # mov edx, eax
    # rdtsc
    # mov eax, 0x55555555
    # mov edx, eax
    # rdtscp

    o = microx.Operations()

    code = microx.ArrayMemoryMap(o, 0x1000, 0x2000, can_write=False, can_execute=True)
    stack = microx.ArrayMemoryMap(o, 0x80000, 0x82000)

    code.store_bytes(
        0x1000,
        b"\xb8\x55\x55\x55\x55\x89\xc2\x0f\x31\xb8\x55\x55\x55\x55\x89\xc2\x0f\x01\xf9",
    )

    m = microx.Memory(o, 32)
    m.add_map(code)
    m.add_map(stack)

    t = microx.EmptyThread(o)
    t.write_register("EIP", 0x1000)
    t.write_register("ESP", 0x81000)

    p = microx.Process(o, m)

    try:
        while True:
            pc = t.read_register("EIP", t.REG_HINT_PROGRAM_COUNTER)
            eax = t.read_register("EAX", t.REG_HINT_GENERAL)
            edx = t.read_register("EDX", t.REG_HINT_GENERAL)
            tsc = t.read_register("TSC", t.REG_HINT_NONE)
            print(
                "Emulating instruction at {:08x} (EAX={:08x}, EDX={:08x}, TSC={:016x})".format(
                    pc, eax, edx, tsc
                )
            )
            p.execute(t, 1)
    except Exception as e:
        print(e)
        print(traceback.format_exc())
