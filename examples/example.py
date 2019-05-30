#!/usr/bin/env python3
# Copyright (c) 2019 Trail of Bits, Inc., all rights reserved.

import microx
import traceback

if __name__ == "__main__":

    # 13 Disassembly:
    # 14 0:  55                      push   ebp
    # 15 1:  89 e5                   mov    ebp,esp
    # 16 3:  51                      push   ecx
    # 17 4:  8b 45 08                mov    eax,DWORD PTR [ebp+0x8]
    # 18 7:  8a 08                   mov    cl,BYTE PTR [eax]
    # 19 9:  88 4d ff                mov    BYTE PTR [ebp-0x1],cl
    # 20 c:  89 ec                   mov    esp,ebp
    # 21 e:  5d                      pop    ebp
    # 22 f:  c2 00 00                ret    0x0

    o = microx.Operations()

    code = microx.ArrayMemoryMap(o, 0x1000, 0x2000, can_write=False, can_execute=True)
    stack = microx.ArrayMemoryMap(o, 0x80000, 0x82000)

    code.store_bytes(
        0x1000,
        b"\x55\x89\xE5\x51\x8B\x45\x08\x8A\x08\x88\x4D\xFF\x89\xEC\x5D\xC2\x00\x00",
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
            print("Emulating instruction at {:08x}".format(pc))
            p.execute(t, 1)
    except Exception as e:
        print(e)
        print(traceback.format_exc())

