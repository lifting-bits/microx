#!/usr/bin/env python3
# Copyright (c) 2019 Trail of Bits, Inc., all rights reserved.

import microx
import traceback

if __name__ == "__main__":

    # Disassembly:
    # lea edi, [esp - 32]
    # mov eax, 0x41
    # mov ecx, 32
    # rep stosb
    #
    # lea esi, [esp - 32]
    # lea edi, [esp - 64]
    # mov ecx, 32
    # rep movsb
    #
    # mov byte ptr [esp - 32], 0
    # lea edi, [esp - 64]
    # xor eax, eax
    # mov ecx, -1
    # repne scasb
    # not ecx
    # dec ecx

    o = microx.Operations()

    code = microx.ArrayMemoryMap(o, 0x1000, 0x2000, can_write=False, can_execute=True)
    stack = microx.ArrayMemoryMap(o, 0x80000, 0x82000)

    code.store_bytes(
        0x1000,
        b"\x8d\x7c\x24\xe0\xb8\x41\x00\x00\x00\xb9\x20\x00\x00\x00\xf3\xaa\x8d\x74\x24\xe0\x8d\x7c\x24\xc0\xb9\x20\x00\x00\x00\xf3\xa4\xc6\x44\x24\xe0\x00\x8d\x7c\x24\xc0\x31\xc0\xb9\xff\xff\xff\xff\xf2\xae\xf7\xd1\x49",
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
            esi = t.read_register("ESI", t.REG_HINT_GENERAL)
            edi = t.read_register("EDI", t.REG_HINT_GENERAL)
            ecx = t.read_register("ECX", t.REG_HINT_GENERAL)
            print(
                "Emulating instruction at {:08x} (EAX={:08x}, ESI={:08x}, EDI={:08x}, ECX={:08x})".format(
                    pc, eax, esi, edi, ecx
                )
            )
            p.execute(t, 1)
    except Exception as e:
        print(e)
        print(traceback.format_exc())
