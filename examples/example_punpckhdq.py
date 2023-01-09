import traceback
import microx


def main():
    o = microx.Operations()

    code = microx.ArrayMemoryMap(o, 0x1000, 0x2000, can_write=False, can_execute=True)
    stack = microx.ArrayMemoryMap(o, 0x80000, 0x82000)
    heap = microx.ArrayMemoryMap(o, 0x10000, 0x12000)

    code.store_bytes(
        0x1050,
        # punpckhdq mm0, [eax]
        b"\x0F\x6A\x00\xeb\x0e",
    )
    heap.store_bytes(0x10900, b"\xab\x00\x12\x00\xab\xab\xab\xab")

    m = microx.Memory(o, 32)
    m.add_map(code)
    m.add_map(stack)
    m.add_map(heap)

    t = microx.EmptyThread(o)
    t.write_register("EIP", 0x1050)
    t.write_register("ESP", 0x81000)

    t.write_register("MM0", 0xDEADBEEF12121212)
    t.write_register("EAX", 0x10900)

    p = microx.Process(o, m)

    try:
        pc = t.read_register("EIP", t.REG_HINT_PROGRAM_COUNTER)
        eax = t.read_register("EAX", t.REG_HINT_MEMORY_BASE_ADDRESS)
        mm0 = t.read_register("MM0", t.REG_HINT_GENERAL)
        print(f"Emulating instruction at {pc:08x} (EAX={eax:08x}, MM0={mm0:08x}")
        p.execute(t, 1)
        pc = t.read_register("EIP", t.REG_HINT_PROGRAM_COUNTER)
        eax = t.read_register("EAX", t.REG_HINT_MEMORY_BASE_ADDRESS)
        mm0 = t.read_register("MM0", t.REG_HINT_GENERAL)
        print(f"Finished emulating instruction: (EAX={eax:08x}, MM0={mm0:08x}")
    except Exception as e:
        print(e)
        print(traceback.format_exc())


if __name__ == "__main__":
    main()
