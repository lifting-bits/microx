#!/usr/bin/env python3
# Copyright (c) 2019 Trail of Bits, Inc., all rights reserved.
import microx
from microx_core import InstructionFetchError  # pylint: disable=no-name-in-module
import traceback
import logging
import sys
from flag_map import MemoryFlags
from policies import DefaultMemoryPolicy, InputMemoryPolicy, InputType
from policy_map import PolicyMemoryMap



class GodefroidProcess(microx.Process):
    INPUT_SPACE_SIZE = 0x1080000
    def __init__(self, ops, memory, sp_value=None):
        super(GodefroidProcess, self).__init__(ops, memory)

        # TODO(artem): Iterarate over maps in `memory`, and pick a hole for use as 'input' addresses
        # This is an address range for addresses that we identify as "input"
        # For example, this is the range into which a hypothetical pointer passed in an argument
        # would point

        #NOTE(artem): Allows for user-specified input heaps
        if not memory.find_maps_by_name("[input_space]"):
            input_size = GodefroidProcess.INPUT_SPACE_SIZE
            input_base = memory.find_hole(input_size)

            sys.stdout.write(f"[+] Mapping input space to: {input_base:08x} - {input_base+input_size:08x}\n")
            input_space = PolicyMemoryMap(
                self._ops,
                input_base,
                input_base+input_size,
                MemoryFlags.Read | MemoryFlags.Write,
                DefaultMemoryPolicy(),  # DefaultPolicy is only temporary, see below
                mapname="[input_space]",
            )

            memory.add_map(input_space)

        stacks = list(memory.find_maps_by_name("[stack]"))
        assert len(stacks) == 1
        stack = stacks[0]
        if sp_value is None:
            # generate an aligned stack of some kind
            sp_value = ((stack.limit() - stack.base()) // 2) & (~0xFF)

        self._initial_sp = sp_value

        # TODO(artem): Support multiple input areas
        inputs = list(memory.find_maps_by_name("[input_space]"))
        assert len(inputs) == 1

        # adjust function stack by the pushed return address
        function_stack_start = self._initial_sp + (memory.address_size_bits() // 8)
        assert stack.base() <= function_stack_start < stack.limit()

        # assumes stacks grow down
        #TODO(artem): Support multiple input spaces in InputMemoryPolicy
        input_policy = InputMemoryPolicy(
            memory.address_size_bits(),
            (function_stack_start, stack.limit()),  # argument space
            (inputs[0].base(), inputs[0].limit()),  # pointer space
        )

        stacks[0].attach_policy(input_policy)

        # attach input policy instead of default policy on all input spaces
        for h in inputs:
            h.attach_policy(input_policy)

        self._policy = input_policy

    def compute_address(self, seg_name, base_addr, index, scale, disp, size, hint):
        result = super(GodefroidProcess, self).compute_address(
            seg_name, base_addr, index, scale, disp, size, hint
        )
        assert isinstance(self._policy, InputMemoryPolicy)
        addr = self._policy.handle_compute(
            result, base_addr, index, scale, disp, size, hint
        )
        return addr

    def get_inputs(self):
        assert isinstance(self._policy, InputMemoryPolicy)
        return self._policy.get_inputs()

    def get_outputs(self):
        assert isinstance(self._policy, InputMemoryPolicy)
        return self._policy.get_outputs()

    def run(self, initial_pc, max_insts, magic_return=0xFEEDF00D):

        assert max_insts > 0
        # write our "magic return address" to the stack
        if magic_return is not None:
            stacks = list(self._memory.find_maps_by_name("[stack]"))
            assert len(stacks) == 1
            stack = stacks[0]
            # Write our magic return on the stack without triggering a policy
            stack.store_bytes_raw(
                self._initial_sp,
                magic_return.to_bytes(self._memory.address_size_bits() // 8, byteorder="little"),
            )
            sys.stdout.write(f"[+] Using fake return address of {magic_return:08x}\n")

        sys.stdout.write(f"[+] Initial EIP is: {initial_pc:08x}\n")
        sys.stdout.write(f"[+] Initial ESP is: {self._initial_sp:08x}\n")

        t = microx.EmptyThread(self._ops)
        t.write_register("EIP", initial_pc)
        t.write_register("ESP", self._initial_sp)

        instruction_count = 0
        try:
            while instruction_count < max_insts:
                pc_bytes = t.read_register("EIP", t.REG_HINT_PROGRAM_COUNTER)
                pc = self._ops.convert_to_integer(pc_bytes)
                if magic_return is not None and magic_return == pc:
                    sys.stdout.write("[+] Reached return address. Stopping\n")
                    break
                else:
                    sys.stdout.write(f"[+] Emulating instruction at: {pc:08x}\n")
                    self.execute(t, 1)
                    instruction_count += 1
        except InstructionFetchError:
            sys.stdout.write(f"[!] Could not fetch instruction at: {pc:08x}. Ending run.\n")
        except Exception as e:
            print(e)
            print(traceback.format_exc())
            pass

        return instruction_count
    
    @classmethod
    def create_from_sections(cls, sections, initial_sp=None):
        o = microx.Operations()

        m = microx.Memory(o, 32)

        for section in sections:
            start = section['start']
            size = section['size']
            flags = section['flags']
            name = section['name']
            content = section['content']

            mem_map = PolicyMemoryMap(
                o,
                start,
                start+size,
                flags,
                DefaultMemoryPolicy(),
                mapname=name,
            )

            if content:
                mem_map.store_bytes(start, content)

            m.add_map(mem_map)

        p = GodefroidProcess(o, m, initial_sp)

        return p

def default_example():

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

    sections = [
        {'name' : ".text",
         "start": 0x1000,
         "size" : 0x1000,
         "flags": MemoryFlags.Read | MemoryFlags.Execute,
         "content": b"\x55\x89\xE5\x51\x8B\x45\x08\x8A\x08\x88\x4D\xFF\x89\xEC\x5D\xC2\x00\x00",
         },

        {'name' : "[stack]",
         "start": 0x80000,
         "size" : 0x82000,
         "flags": MemoryFlags.Read | MemoryFlags.Write,
         "content":  None,
         }
    ]

    p = GodefroidProcess.create_from_sections(sections, initial_sp=0x81000)
    icount = p.run(initial_pc=0x1000, max_insts=15)
    return icount, p

if __name__ == "__main__":

    instruction_count, p = default_example()
    # Stats
    sys.stdout.write(f"[+] Executed {instruction_count} instructions\n")
    # Dump known inputs
    inputs = p.get_inputs()

    if len(inputs) > 0:
        sys.stdout.write("[+] Found the following inputs:\n")
        for (k, v) in inputs.items():
            input_size, input_type, input_data = v
            sys.stdout.write(f"\t{k:08x} - {k+input_size:08x} [size: {input_size}]")
            if InputType.POINTER == input_type:
                sys.stdout.write(f" [POINTER TO: {input_data:08x}]")
            elif InputType.DATA == input_type:
                sys.stdout.write(" [DATA]")
            elif InputType.COMPUTED == input_type:
                sys.stdout.write(" [COMPUTED]")
            else:
                assert "Unknown input type"
            sys.stdout.write("\n")
    else:
        sys.stdout.write("[-] No inputs found\n")
    # Dump known outputs
    outputs = p.get_outputs()

    if len(outputs) > 0:
        sys.stdout.write("[+] Found the following outputs:\n")
        for (k, v) in outputs.items():
            sys.stdout.write(f"\t{k:08x} - {k+v:08x}\n")
    else:
        sys.stdout.write("[-] No outputs found\n")

