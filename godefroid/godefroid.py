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
import argparse
import os
from enum import Enum, auto
import cle
import copy

class Icount(Enum):
    INFINITE = auto()
    COUNTED = auto()


class GodefroidRunner(object):
    def __init__(self,
            memory,
            initial_pc,
            initial_sp,
            max_insts,
            run_length=Icount.COUNTED,
            magic_return=0xFEEDF00D):

        assert run_length == Icount.INFINITE or max_insts > 0

        self._memory = memory
        self.i_pc = initial_pc
        self.i_sp = initial_sp
        self.max_insts = max_insts
        self.run_length = run_length
        self.magic_return = magic_return
    
    def make_new_process(self, mem):
        p = GodefroidProcess(mem._ops, mem, self.i_sp)
        # write our "magic return address" to the stack
        if self.magic_return is not None:
            stacks = list(p._memory.find_maps_by_name("[stack]"))
            assert len(stacks) == 1
            stack = stacks[0]
            # Write our magic return on the stack without triggering a policy
            stack.store_bytes_raw(
                p._initial_sp,
                self.magic_return.to_bytes(p._memory.address_size_bits() // 8, byteorder="little"),
            )
            sys.stdout.write(f"[+] Using fake return address of {self.magic_return:08x}\n")

        return p

    def run(self, iterations=1):

        return_dict = {}
        for itercount in range(iterations):

            sys.stdout.write(f"[+] Attempting iteration {itercount}/{iterations}\n")

            #TODO(artem): This is really slow. Should be implemented as some kind of CoW semantics
            # or at least provide a way to 'reset' to a clean state
            proc = self.make_new_process(copy.deepcopy(self._memory))

            t = microx.EmptyThread(proc)
            t.write_register("EIP", self.i_pc)
            t.write_register("ESP", proc._initial_sp)

            sys.stdout.write(f"[+] Initial EIP is: {self.i_pc:08x}\n")
            sys.stdout.write(f"[+] Initial ESP is: {proc._initial_sp:08x}\n")

            instruction_count = 0
            try:
                while self.run_length == Icount.INFINITE or instruction_count < self.max_insts:
                    pc_bytes = t.read_register("EIP", t.REG_HINT_PROGRAM_COUNTER)
                    pc = proc._ops.convert_to_integer(pc_bytes)
                    if self.magic_return is not None and self.magic_return == pc:
                        sys.stdout.write("[+] Reached return address. Stopping\n")
                        break
                    else:
                        sys.stdout.write(f"[+] Emulating instruction at: {pc:08x}\n")
                        proc.execute(t, 1)
                        instruction_count += 1
            except InstructionFetchError as efe:
                sys.stdout.write(f"[!] Could not fetch instruction at: {pc:08x}. Error msg: {repr(efe)}.\n")
            except Exception as e:
                print(e)
                print(traceback.format_exc())
                pass

            return_dict[itercount] = (instruction_count, proc)
        return return_dict

class GodefroidProcess(microx.Process):
    INPUT_SPACE_SIZE = 0x1080000
    def __init__(self, ops, memory, sp_value=None):
        super(GodefroidProcess, self).__init__(ops, memory)

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
            sp_value = stack.base() + ((stack.limit() - stack.base()) // 2) & (~0xFF)

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

    @classmethod
    def create_memory_from_sections(cls, sections):
        o = microx.Operations()

        m = microx.Memory(o, 32)

        mem_map = None
        for section in sections:
            start = section['start']
            size = section['size']
            flags = section['flags']
            name = section['name']
            content = section['content']
            #sys.stdout.write(f"[+] Processing section {name}\n")

            page_start = start & ~(0xFFF)
            page_end = (start + size + 0xFFF) & ~0xFFF
            if "[stack]" == name:
                sys.stdout.write(f"[+] Creating stack region from 0x{page_start:x} to 0x{page_end:x}. Flags: {flags}\n")
                mem_map = PolicyMemoryMap(o,
                    page_start,
                    page_end,
                    flags,
                    DefaultMemoryPolicy(),
                    mapname=name)
                m.add_map(mem_map)
            else:
                for page in range(page_start, page_end, 0x1000):
                    if not m.can_read(page):
                        sys.stdout.write(f"[+] Mapping page from 0x{page:x} to 0x{page+0x1000:x}. Flags: {flags}\n")
                        mem_map = PolicyMemoryMap(o,
                            page,
                            page+0x1000,
                            flags,
                            DefaultMemoryPolicy(),
                            mapname=name)

                        m.add_map(mem_map)

            if content:
                assert mem_map is not None
                #sys.stdout.write(f"[+] Writing 0x{len(content):x} bytes at 0x{start:x}\n")
                mem_map.store_bytes_raw(start, content)

        return m

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

    m = GodefroidProcess.create_memory_from_sections(sections)
    r = GodefroidRunner(m, initial_pc=0x1000, initial_sp=0x81000, max_insts=15)
    rv = r.run(iterations=1)
    return rv[0]


def make_stack_section(loaded):

    STACK_SIZE = 8 * 1024 * 1024  # 8MB Stack
    new_section = {}
    if loaded.min_addr - 0x40000 > STACK_SIZE:
        new_section["start"] = 0x40000
    elif 0xFFFFFFFF - (loaded.max_addr + 0x40000) > STACK_SIZE:
        # Align loaded.max_addr to page alignment (on x86)
        new_section["start"] = ((loaded.max_addr + 0xFFF) & ~0xFFF) + 0x40000
    else:
        sys.stdout.write(f"[!] Could not find a {STACK_SIZE:x} hole for stack. Aborting.\n")
        return None

    new_section["name"] = "[stack]"
    new_section["size"] = STACK_SIZE
    new_section["flags"] = MemoryFlags.Read | MemoryFlags.Write
    new_section["content"] = None

    return new_section

def load_sections_from_binary(
    loader, 
    cle_binary):

    sections = []

    for section in cle_binary.sections:

        # Only care about in-memory sections
        if not section.occupies_memory:
            continue

        new_section = {}
        new_section["name"] = section.name
        new_section["start"] = section.min_addr
        new_section["size"] = section.memsize
        #sys.stdout.write(f"[+] CLE is loading section {section.name} from 0x{section.min_addr:x} to 0x{section.min_addr + section.memsize:x}\n")

        elfseg = cle_binary.find_segment_containing(section.min_addr)

        # no segment... use section permissions and hope for the best
        if elfseg is None:
            sys.stdout.write("[!] WARNING: no ELF segments found.. using section permissions and hoping for the best\n")
            elfseg = section

        new_section["flags"] = MemoryFlags.no_flags
        if elfseg.is_readable:
            new_section["flags"] |= MemoryFlags.Read
        if elfseg.is_writable:
            new_section["flags"] |= MemoryFlags.Write
        if elfseg.is_executable:
            new_section["flags"] |= MemoryFlags.Execute

        if section.only_contains_uninitialized_data:
            new_section["content"] = b'\00' * new_section["size"]
        else:
            new_section["content"] = loader.memory.load(
                new_section["start"], new_section["size"])
        
        sections.append(new_section)


    return sections


def run_on_binary(
        binary,
        entry,
        icount_type,
        maxinst):
    """
        binary: path to binary file to load
        entry: name or hex (0x prefixed) of the entrypoint)
        icount_type: infinite (run forever)  or counted (max instructions)
        maxinst: how many instructions to run (if in counted mode)
    """

    loaded = None
    try:
        loaded = cle.Loader(binary)
    except Exception as e:
        sys.stdout.write(f"[!] Could not load binary [{binary}]. Reason: {str(e)}\n")

    if loaded is None:
        return None
    else:
        sys.stdout.write(f"[+] Loaded binary: {binary}\n")

    # loop over binary sections
    main_binary = loaded.main_object
    if not main_binary:
        sys.stdout.write(f"[!] Could not find sections in {binary}\n")
        return None

    ep = entry
    if entry.startswith("0x"):
        ep = int(entry, base=16)
    # zero is technically a valid address, but warn about it
    if int == type(ep):
        if ep == 0:
            sys.stdout.write("[-] WARNING: Entrypoint is zero! This could be intentional but maybe something is wrong\n")
        sys.stdout.write("[+] Entry Point: 0x{ep:x}\n")
    else:
        sym = loaded.find_symbol(ep)
        if not sym:
            sys.stdout.write(f"[!] Could not find symbol {ep} in {binary}\n")
            return None
        else:
            ep_addr = sym.rebased_addr
            sys.stdout.write(f"[+] Found [{ep}] at 0x{ep_addr:x}\n")
            ep = ep_addr
    
    if ep < main_binary.min_addr or ep > main_binary.max_addr:
        sys.stdout.write(
            f"[!] Entry point addres f{ep:x} "
            f"is outside the range of the main "
            f"program binary [f{main_binary.min_addr:x} - f{main_binary.max_addr:x}]\n")
        return None

    sections = load_sections_from_binary(loaded, main_binary)
    if len(sections) == 0:
        sys.stdout.write(f"[!] Could not load sections from f{binary}\n")
        return None
    else:
        sys.stdout.write(f"[+] Loaded {len(sections)} sections from {binary}\n")

    stack_s = make_stack_section(loaded)
    if not stack_s:
        return None
    else:
        sys.stdout.write(f"[+] Loaded stack at: {stack_s['start']:x}\n")
        sections.append(stack_s)
    
    m = GodefroidProcess.create_memory_from_sections(sections)
    r = GodefroidRunner(m, initial_pc=ep, initial_sp=None, max_insts=maxinst, run_length=icount_type)
    rv = r.run(iterations=1)
    return rv[0]

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    group_a = parser.add_mutually_exclusive_group()
    group_a.add_argument("--default", action="store_true", help="Run the default example")
    group_b = group_a.add_argument_group()
    group_b.add_argument("--binary", help="Which binary file to load")
    group_b.add_argument("--entry", help="Address (in hex, 0x prefixed) or symbol at which to start execution")
    group_c = group_a.add_mutually_exclusive_group()
    group_c.add_argument("--maxinst", type=int, default=1024, help="How many instrutions to execute")
    group_c.add_argument("--infinite", action="store_true", help="Execute instructions until time limit is reached")

    args = parser.parse_args()

    if args.default:
        sys.stdout.write("[+] Executing the default Godefroid paper example\n")
        instruction_count, p = default_example()
        
    else:
        if not args.binary:
            sys.stdout.write("[!] Please specify a binary file to load\n")
            sys.exit(-1)

        if not os.path.exists(args.binary):
            sys.stdout.write(f"[!] Could not find file: {args.binary}\n")
            sys.exit(-1)

        if not args.entry:
            sys.stdout.write("[!] Please specify an entry point\n")
            sys.exit(-1)
    
        binary = args.binary
        entrypoint = args.entry

        icount_type = Icount.COUNTED
        max_inst = 0

        if args.infinite:
            sys.stdout.write("[+] Running for an INFINITE amount of instructions (or until function return)\n")
            icount_type = Icount.INFINITE
        elif args.maxinst < 0:
            sys.stdout.write(f"[!] Max instruction count must be zero or more. Got {args.maxinst}\n")
            sys.exit(1)
        else:
            icount_type = Icount.COUNTED
            max_inst = args.maxinst
            sys.stdout.write(f"[+] Running for {max_inst} instructions (or function return)\n")

        result = run_on_binary(
            binary = binary,
            entry = entrypoint,
            icount_type = icount_type,
            maxinst = max_inst
        )

        if result is None:
            sys.stdout.write(f"[!] Could not run on {binary} @ {entrypoint}\n")
            sys.exit(-1)

        instruction_count, p = result
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

