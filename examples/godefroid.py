#!/usr/bin/env python3
# Copyright (c) 2019 Trail of Bits, Inc., all rights reserved.

import microx
from microx_core import InstructionFetchError  # pylint: disable=no-name-in-module
import traceback
import logging
import sys
import secrets
import collections

from flags import Flags
from enum import Enum


class MemoryFlags(Flags):
    Read = ()  # can be read
    Write = ()  # can be written
    Execute = ()  # can be executed


class PolicyFlags(Flags):
    Read = ()
    Written = ()
    Executed = ()
    Present = ()  # TODO(artem): Used for future allocation/free tracking


class FlaggedMemoryMap(microx.MemoryMap):
    def __init__(self, ops, base, limit, access_flags, mapname=None):
        assert base < limit
        self._ops = ops
        self._base = base
        self._limit = limit
        self._access_flags = access_flags
        super(FlaggedMemoryMap, self).__init__(mapname)

    def _can_do_op(self, op, addr):
        return op in self._access_flags and self._base <= addr < self._limit

    def can_read(self, byte_addr):
        return self._can_do_op(MemoryFlags.Read, byte_addr)

    def can_write(self, byte_addr):
        return self._can_do_op(MemoryFlags.Write, byte_addr)

    def can_execute(self, byte_addr):
        return self._can_do_op(MemoryFlags.Execute, byte_addr)

    def base(self):
        return self._base

    def limit(self):
        return self._limit


class DefaultMemoryPolicy:
    def __init__(self):
        pass

    def handle_store(self, addr):
        # Does this policy care about stores?
        return True

    def handle_load(self, addr):
        # Does this policy care about loads?
        return False

    def read_before_write(self, addr, size, data):
        # sys.stdout.write("Read before write of {:x} - {:x}\n".format(addr, addr + size))
        return data

    def write_before_read(self, addr, size, data):
        # sys.stdout.write("Write before read of {:x} - {:x}\n".format(addr, addr + size))
        return data


class PolicyMemoryMap(FlaggedMemoryMap):
    def __init__(self, ops, base, limit, access_flags, policy, mapname=None):
        super(PolicyMemoryMap, self).__init__(ops, base, limit, access_flags, mapname)
        self._data = [0] * (limit - base)
        self._policy = policy
        self._access_map = {}

    def attach_policy(self, policy):
        # TODO(artem): Determine if we need to have multiple policies per map
        self._policy = policy

    def _load_policy(self, addr, size):

        # this policy doesn't care about memory reads
        if not self._policy.handle_load(addr):
            return

        flag_list = [
            self._access_map.get(i, PolicyFlags.no_flags)
            for i in range(addr, addr + size)
        ]
        # read before write
        r_before_w = map(lambda x: PolicyFlags.Written not in x, flag_list)
        if any(r_before_w):
            # callback to read_before_write in Policy
            start = addr - self._base
            end = start + size

            # TODO(artem): pass individual bytes that meet policy? right now its
            # called if any byte hits it
            new_data = self._policy.read_before_write(addr, size, self._data[start:end])

            assert len(new_data) == size
            self._data[start:end] = new_data

        # Mark all data as read
        for i in range(size):
            flag_list[i] |= PolicyFlags.Read
            self._access_map[addr + i] = flag_list[i]

    def _store_policy(self, addr, size):

        # this policy doesn't care about memory writes
        if not self._policy.handle_store(addr):
            # sys.stdout.write(f"!!! Addr not in policy: {addr:08x}\n")
            return

        flag_list = [
            self._access_map.get(i, PolicyFlags.no_flags)
            for i in range(addr, addr + size)
        ]
        # write before read
        w_before_r = map(lambda x: PolicyFlags.Read not in x, flag_list)
        if any(w_before_r):
            # callback to write_before_read in Policy
            start = addr - self._base
            end = start + size

            # TODO(artem): pass individual bytes that meet policy? right now its
            # called if any byte hits it
            new_data = self._policy.write_before_read(addr, size, self._data[start:end])

            assert len(new_data) == size
            self._data[start:end] = new_data
        else:
            # For now, assume we care a about *all* writes except those that
            # this mapping isn't set up to handle
            self._policy.add_output(addr, size)

        # Mark all data as written
        for i in range(size):
            flag_list[i] |= PolicyFlags.Written
            self._access_map[addr + i] = flag_list[i]

    def _load_unit(self, addr, size):
        # sys.stdout.write("Load size({:d}) at {:x}\n".format(size, addr))
        self._load_policy(addr, size)
        offset = addr - self._base
        return self._ops.convert_to_byte_string(self._data[offset : (offset + size)])

    def load_byte(self, addr):
        return self._load_unit(addr, 1)

    def load_word(self, addr):
        return self._load_unit(addr, 2)

    def load_dword(self, addr):
        return self._load_unit(addr, 4)

    def load_qword(self, addr):
        return self._load_unit(addr, 8)

    def load_bytes(self, addr, num_bytes):
        self._load_policy(addr, num_bytes)
        offset = addr - self._base
        return self._data[offset : (offset + num_bytes)]

    def _store_unit(self, addr, size, data):
        self._store_policy(addr, size)
        data = self._ops.convert_to_byte_string(data)
        self._store_bytes(addr, data[:size])

    def store_byte(self, addr, data):
        return self._store_unit(addr, 1, data)

    def store_word(self, addr, data):
        return self._store_unit(addr, 2, data)

    def store_dword(self, addr, data):
        return self._store_unit(addr, 4, data)

    def store_qword(self, addr, data):
        return self._store_unit(addr, 8, data)

    def _store_bytes(self, addr, data):
        offset = addr - self._base
        for b in data:
            if isinstance(b, str):
                b = ord(b)
            self._data[offset] = b
            offset += 1

    def store_bytes(self, addr, data):
        self._store_policy(addr, len(data))
        return self._store_bytes(addr, data)


class InputType(Enum):
    DATA = 0
    POINTER = 1
    COMPUTED = 2


class InputMemoryPolicy:

    # TODO(artem): Make this a configurable value or based on address size
    POINTER_INCREMENT = int(0x1000 / 4)

    def __init__(self, address_size, argument_vas, pointer_vas):

        self._address_size = int(address_size / 8)
        self._known_inputs = {}
        self._known_outputs = {}

        # Where initial arguments will be found (i.e., the stack)
        self._start = argument_vas[0]
        self._end = argument_vas[1]
        assert self._start < self._end

        # Things that look like pointers all point *to* this range
        self._pointers_start = pointer_vas[0]
        self._pointers_end = pointer_vas[1]
        assert self._pointers_start < self._pointers_end

        self._pointer_watermark = self._pointers_start

        # maps address (such as stack) -> where it points to (in "heap")
        self._pointer_map = {}

    def add_output(self, addr, size):
        sys.stdout.write(
            f"!!! Manually adding output at {addr:08x} - {addr+size:08x}\n"
        )
        self._known_outputs[addr] = size

    def pointer_to_bytes(self, ptr):
        return int(ptr).to_bytes(self._address_size, byteorder="little")

    def generate_pointer(self):

        # start at the current "high water mark" for input pointers
        new_ptr = self._pointer_watermark
        assert (new_ptr + self._address_size) < self._pointers_end
        # move watermark to next area, further down from here
        self._pointer_watermark += InputMemoryPolicy.POINTER_INCREMENT
        # TODO(artem): Handle the case where we run out of pointer space :)
        assert self._pointer_watermark < self._pointers_end
        sys.stdout.write(
            "Generating a pointer going to {:08x} in pointer space\n".format(new_ptr)
        )

        return new_ptr

    def generate_random(self, size):
        # NOTE(artem): Consider a seeded random for reproducability
        return secrets.token_bytes(size)

    def handle_store(self, addr):
        if (self._start <= addr <= self._end) or (
            self._pointers_start <= addr <= self._pointers_end
        ):
            # Does this policy care about stores?
            return True
        else:
            # This address is outside policy bounds
            return False

    def handle_load(self, addr):
        if (self._start <= addr <= self._end) or (
            self._pointers_start <= addr <= self._pointers_end
        ):
            # Does this policy care about loads?
            return True
        else:
            # This address is outside policy bounds
            return False

    def read_before_write(self, addr, size, data):
        sys.stdout.write(f"Read-before-write of {size} bytes\n")
        sys.stdout.write(f" at {addr:08x} [{addr:08x} - {addr+size:08x}]\n")
        new_data = data
        # TODO(artem): Check if this address+size has been previously read
        if self._address_size == size:
            # when reading a pointer size, at first, always assume the value is a pointer
            # and generate a pointer into pointer space aka ("heap")
            ptr = self.generate_pointer()
            self._pointer_map[addr] = ptr
            new_data = self.pointer_to_bytes(ptr)
        else:
            # When reading a non-pointer size, return a random value
            new_data = self.generate_random(size)

        # Mark the memory cell containing this value as used
        self._known_inputs[addr] = size

        assert len(data) == len(new_data)

        return new_data

    def write_before_read(self, addr, size, data):
        sys.stdout.write(f"Write-before-read of {size} bytes")
        sys.stdout.write(f" at {addr:08x} [{addr:08x} - {addr+size:08x}]\n")

        self._known_outputs[addr] = size

        return data

    def _make_itype(self, addr, size):
        ptr = self.get_pointer(addr)
        if ptr is not None:
            return (size, InputType.POINTER, ptr)
        elif size != 0:
            # TODO(artem): Keep track of initial values returned
            return (size, InputType.DATA, 0)
        elif size == 0:
            return (size, InputType.COMPUTED, 0)

    def get_outputs(self):
        # a copy of get_inputs that doesn't care about
        # the kind of output, at least for now
        output_addrs = sorted(self._known_outputs.keys())

        merged_addrs = collections.OrderedDict()

        # no outputs = blank dict
        if 0 == len(output_addrs):
            return merged_addrs

        # process the base case of the first input
        entry = output_addrs[0]
        merged_addrs[entry] = self._known_outputs[entry]

        watermark = entry + self._known_outputs[entry]

        # start merging overlapping input areas
        for addr in output_addrs[1:]:
            write_size = self._known_outputs[addr]

            if addr >= watermark:
                # Next output address is greater than addr+size of previous
                # This means a new output "area" was found
                merged_addrs[addr] = write_size
                watermark = addr + write_size
                entry = addr
            else:
                # This output address at least partially overlaps
                # the previous output address. Merge them
                if (addr + write_size) > watermark:
                    new_watermark = addr + write_size
                    merged_addrs[entry] = new_watermark - entry
                    watermark = new_watermark
                    # entry not updated since we extended the area
                else:
                    # This entry is entirely subsumed by the previous output area
                    pass

        return merged_addrs

    def get_inputs(self):
        # loop through inputs. Get ranges/bytes
        input_addrs = sorted(self._known_inputs.keys())

        # return an ordered dict of
        # address : size of input area
        merged_addrs = collections.OrderedDict()

        # no inputs = blank dict
        if 0 == len(input_addrs):
            return merged_addrs

        # process the base case of the first input
        entry = input_addrs[0]
        merged_addrs[entry] = self._make_itype(entry, self._known_inputs[entry])
        watermark = entry + self._known_inputs[entry]

        # start merging overlapping input areas
        for addr in input_addrs[1:]:
            read_size = self._known_inputs[addr]

            if addr >= watermark:
                # Next input address is greater than addr+size of previous
                # This means a new input "area" was found
                merged_addrs[addr] = self._make_itype(addr, read_size)
                watermark = addr + read_size
                entry = addr
            else:
                # This input address at least partially overlaps
                # the previous input address. Merge them
                if (addr + read_size) > watermark:
                    new_watermark = addr + read_size
                    merged_addrs[entry] = self._make_itype(addr, new_watermark - entry)
                    watermark = new_watermark
                    # entry not updated since we extended the area
                else:
                    # This entry is entirely subsumed by the previous input area
                    pass

        return merged_addrs

    def get_pointer(self, addr):
        # Return address it points to, or None if not a pointer
        return self._pointer_map.get(addr, None)

    def handle_compute(self, result, base, scale, index, disp):

        parts = (base, scale, index, disp)

        for p in parts:
            # NOTE(artem): the check for input address zero is here purely for sanity checking
            if p in self._known_inputs and p != 0:
                sys.stdout.write(
                    f"Input Address: {p:08x} used to compute {result:08x}\n"
                )
                sys.stdout.write(f"\tAdding {result:08x} to inputs")

                # Add a new 'computed' input address
                self._known_inputs[result] = 0
                break

        return result


class GodefroidProcess(microx.Process):
    def __init__(self, ops, memory, sp_value):
        super(GodefroidProcess, self).__init__(ops, memory)

        # TODO(artem): Iterarate over maps in `memory`, and pick a hole for use as 'input' addresses
        # This is an address range for addresses that we identify as "input"
        # For example, this is the range into which a hypothetical pointer passed in an argument
        # would point
        heap_start = 0x0F80000
        heap_end = 0x1FF0000
        heaps = PolicyMemoryMap(
            o,
            heap_start,
            heap_end,
            MemoryFlags.Read | MemoryFlags.Write,
            DefaultMemoryPolicy(),  # DefaultPolicy is only temporary, see below
            mapname="[heap]",
        )

        memory.add_map(heaps)

        # TODO(artem): Support multiple heaps/stacks/argument areas
        stacks = list(memory.find_maps_by_name("[stack]"))
        assert len(stacks) == 1

        heaps = list(memory.find_maps_by_name("[heap]"))
        assert len(heaps) == 1

        # adjust function stack by the pushed return address
        function_stack_start = sp_value + (memory.address_size_bits() // 8)
        assert stacks[0].base() <= function_stack_start <= stacks[0].limit()

        # assumes stacks grow down
        input_policy = InputMemoryPolicy(
            memory.address_size_bits(),
            (function_stack_start, stacks[0].limit()),  # argument space
            (heaps[0].base(), heaps[0].limit()),  # pointer space
        )

        # attach input policy instead of default policy on all stacks
        for s in stacks:
            s.attach_policy(input_policy)

        # attach input policy instead of default policy on all heaps
        for h in heaps:
            h.attach_policy(input_policy)

        self._policy = input_policy

    def compute_address(self, seg_name, base_addr, index, scale, disp, size, hint):
        result = super(GodefroidProcess, self).compute_address(
            seg_name, base_addr, index, scale, disp, size, hint
        )
        assert isinstance(self._policy, InputMemoryPolicy)
        addr = self._policy.handle_compute(result, base_addr, index, scale, disp)
        return addr

    def get_inputs(self):
        assert isinstance(self._policy, InputMemoryPolicy)
        return self._policy.get_inputs()

    def get_outputs(self):
        assert isinstance(self._policy, InputMemoryPolicy)
        return self._policy.get_outputs()


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

    # TODO(artem): Should we make a special code memory policy?
    code_range = (0x1000, 0x2000)
    code = PolicyMemoryMap(
        o,
        code_range[0],
        code_range[1],
        MemoryFlags.Read | MemoryFlags.Execute,
        DefaultMemoryPolicy(),
        mapname=".text",
    )

    code.store_bytes(
        0x1000,
        b"\x55\x89\xE5\x51\x8B\x45\x08\x8A\x08\x88\x4D\xFF\x89\xEC\x5D\xC2\x00\x00",
    )

    stack_range = (0x80000, 0x82000)  # allocated stack

    stack = PolicyMemoryMap(
        o,
        stack_range[0],
        stack_range[1],
        MemoryFlags.Read | MemoryFlags.Write,
        DefaultMemoryPolicy(),  # attach an InputMemoryPolicy later
        mapname="[stack]",
    )

    m = microx.Memory(o, 32)
    m.add_map(code)
    m.add_map(stack)

    t = microx.EmptyThread(o)

    RETURN_ADDRESS_MAGIC = 0xFEEDF00D
    pc = 0x1000
    esp = 0x81000

    # write our "magic return address" to the stack
    stack.store_bytes(
        esp,
        RETURN_ADDRESS_MAGIC.to_bytes(m.address_size_bits() // 8, byteorder="little"),
    )

    sys.stdout.write(f"[+] Initial EIP is: {pc:08x}\n")
    sys.stdout.write(f"[+] Initial ESP is: {esp:08x}\n")

    t.write_register("EIP", pc)
    t.write_register("ESP", esp)

    p = GodefroidProcess(o, m, sp_value=esp)

    instruction_count = 0
    try:
        while True:
            pc_bytes = t.read_register("EIP", t.REG_HINT_PROGRAM_COUNTER)
            pc = o.convert_to_integer(pc_bytes)
            if RETURN_ADDRESS_MAGIC == pc:
                sys.stdout.write("[+] Reached return address. Stopping\n")
                break
            else:
                sys.stdout.write(f"[+] Emulating instruction at: {pc:08x}\n")
                p.execute(t, 1)
                instruction_count += 1
    except InstructionFetchError:
        sys.stdout.write(f"[!] Could not fetch instruction at: {pc:08x}. Ending run.\n")
    except Exception as e:
        print(e)
        print(traceback.format_exc())

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

