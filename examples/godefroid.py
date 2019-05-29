#!/usr/bin/env python3
# Copyright (c) 2019 Trail of Bits, Inc., all rights reserved.

import microx
import traceback
import logging
import sys
import secrets

from flags import Flags


class MemoryFlags(Flags):
  Read = () # can be read
  Write = () # can be written
  Execute = () # can be executed


class PolicyFlags(Flags):
  Read = ()
  Written = ()
  Executed = ()
  Present = () # TODO(artem): Used for future allocation/free tracking

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

class DefaultMemoryPolicy():
  def __init__(self):
    pass

  def handle_store(self, addr):
    # Does this policy care about stores?
    return True

  def handle_load(self, addr):
    # Does this policy care about loads?
    return False

  def read_before_write(self, addr, size, data):
    sys.stdout.write("Read before write of {:x} - {:x}\n".format(addr, addr+size))
    return data 

  def write_before_read(self, addr, size, data):
    sys.stdout.write("Write before read of {:x} - {:x}\n".format(addr, addr+size))
    return data

class PolicyMemoryMap(FlaggedMemoryMap):
  def __init__(self, ops, base, limit, access_flags, policy, mapname=None):
    super(PolicyMemoryMap, self).__init__(ops, base, limit, access_flags, mapname)
    self._data = [0] * (limit - base)
    self._policy = policy
    self._access_map = {}

  def attach_policy(self, policy):
    #TODO(artem): Determine if we need to have multiple policies per map
    self._policy = policy

  def _load_policy(self, addr, size):

    # this policy doesn't care about memory reads
    if not self._policy.handle_load(addr):
      return

    flag_list = \
      [ self._access_map.get(i, PolicyFlags.no_flags) \
          for i in range(addr, addr+size) ]
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
      self._access_map[addr+i] = flag_list[i]

  def _store_policy(self, addr, size):

    # this policy doesn't care about memory writes
    if not self._policy.handle_store(addr):
      return

    flag_list = \
      [ self._access_map.get(i, PolicyFlags.no_flags) \
          for i in range(addr, addr+size) ]
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

    # Mark all data as written
    for i in range(size):
      flag_list[i] |= PolicyFlags.Written
      self._access_map[addr+i] = flag_list[i]

  def _load_unit(self, addr, size):
    sys.stdout.write("Load size({:d}) at {:x}\n".format(size, addr))
    self._load_policy(addr, size)
    offset = addr - self._base
    return self._ops.convert_to_byte_string(self._data[offset:(offset + size)])

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
    return self._data[offset:(offset + num_bytes)]

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

class InputMemoryPolicy():

  #TODO(artem): Make this a configurable value or based on address size
  POINTER_INCREMENT = int(0x1000/4)

  def __init__(self, address_size, argument_vas, pointer_vas):

    self._address_size = int(address_size/8)
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

  def pointer_to_bytes(self, ptr):
    return int(ptr).to_bytes(self._address_size, byteorder='little')

  def generate_pointer(self):

    # start at the current "high water mark" for input pointers
    new_ptr = self._pointer_watermark
    assert (new_ptr + self._address_size) < self._pointers_end
    # move watermark to next area, further down from here
    self._pointer_watermark += InputMemoryPolicy.POINTER_INCREMENT
    #TODO(artem): Handle the case where we run out of pointer space :)
    assert self._pointer_watermark < self._pointers_end
    sys.stdout.write("Generating a pointer going to {:08x} in pointer space\n".format(new_ptr))

    # Add a placeholder size of size 0, indicating this pointer has never been
    # dereferenced or used in computation
    # This size prevents it from being re-used as another pointer
    self._known_inputs[new_ptr] = 0 
    return self.pointer_to_bytes(new_ptr)

  def generate_random(self, size):
    return secrets.token_bytes(size)

  def handle_store(self, addr):
    if (self._start         <= addr <= self._end        ) or \
       (self._pointers_start <= addr <= self._pointers_end):
      # Does this policy care about stores?
      return True
    else:
      # This address is outside policy bounds
      return False


  def handle_load(self, addr):
    if (self._start         <= addr <= self._end        ) or \
       (self._pointers_start <= addr <= self._pointers_end):
      # Does this policy care about loads?
      return True
    else:
      # This address is outside policy bounds
      return False

  def read_before_write(self, addr, size, data):
    sys.stdout.write("Input mem: Read before write of {:x} - {:x}\n".format(addr, addr+size))
    new_data = data
    if self._address_size == size:
      # when reading a pointer size, at first, always assume the value is a pointer
      # and generate a pointer into pointer space aka ("heap")
      new_data = self.generate_pointer()
      sys.stdout.write("Found pointer input at {:08x} - {:08x}\n".format(addr, addr+size))
      # Mark the memory cell containing this pointer
      self._known_inputs[addr] = self._address_size
    else:
      # When reading a non-pointer size, return a random value
      sys.stdout.write("Found input at {:08x} - {:08x}\n".format(addr, addr+size))
      new_data = self.generate_random(size)
      # Mark the memory cell containing this pointer as used
      self._known_inputs[addr] = size

    assert len(data) == len(new_data)

    return new_data

  def write_before_read(self, addr, size, data):
    sys.stdout.write("Write before read of {:x} - {:x}\n".format(addr, addr+size))
    return data

class GodefroidProcess(microx.Process):
  def __init__(self, ops, memory, sp_value):
    super(GodefroidProcess, self).__init__(ops, memory)

    # TODO(artem): Iterarate over maps in `memory`, and pick a hole for use as 'input' addresses
    # This is an address range for addresses that we identify as "input"
    # For example, this is the range into which a hypothetical pointer passed in an argument
    # would point
    heap_start =   0x0F80000
    heap_end   =   0x1FF0000
    heaps = PolicyMemoryMap(o, heap_start, heap_end, MemoryFlags.Read | MemoryFlags.Write,
        DefaultMemoryPolicy(),
        mapname="[heap]")

    memory.add_map(heaps)

    #TODO(artem): Support multiple heaps/stacks/argument areas
    stacks = list(memory.find_maps_by_name("[stack]"))
    assert len(stacks) == 1

    heaps = list(memory.find_maps_by_name("[heap]"))
    assert len(heaps) == 1

    function_stack_start = sp_value
    assert stacks[0].base() <= function_stack_start <= stacks[0].limit()

    # assumes stacks grow down
    input_policy = InputMemoryPolicy(32,  #32 bit addresses
        (function_stack_start, stacks[0].limit(),), # argument space
        (heaps[0].base(), heaps[0].limit(),) # pointer space
      )

    # attach input policy instead of default policy on all stacks
    for s in stacks:
      s.attach_policy(input_policy)

    # attach input policy instead of default policy on all heaps
    for h in heaps:
      h.attach_policy(input_policy)

  def compute_address(self, seg_name, base_addr, index, scale, disp, size, hint):
    addr = super(GodefroidProcess, self).compute_address(seg_name, base_addr, index, scale, disp, size, hint)
    sys.stdout.write("Computing: {:08x} | {:08x} | {:08x} | {:08x}\n".format(
      base_addr, index, scale, disp))
    return addr


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

  #TODO(artem): Should we make a special code memory policy?
  code_range = (0x1000, 0x2000)
  code = PolicyMemoryMap(o, code_range[0], code_range[1],
      MemoryFlags.Read | MemoryFlags.Execute,
      DefaultMemoryPolicy(), 
      mapname=".text")

  code.store_bytes(0x1000, b"\x55\x89\xE5\x51\x8B\x45\x08\x8A\x08\x88\x4D\xFF\x89\xEC\x5D\xC2\x00\x00")

  stack_range = (0x80000, 0x82000) # allocated stack

  stack = PolicyMemoryMap(o, stack_range[0], stack_range[1],
      MemoryFlags.Read | MemoryFlags.Write,
      DefaultMemoryPolicy(), # attach an InputMemoryPolicy later
      mapname="[stack]")

  m = microx.Memory(o, 32)
  m.add_map(code)
  m.add_map(stack)

  t = microx.Thread(o)
  t.write_register('EIP', 0x1000)
  t.write_register('ESP', 0x81000)

  p = GodefroidProcess(o, m, sp_value=0x81000)

  try:
    while True:
      pc = t.read_register('EIP', t.REG_HINT_PROGRAM_COUNTER)
      pc_int = o.convert_to_integer(pc)
      print("Emulating instruction at {:08x}".format(pc_int))
      p.execute(t, 1)
  except Exception as e:
    print(e)
    print(traceback.format_exc())

