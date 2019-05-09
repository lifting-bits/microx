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
  def __init__(self, ops, base, limit, access_flags):
    assert base < limit
    self._ops = ops
    self._base = base
    self._limit = limit
    self._access_flags = access_flags

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

  def read_before_write(self, addr, size, data):
    sys.stdout.write("Read before write of {:x} - {:x}\n".format(addr, addr+size))
    return data 

  def write_before_read(self, addr, size, data):
    sys.stdout.write("Write before read of {:x} - {:x}\n".format(addr, addr+size))
    return data

class PolicyMemoryMap(FlaggedMemoryMap):
  def __init__(self, ops, base, limit, access_flags, policy):
    super(PolicyMemoryMap, self).__init__(ops, base, limit, access_flags)
    self._data = [0] * (limit - base)
    self._policy = policy
    self._access_map = {}

  def _load_policy(self, addr, size):
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

  def load_byte(self, addr):
    self._load_policy(addr, 1)
    offset = addr - self._base
    return self._ops.convert_to_byte_string(self._data[offset:(offset + 1)])

  def load_word(self, addr):
    self._load_policy(addr, 2)
    offset = addr - self._base
    return self._ops.convert_to_byte_string(self._data[offset:(offset + 2)])

  def load_dword(self, addr):
    self._load_policy(addr, 4)
    offset = addr - self._base
    return self._ops.convert_to_byte_string(self._data[offset:(offset + 4)])

  def load_qword(self, addr):
    self._load_policy(addr, 8)
    offset = addr - self._base
    return self._ops.convert_to_byte_string(self._data[offset:(offset + 8)])

  def load_bytes(self, addr, num_bytes):
    self._load_policy(addr, num_bytes)
    offset = addr - self._base
    return self._data[offset:(offset + num_bytes)]

  def store_byte(self, addr, data):
    self._store_policy(addr, 1)
    data = self._ops.convert_to_byte_string(data)
    self.store_bytes(addr, data[:1])

  def store_word(self, addr, data):
    self._store_policy(addr, 2)
    data = self._ops.convert_to_byte_string(data)
    self.store_bytes(addr, data[:2])

  def store_dword(self, addr, data):
    self._store_policy(addr, 4)
    data = self._ops.convert_to_byte_string(data)
    self.store_bytes(addr, data[:4])

  def store_qword(self, addr, data):
    self._store_policy(addr, 8)
    data = self._ops.convert_to_byte_string(data)
    self.store_bytes(addr, data[:8])

  def store_bytes(self, addr, data):
    self._store_policy(addr, len(data))
    offset = addr - self._base
    for b in data:
      if isinstance(b, str):
        b = ord(b)
      self._data[offset] = b
      offset += 1


class InputMemoryPolicy():
  POINTER_INCREMENT = int(0x1000/4)

  def __init__(self, address_size, va_start, va_end):
    #TODO(artem): Track 'pointers' and 'where the point' as separate things
    self._start = int(va_start)
    self._end = int(va_end)
    self._address_size = int(address_size/8)
    self._known_inputs = {}
    self._known_outputs = {}

  def pointer_to_bytes(self, ptr):
    return int(ptr).to_bytes(self._address_size, byteorder='little')

  def generate_pointer(self):
    last_key = max( self._known_inputs.keys(), default=self._start )
    new_ptr = last_key + InputMemoryPolicy.POINTER_INCREMENT
    sys.stdout.write("Generating new input pointer: {:08x}\n".format(new_ptr, self._end))
    assert (new_ptr + self._address_size) < self._end
    self._known_inputs[new_ptr] = 0 # placeholder to make sure this isn't re-used

    return self.pointer_to_bytes(new_ptr)

  def generate_random(self, size):
    return secrets.token_bytes(size)

  def read_before_write(self, addr, size, data):
    sys.stdout.write("Input mem: Read before write of {:x} - {:x}\n".format(addr, addr+size))
    new_data = data
    if self._address_size == size:
      new_data = self.generate_pointer()
      sys.stdout.write("Found pointer input at {:08x} - {:08x}\n".format(addr, addr+size))
      self._known_inputs[addr] = self._address_size
    else:
      sys.stdout.write("Found input at {:08x} - {:08x}\n".format(addr, addr+size))
      self._known_inputs[addr] = size
      new_data = self.generate_random(size)

    assert len(data) == len(new_data)

    return new_data

  def write_before_read(self, addr, size, data):
    sys.stdout.write("Write before read of {:x} - {:x}\n".format(addr, addr+size))
    return data

class GodefroidProcess(microx.Process):
  def __init__(self, ops, memory):
    super(GodefroidProcess, self).__init__(ops, memory)
    # TODO(artem): Make pick a free address for inputs
    input_start = 0xF80000
    input_end   =  0x1FF0000
    inputs = PolicyMemoryMap(o, input_start, input_end, MemoryFlags.Read | MemoryFlags.Write,
        InputMemoryPolicy(memory._address_size, input_start, input_end))
    memory.add_map(inputs)

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

  # code = microx.ArrayMemoryMap(o, 0x1000, 0x2000, can_write=False, can_execute=True)
  code = PolicyMemoryMap(o, 0x1000, 0x2000, MemoryFlags.Read | MemoryFlags.Execute, DefaultMemoryPolicy())
  # stack = microx.ArrayMemoryMap(o, 0x80000, 0x82000)
  stack = PolicyMemoryMap(o, 0x80000, 0x82000, MemoryFlags.Read | MemoryFlags.Write,
      InputMemoryPolicy(32, 0x80000, 0x82000))

  code.store_bytes(0x1000, b"\x55\x89\xE5\x51\x8B\x45\x08\x8A\x08\x88\x4D\xFF\x89\xEC\x5D\xC2\x00\x00")

  m = microx.Memory(o, 32)
  m.add_map(code)
  m.add_map(stack)

  t = microx.Thread(o)
  t.write_register('EIP', 0x1000)
  t.write_register('ESP', 0x81000)

  p = GodefroidProcess(o, m)

  try:
    while True:
      pc = t.read_register('EIP', t.REG_HINT_PROGRAM_COUNTER)
      pc_int = o.convert_to_integer(pc)
      print("Emulating instruction at {:08x}".format(pc_int))
      p.execute(t, 1)
  except Exception as e:
    print(e)
    print(traceback.format_exc())

