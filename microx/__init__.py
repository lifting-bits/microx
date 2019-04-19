#!/usr/bin/env python3
# Copyright (c) 2019 Trail of Bits, Inc., all rights reserved.

import collections
import sys
import struct

from microx_core import Executor

class Operations(object):
  def convert_to_byte_string(self, data):
    return bytes(data)

  def convert_to_byte(self, data):
    pass

  def convert_to_big_integer(self, val_bytes):
    val = int(0)
    for b in reversed(val_bytes):
      val = (val << 8) | int(ord(b))
    return val

  def convert_to_integer(self, val):
    if isinstance(val, (str, bytes, bytearray)):
      if 1 == len(val):
        val = ord(val)
      elif 2 == len(val):
        val = struct.unpack('<H',val)[0]
      elif 4 == len(val):
        val = struct.unpack('<I',val)[0]
      elif 8 == len(val):
        val = struct.unpack('<Q',val)[0]
      else:
        val = self.convert_to_big_integer(val)
    assert isinstance(val, (int))
    return val


class MemoryAccessException(Exception):
  pass


class MemoryMap(object):
  def __init__(self):
    pass

  def can_read(self, byte_addr):
    return False

  def can_write(self, byte_addr):
    return False

  def can_execute(self, byte_addr):
    return False

  def base(self):
    return 0

  def limit(self):
    return 0

  def load_byte(self, addr):
    raise MemoryAccessException(
        "Can't load byte from address {:08x}".format(addr))

  def load_word(self, addr):
    raise MemoryAccessException(
        "Can't load word from address {:08x}".format(addr))

  def load_dword(self, addr):
    raise MemoryAccessException(
        "Can't load dword from address {:08x}".format(addr))

  def load_qword(self, addr):
    raise MemoryAccessException(
        "Can't load qword from address {:08x}".format(addr))

  def load_bytes(self, addr, num_bytes):
    raise MemoryAccessException(
        "Can't load {} bytes from address {:08x}".format(num_bytes, addr))

  def store_byte(self, addr, val):
    raise MemoryAccessException(
        "Can't store byte to address {:08x}".format(addr))

  def store_word(self, addr, val):
    raise MemoryAccessException(
        "Can't store word to address {:08x}".format(addr))

  def store_dword(self, addr, val):
    raise MemoryAccessException(
        "Can't store dword to address {:08x}".format(addr))

  def store_qword(self, addr, val):
    raise MemoryAccessException(
        "Can't store qword to address {:08x}".format(addr))

  def store_bytes(self, addr, data):
    raise MemoryAccessException(
        "Can't store {} bytes to address {:08x}".format(len(data), addr))
  


class PermissionedMemoryMap(MemoryMap):
  def __init__(self, ops, base, limit, can_read=True, can_write=True,
               can_execute=False):
    assert base < limit
    self._ops = ops
    self._base = base
    self._limit = limit
    self._can_read = can_read
    self._can_write = can_write
    self._can_execute = can_execute

  def can_read(self, byte_addr):
    return self._can_read and self._base <= byte_addr < self._limit

  def can_write(self, byte_addr):
    return self._can_write and self._base <= byte_addr < self._limit

  def can_execute(self, byte_addr):
    return self._can_execute and self._base <= byte_addr < self._limit

  def base(self):
    return self._base

  def limit(self):
    return self._limit


class ArrayMemoryMap(PermissionedMemoryMap):
  def __init__(self, ops, base, limit, can_read=True, can_write=True,
               can_execute=False):
    super(ArrayMemoryMap, self).__init__(ops, base, limit, can_read, can_write,
                                         can_execute)
    self._data = [0] * (limit - base)

  def load_byte(self, addr):
    offset = addr - self._base
    return self._ops.convert_to_byte_string(self._data[offset:(offset + 1)])

  def load_word(self, addr):
    offset = addr - self._base
    return self._ops.convert_to_byte_string(self._data[offset:(offset + 2)])

  def load_dword(self, addr):
    offset = addr - self._base
    return self._ops.convert_to_byte_string(self._data[offset:(offset + 4)])

  def load_qword(self, addr):
    offset = addr - self._base
    return self._ops.convert_to_byte_string(self._data[offset:(offset + 8)])

  def load_bytes(self, addr, num_bytes):
    offset = addr - self._base
    return self._data[offset:(offset + num_bytes)]

  def store_byte(self, addr, data):
    if isinstance(data, (int,)):
      data = struct.unpack("BBBBBBBB", struct.pack("<Q", data))
    self.store_bytes(addr, data[:1])

  def store_word(self, addr, data):
    if isinstance(data, (int,)):
      data = struct.unpack("BBBBBBBB", struct.pack("<Q", data))
    self.store_bytes(addr, data[:2])

  def store_dword(self, addr, data):
    if isinstance(data, (int,)):
      data = struct.unpack("BBBBBBBB", struct.pack("<Q", data))
    self.store_bytes(addr, data[:4])

  def store_qword(self, addr, data):
    if isinstance(data, (int,)):
      data = struct.unpack("BBBBBBBB", struct.pack("<Q", data))
    self.store_bytes(addr, data[:8])

  def store_bytes(self, addr, data):
    offset = addr - self._base
    for b in data:
      if isinstance(b, str):
        b = ord(b)
      self._data[offset] = b
      offset += 1


class Memory(object):
  def __init__(self, ops, address_size, page_shift=12):
    assert address_size in (32, 64)
    assert 0 < page_shift < 32
    self._ops = ops
    self._address_size = address_size
    self._address_mask = (1 << self._address_size) - 1
    self._page_shift = page_shift
    self._memory_maps = collections.defaultdict(MemoryMap)

  def _find_map(self, byte_addr):
    return self._memory_maps[(byte_addr & self._address_mask) >> self._page_shift]

  def _crosses_pages(self, addr, num_bytes):
    mmap = self._find_map(addr)
    i = 1
    while i < num_bytes:
      if self._find_map(addr + i) != mmap:
        return True
      i += 1
    return False
  
  def address_size_bits(self):
    return self._address_size

  def add_map(self, mmap):
    base, limit = mmap.base(), mmap.limit()
    assert ((base >> self._page_shift) << self._page_shift) == base
    while base < limit:
      self._memory_maps[(base & self._address_mask) >> self._page_shift] = mmap
      base += 1 << self._page_shift

  def can_read(self, byte_addr):
    return self._find_map(byte_addr).can_read(byte_addr)

  def can_write(self, byte_addr):
    return self._find_map(byte_addr).can_write(byte_addr)

  def can_execute(self, byte_addr):
    return self._find_map(byte_addr).can_execute(byte_addr)

  def load(self, addr, num_bytes):
    if num_bytes in (1, 2, 4, 8) and not self._crosses_pages(addr, num_bytes):
      if 1 == num_bytes:
        return self._find_map(addr).load_byte(addr)
      elif 2 == num_bytes:
        return self._find_map(addr).load_word(addr)
      elif 4 == num_bytes:
        return self._find_map(addr).load_dword(addr)
      else:
        return self._find_map(addr).load_qword(addr)
    else:
      reads = []
      i = 0
      while i < num_bytes:
        byte_addr = addr + i
        i += 1
        reads.append(self._find_map(byte_addr).load_bytes(byte_addr, 1)[0])
      return self._ops.convert_to_byte_string(reads)

  def store(self, addr, data):
    num_bytes = len(data)
    if num_bytes in (1, 2, 4, 8) and not self._crosses_pages(addr, num_bytes):
      if 1 == num_bytes:
        self._find_map(addr).store_byte(addr, data)
      elif 2 == num_bytes:
        self._find_map(addr).store_word(addr, data)
      elif 4 == num_bytes:
        self._find_map(addr).store_dword(addr, data)
      else:
        self._find_map(addr).store_qword(addr, data)
    else:
      i = 0
      while i < num_bytes:
        byte_addr = addr + i
        self._find_map(byte_addr).store_bytes(byte_addr, data[i:i+1])
        i += 1


class Thread(object):
  REG_HINT_NONE = 0
  REG_HINT_GENERAL = 1
  REG_HINT_PROGRAM_COUNTER = 2
  REG_HINT_CONDITION_CODE = 3
  REG_HINT_WRITE_BACK = 4
  REG_HINT_MEMORY_BASE_ADDRESS = 5
  REG_HINT_MEMORY_INDEX_ADDRESS = 6
  REG_HINT_MEMORY_SEGMENT_ADDRESS = 7

  def __init__(self, ops):
    self._regs = collections.defaultdict(int)
    self._fpu_data = b'\0' * 512
    self._ops = ops

  def read_register(self, reg_name, hint):
    return self._regs[reg_name]

  def write_register(self, reg_name, value):
    self._regs[reg_name] = value

  def read_fpu(self):
    return self._fpu_data

  def write_fpu(self, new_fpu_data):
    self._fpu_data = new_fpu_data


class Process(Executor):
  MEM_HINT_READ_ONLY = 0
  MEM_HINT_READ_EXECUTABLE = 1
  MEM_HINT_WRITE_ONLY = 2
  MEM_HINT_READ_WRITE = 3
  MEM_HINT_ADDRESS_GEN = 4

  MEM_READ_HINTS = (MEM_HINT_READ_ONLY,
                    MEM_HINT_READ_EXECUTABLE,
                    MEM_HINT_READ_WRITE)

  MEM_WRITE_HINTS = (MEM_HINT_WRITE_ONLY,
                     MEM_HINT_READ_WRITE)

  MEM_EXEC_HINTS = (MEM_HINT_READ_EXECUTABLE,)

  def __init__(self, ops, memory):
    assert isinstance(memory, Memory)
    super(Process, self).__init__(memory.address_size_bits())
    self._memory = memory
    self._thread = None
    self._ops = ops

  def execute(self, thread, max_num_instructions=1):
    assert 0 < max_num_instructions
    assert isinstance(thread, Thread)

    self._thread = thread
    try:
      super(Process, self).execute(max_num_instructions)
    finally:
      self._thread = None

  def read_register(self, reg_name, hint):
    return self._thread.read_register(reg_name, hint)

  def write_register(self, reg_name, val):
    self._thread.write_register(reg_name, self._ops.convert_to_integer(val))

  def compute_address(self, seg_name, base_addr, index, scale, disp, size, hint):
    seg_base = 0
    if hint != self.MEM_HINT_ADDRESS_GEN:
      seg_base = self._ops.convert_to_integer(self.read_register(
          "{}_BASE".format(seg_name), Thread.REG_HINT_MEMORY_SEGMENT_ADDRESS))
      seg_base = seg_base & self._memory._address_mask
    return seg_base + base_addr + (index * scale) + disp 

  def read_memory(self, addr, num_bytes, hint):
    check_read = hint in self.MEM_READ_HINTS  
    check_write = hint in self.MEM_WRITE_HINTS
    check_exec = hint in self.MEM_EXEC_HINTS

    # Check permissions
    i = 0;
    while i < num_bytes:
      byte_addr = addr + i
      i += 1

      if check_read:
        if not self._memory.can_read(byte_addr):
          raise MemoryAccessException(
              "Address {:08x} is not readable".format(byte_addr))

      if check_write:
        if not self._memory.can_write(byte_addr):
          raise MemoryAccessException(
              "Address {:08x} is not writable".format(byte_addr))

      if check_exec:
        if not self._memory.can_execute(byte_addr):
          raise MemoryAccessException(
              "Address {:08x} is not executable".format(byte_addr))
    return self._memory.load(addr, num_bytes)

  def write_memory(self, addr, data):
    self._memory.store(addr, data)

  # The FPU is treated as an opaque blob of memory.
  def read_fpu(self):
    return self._thread.read_fpu()

  def write_fpu(self, fpu):
    self._thread.write_fpu(fpu)
