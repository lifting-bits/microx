import microx
from flags import Flags

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
