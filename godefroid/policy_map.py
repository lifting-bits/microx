from flag_map import FlaggedMemoryMap, PolicyFlags
import sys
import copy

class PolicyMemoryMap(FlaggedMemoryMap):
    def __init__(self, ops, base, limit, access_flags, policy, mapname=None):
        super(PolicyMemoryMap, self).__init__(ops, base, limit, access_flags, mapname)
        self._data = [0] * (limit - base)
        self._policy = policy
        self._access_map = {}

    def __deepcopy__(self, memo):
        # We do not want to copy access maps
        # and want to do a shallow copy of _data
        cp = PolicyMemoryMap(self._ops, self._base, self._limit,
            self._access_flags,
            copy.deepcopy(self._policy, memo),
            self.get_name())
        cp._data = self._data[:]

        return cp

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

    def store_bytes_raw(self, addr, data):
        """ Does a store bytes without policy checks """
        return self._store_bytes(addr, data)

    def store_bytes(self, addr, data):
        self._store_policy(addr, len(data))
        return self._store_bytes(addr, data)
