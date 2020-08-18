import sys
from enum import Enum
import secrets
import collections


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


class InputType(Enum):
    DATA = 0
    POINTER = 1
    COMPUTED = 2


class InputMemoryPolicy:

    # TODO(artem): Make this a configurable value or based on address size
    POINTER_INCREMENT = int(0x1000 / 4)

    def __deepcopy__(self, memo):
        # Just create a new one. We do not care about
        # copying access ranges for what we're doing
        cp = InputMemoryPolicy(
            self._address_size * 8,
            (self._start, self._end),
            (self._pointers_start, self._pointers_end),
        )
        return cp

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

    def in_input_range(self, addr):

        # is it a known input?
        if addr in self._known_inputs:
            return True

        # is it a pointer to the input heap?
        if self._pointers_start <= addr < self._pointers_end:

            if addr > self._pointer_watermark:
                self._pointer_watermark += InputMemoryPolicy.POINTER_INCREMENT
                assert self._pointer_watermark < self._pointers_end

            return True

        # is it on the stack?
        if self._start <= addr < self._end:

            return True

        # Its probably not an input
        return False

    def handle_compute(self, result, base, scale, index, disp, size, hint):

        parts = (base, scale, index, disp)

        if self.in_input_range(result):
            # Computed address is an input range, mark it as input
            self._known_inputs[result] = size
        else:
            # TODO(artem): This code may not be necessary
            # Is the address computed from an input address?
            for p in parts:
                # NOTE(artem): the check for input address zero is here purely for sanity checking
                if p in self._known_inputs and p != 0:
                    sys.stdout.write(
                        f"Input Address: {p:08x} used to compute {result:08x}\n"
                    )
                    sys.stdout.write(f"\tAdding {result:08x} to inputs")

                    # Add a new 'computed' input address
                    self._known_inputs[result] = size
                    sys.stdout.write(
                        "!!! Failed in_input_range but computed from known input\n"
                    )
                    break

        return result
