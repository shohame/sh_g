from consts import *


class Entry:
    """
    Representation of a page-table entry.
    """

    def __init__(self, entry):
        self.entry = entry
        self.unpack(entry)

    def unpack(self, entry):
        self.flags = entry & 0xFFF
        self.address = entry & 0xFFFFF000

        self.unpack_flags(self.flags)

    def unpack_flags(self, flags):
        self.present = flags & 1
        flags >>= 1
        self.write = flags & 1
        flags >>= 1
        self.accessed = flags & 1
        flags >>= 1
        self.dirty = flags & 1
        flags >>= 1
        self.nx = flags & 1

    def pack(self):
        return self.address | self.pack_flags()

    def pack_flags(self):
        flags = 0
        flags |= self.nx
        flags <<= 1
        flags |= self.dirty
        flags <<= 1
        flags |= self.accessed
        flags <<= 1
        flags |= self.write
        flags <<= 1
        flags |= self.present

        return flags
