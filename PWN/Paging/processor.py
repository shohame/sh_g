from unicorn.arm_const import *
from paging import Paging
from unicorn import *
from consts import *
import struct


class Processor:
    """
    Representation of the current emulated CPU.
    """

    def __init__(self, uc):
        self.paging = Paging(uc, 0)
        self._uc = uc
        self._allocated_list = []
        self._mem_alloc = None

    def is_paging_activated(self):
        return self.paging.is_activated()

    def _get_TTBR0_reg(self):
        return self._uc.reg_read(TTBR0)

    def _free_alloc_mapping(self):
        for a in self._allocated_list:
            self._uc.mem_unmap(a, PAGE)

        self._allocated_list = []

    def activate_paging(self):
        print("Activate paging")
        self.paging.activate()

        self._mem_alloc = self._uc.reg_read(ARM_REG_PC) & PAGE_MASK
        self._uc.mem_map(self._mem_alloc, PAGE, UC_PROT_WRITE | UC_PROT_READ | UC_PROT_EXEC)

        buffer = b''
        for x in range(0, PAGE // 4, SIZE_OF_PTR):
            buffer += self.paging.read(self._mem_alloc + x)
        self._uc_write_align(self._mem_alloc, buffer)

    def deactivate_paging(self):
        print("Deactivate paging")

        self._free_alloc_mapping()
        self._uc.mem_unmap(self._mem_alloc, PAGE)

        self._mem_alloc = None
        self.paging.deactivate()

    def _uc_write_align(self, address, value):
        address_aligned = address & PAGE_MASK
        offset = address - address_aligned

        orig = self._uc.mem_read(address_aligned, PAGE)
        new_val = orig[:offset] + value + orig[offset + len(value):]
        self._uc.mem_write(address_aligned, bytes(new_val))

    def read(self, address, size, is_fetch=False):
        if not is_fetch:
            self._allocate_if_not_exists(address)

            value = self.paging.read(address)

            self._uc_write_align(address, value)

    def _allocate_if_not_exists(self, address):
        if address & PAGE_MASK not in self._allocated_list:
            self._uc.mem_map(address & PAGE_MASK, PAGE, UC_PROT_WRITE | UC_PROT_READ | UC_PROT_EXEC)
            self._allocated_list.append(address & PAGE_MASK)

    def write(self, address, size, value):
        self._allocate_if_not_exists(address)
        self.paging.write(address, value)
