from hypercall import Hypercall
from unicorn.arm_const import *
from entry import Entry
from unicorn import *
from consts import *
import struct


class Paging:
    """
    Paging implementation for the emulated CPU.
    Notice this is not actually the ARM implementation, but our
    own, custom implementation (but pretty standard nonetheless).
    TTBR0 here is the register pointing to the translation table base
    (similar to actual TTBR0 in ARMv7, or CR3 in x86).
    """

    READ = 0
    WRITE = 1
    EXEC = 2

    def __init__(self, uc, TTBR0):
        self._hypercall = Hypercall()
        self._TTBR0 = TTBR0
        self._activated = 0
        self._uc = uc

    def is_activated(self):
        return self._activated

    def run_hypercall(self, hypercall_idx, arg1, arg2):
        """
        Hyper-call implementation is dependent on the paging mechanism being active.
        """
        if not self.is_activated():
            raise OSError("hypercalls are not available if paging is off")

        hypercall_page = self._physical_memory[:PAGE]

        # In order for supporting hypercalls with buffer
        # Paging module will extract memory for string-hypercalls and pass them to hypercall as bytes
        if hypercall_idx >= STRING_HYPERCALLS:
            buffer = b''
            for address in range(arg1, arg1 + arg2, SIZE_OF_PTR):
                buffer += self.read(address)

            arg1 = buffer

        ret, hypercall_page = self._hypercall.run(hypercall_page, hypercall_idx, arg1, arg2)

        # If idx is for string-hypercalls and the return value is not int, returning the buffer to user
        if hypercall_idx >= STRING_HYPERCALLS and not isinstance(ret, int):
            i = 0
            for address in range(arg1, arg1 + arg2, SIZE_OF_PTR):
                self.write(address, ret[i: i + SIZE_OF_PTR])
                i += SIZE_OF_PTR
        else:
            self._uc.reg_write(ARM_REG_R0, ret)

        self._write_memory(HYPERCALL_PAGE_ADDR, hypercall_page)

    def activate(self):
        self._activated = True

        hypercall_page = self._hypercall.activate()
        self._set_physical_mem(hypercall_page)

    def deactivate(self):
        self._activated = False

        hypercall_page = self._restore_physical_mem()
        self._hypercall.deactivate(hypercall_page)

    def write(self, v_addr, value):
        if not isinstance(value, bytes):
            value = struct.pack("<I", value)

        p_addr = self.v_to_p(v_addr, self.WRITE)
        self.set_p_value(p_addr, value)

    def fetch(self, v_addr):
        p_addr = self.v_to_p(v_addr, self.EXEC)

        p_val = self.get_p_value(p_addr)
        return p_val

    def read(self, v_addr):
        p_addr = self.v_to_p(v_addr, self.READ)

        p_val = self.get_p_value(p_addr)
        return p_val

    def _validate_entry(self, Pentry, entry, prot):
        entry.accessed = 1
        if prot == self.WRITE:
            entry.dirty = 1

        entry_packed = entry.pack()
        self._write_memory(Pentry, struct.pack("<I", entry_packed))

        if entry.present == 0:
            raise OSError(f"Error: trying to resolve an unpreset address {entry_packed:x}")
        if prot == self.WRITE and entry.write == 0:
            raise OSError(f"Error: trying to write to unwriteable address {entry_packed:x}")
        if prot == self.EXEC and entry.nx == 1:
            raise OSError(f"Error: trying to fetch instruction from no-execute address {entry_packed:x}")

    def set_TTBR0(self, TTBR0):
        print("Setting TTBR0")
        self._TTBR0 = TTBR0

    def _get_pde(self, v_addr, prot):
        TTBR0 = self._TTBR0

        offset = (v_addr >> 22) & 0x3ff

        PPDE = TTBR0 + (offset * SIZE_OF_PTR)
        PDE = self._physical_memory[PPDE: PPDE + SIZE_OF_PTR]
        PDE = struct.unpack("<I", PDE)[0]

        pde = Entry(PDE)

        self._validate_entry(PPDE, pde, prot)

        return pde.address

    def _get_pte(self, PDE_address, v_addr, prot):
        offset = (v_addr & 0x3fffff) >> 12

        PPTE = PDE_address + (offset * SIZE_OF_PTR)
        PTE = self._physical_memory[PPTE: PPTE + SIZE_OF_PTR]
        PTE = struct.unpack("<I", PTE)[0]

        pte = Entry(PTE)
        self._validate_entry(PPTE, pte, prot)

        return pte.address

    def _get_p_addr(self, PTE_address, v_addr, prot):
        offset = v_addr & 0xfff
        PPH = PTE_address + offset

        return PPH

    def v_to_p(self, v_addr, prot):
        try:
            PDE = self._get_pde(v_addr, prot)
            PTE = self._get_pte(PDE, v_addr, prot)
            p_addr = self._get_p_addr(PTE, v_addr, prot)
        except struct.error:
            raise OSError(f"Error translating virtual memory {v_addr:x}")

        if HYPERCALL_PAGE_ADDR <= p_addr < HYPERCALL_PAGE_ADDR + PAGE:
            raise OSError("Error ! page 0 is not available")

        return p_addr

    def get_p_value(self, p_addr, size=SIZE_OF_PTR):
        val = self._physical_memory[p_addr:p_addr + size]
        if len(val) != size:
            raise OSError(f"Error reading from physical memory {p_addr:x}")

        return val

    def set_p_value(self, p_addr, value, size=SIZE_OF_PTR):
        if len(value) != size:
            raise OSError(f"Error writing to physical memory {p_addr:x}")
        self._write_memory(p_addr, value, size)

    def _write_memory(self, offset, data, size=None):
        if size is None:
            size = len(data)

        self._physical_memory = self._physical_memory[:offset] + data[:size] + self._physical_memory[offset + size:]

    def _restore_physical_mem(self):
        hypercall_page = self._physical_memory[:PAGE]

        self._uc.mem_map(PHYSICAL_MEM_ADDR, PHYSICAL_MEM_SIZE, UC_PROT_WRITE | UC_PROT_READ | UC_PROT_EXEC)
        self._uc.mem_write(HYPERCALL_PAGE_ADDR, bytes(self._page_to_restore))
        self._uc.mem_write(HYPERCALL_PAGE_ADDR + PAGE, bytes(self._physical_memory[PAGE:]))

        return hypercall_page

    def _set_physical_mem(self, hypercall_page):
        assert len(hypercall_page) == PAGE

        self._physical_memory = self._uc.mem_read(PHYSICAL_MEM_ADDR, PHYSICAL_MEM_SIZE)
        self._page_to_restore = self._physical_memory[:PAGE]

        self._write_memory(HYPERCALL_PAGE_ADDR, hypercall_page)
        self._uc.mem_unmap(PHYSICAL_MEM_ADDR, PHYSICAL_MEM_SIZE)

    def page_fault(self, addr, size, reason):
        print(f"Page fault occured, addr: '{addr}', size: '{size}', reason: {reason}")
