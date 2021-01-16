#! /usr/bin/python3

from processor import Processor
from unicorn.arm_const import *
from capstone.arm64 import *
from keystone import *
from capstone import *
from unicorn import *
from consts import *
import readline
import signal
import sys
import os

ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
cs = Cs(CS_ARCH_ARM, KS_MODE_LITTLE_ENDIAN)
cs.detail = True


def hook_write(uc, access, address, size, value, processor):
    try:
        if processor.is_paging_activated():
            processor.write(address, size, value)

    except (OSError, ValueError, AssertionError) as e:
        processor.paging.page_fault(address, size, e)
    return True


def hook_read(uc, access, address, size, value, processor):
    try:
        if processor.is_paging_activated():
            processor.read(address, size)

    except (OSError, ValueError, AssertionError) as e:
        processor.paging.page_fault(address, size, e)
    return True


def extract_operand_val(uc, insn, operand):
    if operand.type == ARM_OP_REG:
        reg_val = uc.reg_read(operand.value.reg)
        return reg_val
    elif operand.type == ARM_OP_IMM:
        return operand.value.imm
    else:
        raise ValueError("moving into special register available only with immidiate or register")


def hook_intr(uc, intno, processor):
    address = uc.reg_read(ARM_REG_PC) - 4
    inst = uc.mem_read(address, 4)

    for insn in cs.disasm(inst, address):
        if insn.mnemonic != "svc":
            print(f"Unknown interrupt")
            return

        svc_num = extract_operand_val(uc, insn, insn.operands[0])
        arg = uc.reg_read(ARM_REG_R0)

        if svc_num == PAGING_DISABLE:
            if processor.is_paging_activated():
                processor.deactivate_paging()

        elif svc_num == PAGING_ENABLE:
            if not processor.is_paging_activated():
                processor.activate_paging()

        elif svc_num == TTBR0:
            processor.paging.set_TTBR0(arg)

        elif svc_num == HYPERCALL_REG:
            arg1 = uc.reg_read(ARM_REG_R1)
            arg2 = uc.reg_read(ARM_REG_R2)
            processor.paging.run_hypercall(arg, arg1, arg2)

        elif svc_num == AUTHENTICATE_SVC:
            if processor.is_paging_activated():
                processor.paging.hypercall.authenticate(arg)

        elif svc_num == EXIT_SVC:
            print("Exiting...")
            os._exit(12)
        else:
            print(f"SVC {svc_num} is not supported")
        return


def hook_code(uc, address, size, processor):
    try:
        if processor.is_paging_activated():
            processor.read(address, size, is_fetch=True)
    except (OSError, ValueError, AssertionError) as e:
        processor.paging.page_fault(address, size, e)

    inst = uc.mem_read(address, size)

    for insn in cs.disasm(inst, address):
        print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

    return True


def reset_registers(mu):
    for idx in range(15):
        mu.reg_write(UC_ARM_REG_R0 + idx, 0)


def vm(code):
    try:
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        processor = Processor(uc)

        reset_registers(uc)

        # Allocating physical memory
        uc.mem_map(PHYSICAL_MEM_ADDR, PHYSICAL_MEM_SIZE, UC_PROT_WRITE | UC_PROT_READ | UC_PROT_EXEC)

        # Copying code
        assert len(code) < PAGE
        uc.mem_write(CODE_ADDRESS, code)

        uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_READ_UNMAPPED |
                    UC_HOOK_MEM_FETCH_UNMAPPED, hook_read, user_data=processor)
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_WRITE_UNMAPPED, hook_write, user_data=processor)
        uc.hook_add(UC_HOOK_CODE, hook_code, user_data=processor)
        uc.hook_add(UC_HOOK_INTR, hook_intr, user_data=processor)

        uc.emu_start(CODE_ADDRESS, CODE_ADDRESS + len(code))

    except unicorn.UcError as e:
        if len(code) == uc.reg_read(UC_ARM_REG_PC):
            return
        print(f"Error {(type(e).__name__)}: {e} occured, try again")
        print(f"registers r0:{uc.reg_read(UC_ARM_REG_R0):x} "
              f"r1:{uc.reg_read(UC_ARM_REG_R1):x} "
              f"r2:{uc.reg_read(UC_ARM_REG_R2):x} "
              f"r3:{uc.reg_read(UC_ARM_REG_R3):x} "
              f"r4:{uc.reg_read(UC_ARM_REG_R4):x} "
              f"r5:{uc.reg_read(UC_ARM_REG_R5):x} "
              f"pc:{uc.reg_read(UC_ARM_REG_PC):x} "
              )


def execution_timeout_handler(signum, frame):
    print("Execution timeout reached!")
    os._exit(0)


def set_execution_timeout():
    signal.signal(signal.SIGALRM, execution_timeout_handler)
    signal.alarm(EXECUTION_TIMEOUT)


def main():
    sys.stderr = sys.stdout
    set_execution_timeout()
    try:
        print("Enter armv7-a code, terminate via 'exit' line")
        asm_code = []
        asm_line = ""
        for _ in range(MAX_ASM_LINES):    
            asm_line = sys.stdin.readline().strip()
            if asm_line.startswith("exit"):
                break
            if asm_line and asm_line[0] not in ['.', '@']:
                asm_code.append(asm_line)

        asm_code = ";".join(asm_code)

        encoding, _ = ks.asm(asm_code)
        vm(bytes(encoding))

    except keystone.KsError as e:
        print(f"Error {(type(e).__name__)}: {e} occured, try again")


if __name__ == "__main__":
    main()
