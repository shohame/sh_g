/*
 * This file contains the definitions of the instructions:
 * what is the string represents them, what is their parse function and what is their execution function.
 */
#include "instructions.h"
#include "execute_instructions.h"
#include "parse_instructions.h"

int init_interpreter_instruction(interpreter_instruction_t * inst)
{
    memset(inst, 0, sizeof(*inst));
    inst->type = INSTRUCTION_TYPE_NOP;
    return 0;
}

int destruct_interpreter_instruction(interpreter_instruction_t * inst)
{
    int ret = 0;
    if (instruction_definitions[inst->type].free_func(inst) != 0)
    {
        ret = -1;
        goto cleanup;
    }

cleanup:
    inst->type = INSTRUCTION_TYPE_NOP;
    return ret;
}

instruction_definition_t instruction_definitions[] = {
    [INSTRUCTION_TYPE_NOP] = {"nop", parse_nop, free_nop, exec_nop},
    [INSTRUCTION_TYPE_LABEL] = {"label", parse_label, free_label, exec_label},
    [INSTRUCTION_TYPE_CALL] = {"call", parse_call, free_call, exec_call},
    [INSTRUCTION_TYPE_RETURN] = {"ret", parse_ret, free_ret, exec_ret},
    [INSTRUCTION_TYPE_JUMP] = {"jmp", parse_jmp, free_jmp, exec_jmp},
    [INSTRUCTION_TYPE_COMPARE_BRANCH_ZERO] = {"cbz", parse_cbz, free_cbz, exec_cbz},
    [INSTRUCTION_TYPE_DEFINE_VAR] = {"def", parse_def, free_def, exec_def},
    [INSTRUCTION_TYPE_MOV_VAR] = {"mov", parse_mov, free_mov, exec_mov},
    [INSTRUCTION_TYPE_PRINT_VAR] = {"print", parse_print, free_print, exec_print},
    [INSTRUCTION_TYPE_ADD] = {"add", parse_add, free_add, exec_add},
    [INSTRUCTION_TYPE_SUB] = {"sub", parse_sub, free_sub, exec_sub},
    [INSTRUCTION_TYPE_STORE_REG] = {"store", parse_store, free_store, exec_store},
    [INSTRUCTION_TYPE_LOAD_REG] = {"load", parse_load, free_load, exec_load}};
const size_t instruction_definitions_size = NELEM(instruction_definitions);
