#pragma once
#ifndef __INSTRUCTIONS_H
#define __INSTRUCTIONS_H

#include "common.h"
#include "interpreter.h"

#define MAX_OPERANDS_COUNT (4)

/* Forward decleration */
typedef struct interpreter_script_s interpreter_script_t;

typedef enum instruction_type_e
{
    INSTRUCTION_TYPE_NOP,
    INSTRUCTION_TYPE_LABEL,
    INSTRUCTION_TYPE_CALL,
    INSTRUCTION_TYPE_RETURN,
    INSTRUCTION_TYPE_JUMP,
    INSTRUCTION_TYPE_COMPARE_BRANCH_ZERO,
    INSTRUCTION_TYPE_DEFINE_VAR,
    INSTRUCTION_TYPE_MOV_VAR,
    INSTRUCTION_TYPE_PRINT_VAR,
    INSTRUCTION_TYPE_LOAD_REG,
    INSTRUCTION_TYPE_STORE_REG,
    INSTRUCTION_TYPE_ADD,
    INSTRUCTION_TYPE_SUB
} instruction_type_t;

typedef enum instruction_execution_command_e
{
    INSTRUCTION_EXEC_CMD_ERROR = -1,
    INSTRUCTION_EXEC_CMD_RET = -2,
    INSTRUCTION_EXEC_CMD_CONT = -3
} instruction_execution_command_t;

typedef struct interpreter_instruction_s
{
    instruction_type_t type;
    union instruction_operands
    {
        struct label_operands_s
        {
            const char * label_name;
        } label_operands;

        struct call_operands_s
        {
            const char * label_name;
        } call_operands;

        struct jump_operands_s
        {
            const char * label_name;
        } jump_operands;

        struct cbz_operands_s
        {
            const char * var_name;
            const char * label_name;
        } cbz_operands;

        struct def_operands_s
        {
            const char * var_name;
            const char * var_value;
        } def_operands;

        struct mov_operands_s
        {
            const char * dest_name;
            const char * src_name;
        } mov_operands;

        struct print_operands_s
        {
            const char * var_name;
        } print_operands;

        struct add_operands_s
        {
            const char * dest_var;
            const char * op1_var;
            const char * op2_var;
        } add_operands;

        struct sub_operands_s
        {
            const char * dest_var;
            const char * op1_var;
            const char * op2_var;
        } sub_operands;

        struct load_operands_s
        {
            const char * dest_var_name;
            const char * src_reg_name;
        } load_operands;

        struct store_operands_s
        {
            const char * dest_reg_name;
            const char * src_var_name;
        } store_operands;

    } operands;
    // Arguments
} interpreter_instruction_t;

typedef const char * instruction_operands_t[MAX_OPERANDS_COUNT];

/* Parses the operands in 'operands' and fills-in 'instruction' with the correct representation.
 */
typedef int (*instruction_parse_func_t)(interpreter_instruction_t * instruction, instruction_operands_t operands);

/* Free the memory allocated by the 'instruction_parse_func_t'.
 * Notice that using the instruction after calling 'free' results in undefined behaviour.
 */
typedef int (*instruction_free_func_t)(interpreter_instruction_t * instruction);

/* Executes the instruction in 'instruction_index' from the current 'script'.
 * Returns:
 * INSTRUCTION_EXEC_CMD_ERROR - on error
 * INSTRUCTION_EXEC_CMD_RET - on return
 * INSTRUCTION_EXEC_CMD_CONT - continue to next instruction
 * Otherwise - the index of the next instruction to be executed
 */
typedef size_t (*instruction_exec_func_t)(interpreter_script_t * script, interpreter_instruction_t * instruction);

typedef struct instruction_definition_s
{
    const char * token;
    instruction_parse_func_t parse_func;
    instruction_free_func_t free_func;
    instruction_exec_func_t exec_func;
} instruction_definition_t;

int init_interpreter_instruction(interpreter_instruction_t * inst);
int destruct_interpreter_instruction(interpreter_instruction_t * inst);

extern instruction_definition_t instruction_definitions[];
extern const size_t instruction_definitions_size;

#endif /* __INSTRUCTIONS_H */
