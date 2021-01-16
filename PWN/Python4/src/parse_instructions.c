
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "parse_instructions.h"

int parse_nop(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_NOP;
    if (operands[0] != NULL)
    {
        return -1;
    }
    return 0;
}

int free_nop(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_NOP)
    {
        return -1;
    }
    return 0;
}

int parse_label(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_LABEL;
    if (operands[0] == NULL || operands[1] != NULL)
    {
        return -1;
    }
    instruction->operands.label_operands.label_name = strdup(operands[0]);
    return 0;
}

int free_label(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_LABEL)
    {
        return -1;
    }

    free((void *)instruction->operands.label_operands.label_name);
    instruction->operands.label_operands.label_name = NULL;

    return 0;
}

int parse_call(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_CALL;
    if (operands[0] == NULL || operands[1] != NULL)
    {
        return -1;
    }
    instruction->operands.call_operands.label_name = strdup(operands[0]);
    return 0;
}

int free_call(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_CALL)
    {
        return -1;
    }

    free((void *)instruction->operands.call_operands.label_name);
    instruction->operands.call_operands.label_name = NULL;

    return 0;
}

int parse_ret(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_RETURN;
    if (operands[0] != NULL)
    {
        return -1;
    }
    return 0;
}

int free_ret(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_RETURN)
    {
        return -1;
    }

    return 0;
}

int parse_jmp(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_JUMP;
    if (operands[0] == NULL || operands[1] != NULL)
    {
        return -1;
    }
    instruction->operands.jump_operands.label_name = strdup(operands[0]);
    return 0;
}

int free_jmp(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_JUMP)
    {
        return -1;
    }

    free((void *)instruction->operands.jump_operands.label_name);
    instruction->operands.jump_operands.label_name = NULL;

    return 0;
}

int parse_cbz(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_COMPARE_BRANCH_ZERO;
    if (operands[0] == NULL || operands[1] == NULL || operands[2] != NULL)
    {
        return -1;
    }

    instruction->operands.cbz_operands.var_name = strdup(operands[0]);
    instruction->operands.cbz_operands.label_name = strdup(operands[1]);
    return 0;
}

int free_cbz(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_COMPARE_BRANCH_ZERO)
    {
        return -1;
    }

    free((void *)instruction->operands.cbz_operands.label_name);
    instruction->operands.cbz_operands.label_name = NULL;

    free((void *)instruction->operands.cbz_operands.var_name);
    instruction->operands.cbz_operands.var_name = NULL;

    return 0;
}

int parse_def(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_DEFINE_VAR;
    if (operands[0] == NULL || operands[1] == NULL || operands[2] != NULL)
    {
        return -1;
    }

    instruction->operands.def_operands.var_name = strdup(operands[0]);
    instruction->operands.def_operands.var_value = strdup(operands[1]);
    return 0;
}

int free_def(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_DEFINE_VAR)
    {
        return -1;
    }

    free((void *)instruction->operands.def_operands.var_value);
    instruction->operands.def_operands.var_value = NULL;

    free((void *)instruction->operands.def_operands.var_name);
    instruction->operands.def_operands.var_name = NULL;

    return 0;
}

int parse_mov(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_MOV_VAR;
    if (operands[0] == NULL || operands[1] == NULL || operands[2] != NULL)
    {
        return -1;
    }

    instruction->operands.mov_operands.dest_name = strdup(operands[0]);
    instruction->operands.mov_operands.src_name = strdup(operands[1]);
    return 0;
}

int free_mov(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_MOV_VAR)
    {
        return -1;
    }

    free((void *)instruction->operands.mov_operands.src_name);
    instruction->operands.mov_operands.src_name = NULL;

    free((void *)instruction->operands.mov_operands.dest_name);
    instruction->operands.mov_operands.dest_name = NULL;

    return 0;
}

int parse_print(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_PRINT_VAR;
    if (operands[0] == NULL || operands[1] != NULL)
    {
        return -1;
    }

    instruction->operands.print_operands.var_name = strdup(operands[0]);
    return 0;
}

int free_print(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_PRINT_VAR)
    {
        return -1;
    }

    free((void *)instruction->operands.print_operands.var_name);
    instruction->operands.print_operands.var_name = NULL;

    return 0;
}

int parse_add(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_ADD;
    if (operands[0] == NULL || operands[1] == NULL || operands[2] == NULL || operands[3] != NULL)
    {
        return -1;
    }

    instruction->operands.add_operands.dest_var = strdup(operands[0]);
    instruction->operands.add_operands.op1_var = strdup(operands[1]);
    instruction->operands.add_operands.op2_var = strdup(operands[2]);
    return 0;
}

int free_add(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_ADD)
    {
        return -1;
    }

    free((void *)instruction->operands.add_operands.op2_var);
    instruction->operands.add_operands.op2_var = NULL;

    free((void *)instruction->operands.add_operands.op1_var);
    instruction->operands.add_operands.op1_var = NULL;

    free((void *)instruction->operands.add_operands.dest_var);
    instruction->operands.add_operands.dest_var = NULL;

    return 0;
}

int parse_sub(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_SUB;
    if (operands[0] == NULL || operands[1] == NULL || operands[2] == NULL || operands[3] != NULL)
    {
        return -1;
    }

    instruction->operands.sub_operands.dest_var = strdup(operands[0]);
    instruction->operands.sub_operands.op1_var = strdup(operands[1]);
    instruction->operands.sub_operands.op2_var = strdup(operands[2]);
    return 0;
}

int free_sub(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_SUB)
    {
        return -1;
    }

    free((void *)instruction->operands.sub_operands.op2_var);
    instruction->operands.sub_operands.op2_var = NULL;

    free((void *)instruction->operands.sub_operands.op1_var);
    instruction->operands.sub_operands.op1_var = NULL;

    free((void *)instruction->operands.sub_operands.dest_var);
    instruction->operands.sub_operands.dest_var = NULL;

    return 0;
}

int parse_load(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_LOAD_REG;
    if (operands[0] == NULL || operands[1] == NULL || operands[2] != NULL)
    {
        return -1;
    }

    instruction->operands.load_operands.dest_var_name = strdup(operands[0]);
    instruction->operands.load_operands.src_reg_name = strdup(operands[1]);
    return 0;
}

int free_load(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_LOAD_REG)
    {
        return -1;
    }

    free((void *)instruction->operands.load_operands.src_reg_name);
    instruction->operands.load_operands.src_reg_name = NULL;

    free((void *)instruction->operands.load_operands.dest_var_name);
    instruction->operands.load_operands.dest_var_name = NULL;

    return 0;
}

int parse_store(interpreter_instruction_t * instruction, instruction_operands_t operands)
{
    instruction->type = INSTRUCTION_TYPE_STORE_REG;
    if (operands[0] == NULL || operands[1] == NULL || operands[2] != NULL)
    {
        return -1;
    }

    instruction->operands.store_operands.dest_reg_name = strdup(operands[0]);
    instruction->operands.store_operands.src_var_name = strdup(operands[1]);
    return 0;
}

int free_store(interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_STORE_REG)
    {
        return -1;
    }

    free((void *)instruction->operands.store_operands.src_var_name);
    instruction->operands.store_operands.src_var_name = NULL;

    free((void *)instruction->operands.store_operands.dest_reg_name);
    instruction->operands.store_operands.dest_reg_name = NULL;

    return 0;
}
