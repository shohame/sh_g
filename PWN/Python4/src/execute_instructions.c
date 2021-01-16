/*
 * This file contains the implementation of each instruction execution.
 */
#include <string.h>
#include <unistd.h>

#include "execute_instructions.h"

size_t exec_nop(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_NOP)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }
    printf("Nope!\n");
    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_label(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_LABEL)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_call(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_CALL)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    const char * label_name = instruction->operands.call_operands.label_name;
    size_t label_index = interpreter_find_label(script, label_name);
    if (label_index == -1)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    if (execute_interpreter_function(script, label_name) != 0)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_ret(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_RETURN)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    return INSTRUCTION_EXEC_CMD_RET;
}

size_t exec_jmp(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_JUMP)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    const char * label_name = instruction->operands.call_operands.label_name;
    size_t label_index = interpreter_find_label(script, label_name);
    if (label_index == -1)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    return label_index;
}

size_t exec_cbz(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_COMPARE_BRANCH_ZERO)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    interpreter_var_t * var = find_var(script->local_vars, instruction->operands.cbz_operands.var_name);
    if (var == NULL || var->var_type != VAR_TYPE_INT)
    {
        puts("Illegal var for CBZ");
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    const char * label_name = instruction->operands.cbz_operands.label_name;
    size_t label_index = interpreter_find_label(script, label_name);
    if (label_index == -1)
    {
        puts("Illegal label for CBZ");
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    if (var->var_value.var_value_int == 0)
    {
        return label_index;
    }
    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_def(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_DEFINE_VAR)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    // Validate variable name length
    if (strlen(instruction->operands.def_operands.var_name) >= SIZEOF_MEMBER(interpreter_var_t, var_name))
    {
        puts("Variable name too long.");
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    // Make sure we don't collide
    interpreter_var_t * var = NULL;
    var = find_var(script->local_vars, instruction->operands.def_operands.var_name);
    if (var != NULL)
    {
        puts("Variable already exists...");
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    // Find free slot in the local variables
    var = NULL;
    for (size_t i = 0; i < NELEM(script->local_vars->vars); ++i)
    {
        if (script->local_vars->vars[i].var_type == VAR_TYPE_UNDEF)
        {
            var = &script->local_vars->vars[i];
            break;
        }
    }
    if (var == NULL)
    {
        puts("Too many local variables...");
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    // Parse value of the variables:
    // - strings starts and end with '"' character
    // - integers start with '0x' prefix
    // otherwise - illegal value
    const char * var_value = instruction->operands.def_operands.var_value;
    size_t var_value_len = strlen(var_value);
    if (var_value_len < 2)
    {
        puts("Invalid variable value");
        return INSTRUCTION_EXEC_CMD_ERROR;
    }
    if (strncmp("0x", var_value, 2) == 0)
    {
        // Integer value!
        int64_t var_integer_value = 0;
        if (sscanf(var_value, "0x%lx", &var_integer_value) != 1)
        {
            return INSTRUCTION_EXEC_CMD_ERROR;
        }
        var->var_type = VAR_TYPE_INT;
        var->var_value.var_value_int = var_integer_value;
    }
    else if (var_value[0] == '"' && var_value[var_value_len - 1] == '"')
    {
        // String value! (get rid of the "" around)
        var->var_type = VAR_TYPE_STR;
        size_t var_value_max_len = sizeof(var->var_value.var_value_string) - 1;
        size_t var_value_str_size = MIN(var_value_len - 2, var_value_max_len);
        strncpy(var->var_value.var_value_string, &var_value[1], var_value_str_size);
        var->var_value.var_value_string[var_value_str_size] = '\0';
    }
    else
    {
        // Unknown variable type
        puts("Invalid variable definition - unknown type");
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    // Copy variable name
    strncpy(var->var_name, instruction->operands.def_operands.var_name, sizeof(var->var_name));

    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_mov(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_MOV_VAR)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    interpreter_var_t * dest_var = find_var(script->local_vars, instruction->operands.mov_operands.dest_name);
    interpreter_var_t * src_var = find_var(script->local_vars, instruction->operands.mov_operands.src_name);
    if (dest_var == NULL || src_var == NULL)
    {
        puts("Can't find variables...");
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    dest_var->var_type = src_var->var_type;
    memcpy(&dest_var->var_value, &src_var->var_value, sizeof(dest_var->var_value));

    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_print(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_PRINT_VAR)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    // Find free slot in the local variables
    interpreter_var_t * var = find_var(script->local_vars, instruction->operands.print_operands.var_name);
    if (var == NULL)
    {
        puts("Can't find variable");
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    // Print the value
    if (var->var_type == VAR_TYPE_STR)
    {
        printf("variable: '%s', value: \"%s\"\n", var->var_name, var->var_value.var_value_string);
    }
    else if (var->var_type == VAR_TYPE_INT)
    {
        printf("variable: '%s', value: 0x%lx\n", var->var_name, var->var_value.var_value_int);
    }
    else
    {
        printf("Unknown variable type %d\n", var->var_type);
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_add(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_ADD)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    interpreter_var_t * dest_var = find_var(script->local_vars, instruction->operands.add_operands.dest_var);
    interpreter_var_t * op1_var = find_var(script->local_vars, instruction->operands.add_operands.op1_var);
    interpreter_var_t * op2_var = find_var(script->local_vars, instruction->operands.add_operands.op2_var);
    if (dest_var == NULL || op1_var == NULL || op2_var == NULL)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    if (op1_var->var_type != op2_var->var_type)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    if (op1_var->var_type == VAR_TYPE_INT)
    {
        // Integer addition
        dest_var->var_type = VAR_TYPE_INT;
        dest_var->var_value.var_value_int = op1_var->var_value.var_value_int + op2_var->var_value.var_value_int;
    }
    else if (op1_var->var_type == VAR_TYPE_STR)
    {
        const char * op1_str = op1_var->var_value.var_value_string;
        const char * op2_str = op2_var->var_value.var_value_string;
        char * dest_str = dest_var->var_value.var_value_string;
        dest_var->var_type = VAR_TYPE_STR;
        if ((strlen(op1_str) + strlen(op2_str) + 1) > sizeof(dest_var->var_value.var_value_string))
        {
            puts("String addition failed - size too long");
            return INSTRUCTION_EXEC_CMD_ERROR;
        }
        strncpy(dest_str, op1_str, sizeof(dest_var->var_value.var_value_string));
        strncat(dest_str, op2_str, strlen(op2_str));
    }
    else
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_sub(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_SUB)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    interpreter_var_t * dest_var = find_var(script->local_vars, instruction->operands.sub_operands.dest_var);
    interpreter_var_t * op1_var = find_var(script->local_vars, instruction->operands.sub_operands.op1_var);
    interpreter_var_t * op2_var = find_var(script->local_vars, instruction->operands.sub_operands.op2_var);
    if (dest_var == NULL || op1_var == NULL || op2_var == NULL)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    if (op1_var->var_type != op2_var->var_type)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    if (op1_var->var_type == VAR_TYPE_INT)
    {
        // Integer substraction
        dest_var->var_type = VAR_TYPE_INT;
        dest_var->var_value.var_value_int = op1_var->var_value.var_value_int - op2_var->var_value.var_value_int;
    }
    else if (op1_var->var_type == VAR_TYPE_STR)
    {
        const char * op1_str = op1_var->var_value.var_value_string;
        const char * op2_str = op2_var->var_value.var_value_string;
        char * dest_str = dest_var->var_value.var_value_string;
        dest_var->var_type = VAR_TYPE_STR;
        size_t len_to_copy = strlen(op1_str);
        if ((strlen(op2_str) <= strlen(op1_str)) && (strcmp(op1_str + strlen(op1_str) - strlen(op2_str), op2_str) == 0))
        {
            len_to_copy -= strlen(op2_str);
        }
        strncpy(dest_str, op1_str, len_to_copy);
        dest_str[len_to_copy] = '\0';
    }
    else
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_load(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_LOAD_REG)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    interpreter_reg_t * src_reg = find_reg(instruction->operands.load_operands.src_reg_name);
    interpreter_var_t * dest_var = find_var(script->local_vars, instruction->operands.load_operands.dest_var_name);
    if (src_reg == NULL || dest_var == NULL)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    if (dest_var->var_type != VAR_TYPE_INT)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    dest_var->var_value.var_value_int = *src_reg;

    return INSTRUCTION_EXEC_CMD_CONT;
}

size_t exec_store(interpreter_script_t * script, interpreter_instruction_t * instruction)
{
    if (instruction->type != INSTRUCTION_TYPE_STORE_REG)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    interpreter_reg_t * dest_reg = find_reg(instruction->operands.store_operands.dest_reg_name);
    interpreter_var_t * src_var = find_var(script->local_vars, instruction->operands.store_operands.src_var_name);
    if (dest_reg == NULL || src_var == NULL)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    if (src_var->var_type != VAR_TYPE_INT)
    {
        return INSTRUCTION_EXEC_CMD_ERROR;
    }

    *dest_reg = src_var->var_value.var_value_int;

    return INSTRUCTION_EXEC_CMD_CONT;
}
