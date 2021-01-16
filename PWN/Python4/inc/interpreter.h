#pragma once
#ifndef __INTERPETER_H
#define __INTERPETER_H

#define INTERPETER_MAX_INSTRUCTION_COUNT (256)
#define VAR_NAME_MAX_LEN (16)
#define VAR_STR_VALUE_MAX_LEN (64)
#define LOCAL_VARS_AMOUNT (32)
#define REGS_AMOUNT (10)

#include "common.h"
#include "instructions.h"

/* Forward decleration */
typedef struct interpreter_instruction_s interpreter_instruction_t;

typedef enum interpreter_var_type_e
{
    VAR_TYPE_STR,
    VAR_TYPE_INT,
    VAR_TYPE_UNDEF
} interpreter_var_type_t;

/* Vars definition */
typedef struct interpreter_var_s
{
    char var_name[VAR_NAME_MAX_LEN];
    interpreter_var_type_t var_type;
    union var_value_u
    {
        char var_value_string[VAR_STR_VALUE_MAX_LEN];
        int64_t var_value_int;
    } var_value;
} interpreter_var_t;

typedef struct interpreter_local_vars_s
{
    interpreter_var_t vars[LOCAL_VARS_AMOUNT];
} interpreter_local_vars_t;

/* Register definitions */
typedef int64_t interpreter_reg_t;
// Registers accessed with $0-$9
typedef struct interpreter_registers_s
{
    interpreter_reg_t regs[REGS_AMOUNT];
} interpreter_registers_t;

typedef struct interpreter_script_s
{
    size_t instruction_count;
    interpreter_instruction_t * instructions;

    interpreter_local_vars_t * local_vars;
} interpreter_script_t;

interpreter_script_t * init_interpreter_script(size_t instruction_count);
int destruct_interpreter_script(interpreter_script_t * script);
size_t interpreter_find_label(interpreter_script_t * script, const char * label);
int execute_interpreter_function(interpreter_script_t * script, const char * label);
int initialize_local_vars(interpreter_local_vars_t * vars);
interpreter_var_t * find_var(interpreter_local_vars_t * local_vars, const char * name);
interpreter_reg_t * find_reg(const char * name);

#endif /* __INTERPETER_H */
