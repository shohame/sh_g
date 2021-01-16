/* This file contains the main logic of the interpreter. */
#include "interpreter.h"
#include "common.h"
#include "instructions.h"
#include <ctype.h>
#include <stdlib.h>

interpreter_registers_t interpreter_regs = {0};

interpreter_script_t * init_interpreter_script(size_t instruction_count)
{
    interpreter_script_t * script = NULL;
    if (instruction_count > INTERPETER_MAX_INSTRUCTION_COUNT)
    {
        goto cleanup;
    }

    script = (interpreter_script_t *)calloc(1, sizeof(*script));
    if (script == NULL)
    {
        goto cleanup;
    }

    script->instruction_count = instruction_count;
    script->instructions = (interpreter_instruction_t *)calloc(instruction_count, sizeof(*script->instructions));
    if (script->instructions == NULL)
    {
        free(script);
        script = NULL;
        goto cleanup;
    }

    script->local_vars = NULL;

cleanup:
    return script;
}

int destruct_interpreter_script(interpreter_script_t * script)
{
    for (size_t i = 0; i < script->instruction_count; ++i)
    {
        destruct_interpreter_instruction(&script->instructions[i]);
    }
    free(script->instructions);
    free(script);

    return 0;
}

/* Return index of the label */
size_t interpreter_find_label(interpreter_script_t * script, const char * label)
{
    size_t label_index = -1;
    for (size_t i = 0; i < script->instruction_count; ++i)
    {
        if ((script->instructions[i].type == INSTRUCTION_TYPE_LABEL) &&
            (strcmp(script->instructions[i].operands.label_operands.label_name, label) == 0))
        {
            label_index = i;
            break;
        }
    }
    return label_index;
}

int execute_interpreter_function(interpreter_script_t * script, const char * label)
{
    int ret = 0;

    // Find label
    size_t label_index = interpreter_find_label(script, label);
    if (label_index == -1)
    {
        printf("Illegal call to label '%s'\n", label);
        ret = -1;
        goto cleanup;
    }

    // Switch contexts
    interpreter_local_vars_t * previous_context = script->local_vars;
    interpreter_local_vars_t current_context;
    if (initialize_local_vars(&current_context) != 0)
    {
        ret = -1;
        goto cleanup;
    }
    script->local_vars = &current_context;

    // Run starting from label
    size_t current_instruction_index = label_index;
    while (true)
    {
        if (current_instruction_index >= script->instruction_count)
        {
            puts("Illegal End-of-script");
            ret = -1;
            goto cleanup;
        }

        interpreter_instruction_t * inst = &script->instructions[current_instruction_index];
        size_t inst_exec_res = instruction_definitions[inst->type].exec_func(script, inst);
        if (inst_exec_res == INSTRUCTION_EXEC_CMD_ERROR)
        {
            printf("Error in running instruction %zd\n", current_instruction_index);
            ret = -1;
            break;
        }
        else if (inst_exec_res == INSTRUCTION_EXEC_CMD_RET)
        {
            ret = 0;
            break;
        }
        else if (inst_exec_res == INSTRUCTION_EXEC_CMD_CONT)
        {
            // Increment IP
            current_instruction_index += 1;
        }
        else /* jmp */
        {
            current_instruction_index = inst_exec_res;
        }
    }

    // Switch-back contexts
    script->local_vars = previous_context;

cleanup:
    return ret;
}

int initialize_local_vars(interpreter_local_vars_t * vars)
{
    for (size_t i = 0; i < NELEM(vars->vars); ++i)
    {
        vars->vars[i].var_type = VAR_TYPE_UNDEF;
    }
    return 0;
}

interpreter_var_t * find_var(interpreter_local_vars_t * local_vars, const char * name)
{
    interpreter_var_t * var = NULL;
    for (size_t i = 0; i < NELEM(local_vars->vars); ++i)
    {
        if ((local_vars->vars[i].var_type != VAR_TYPE_UNDEF) &&
            (strncmp(local_vars->vars[i].var_name, name, sizeof(local_vars->vars[i].var_name)) == 0))
        {
            var = &local_vars->vars[i];
            break;
        }
    }
    return var;
}

interpreter_reg_t * find_reg(const char * name)
{
    if (name[0] != '$' || name[2] != '\0' || !isdigit(name[1]))
    {
        puts("Invalid register accessed");
        return NULL;
    }

    size_t reg_index = name[1] - '0';
    if (reg_index >= NELEM(interpreter_regs.regs))
    {
        puts("Out-of-index register accessed");
        return NULL;
    }

    return &interpreter_regs.regs[reg_index];
}
