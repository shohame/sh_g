
#include "instructions.h"

int parse_nop(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_label(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_call(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_ret(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_jmp(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_cbz(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_def(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_mov(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_print(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_add(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_sub(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_load(interpreter_instruction_t * instruction, instruction_operands_t operands);
int parse_store(interpreter_instruction_t * instruction, instruction_operands_t operands);

int free_nop(interpreter_instruction_t * instruction);
int free_label(interpreter_instruction_t * instruction);
int free_call(interpreter_instruction_t * instruction);
int free_ret(interpreter_instruction_t * instruction);
int free_jmp(interpreter_instruction_t * instruction);
int free_cbz(interpreter_instruction_t * instruction);
int free_def(interpreter_instruction_t * instruction);
int free_mov(interpreter_instruction_t * instruction);
int free_print(interpreter_instruction_t * instruction);
int free_add(interpreter_instruction_t * instruction);
int free_sub(interpreter_instruction_t * instruction);
int free_load(interpreter_instruction_t * instruction);
int free_store(interpreter_instruction_t * instruction);
