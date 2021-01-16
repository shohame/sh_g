
#include "instructions.h"

size_t exec_nop(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_label(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_call(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_ret(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_jmp(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_cbz(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_def(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_mov(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_print(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_add(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_sub(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_load(interpreter_script_t * script, interpreter_instruction_t * instruction);
size_t exec_store(interpreter_script_t * script, interpreter_instruction_t * instruction);
