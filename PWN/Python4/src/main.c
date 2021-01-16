/* This file contains the main logic of the program.
 */
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "common.h"
#include "instructions.h"
#include "interpreter.h"

#define EXECUTION_TIMEOUT_SECONDS (60)

static int parse_instruction(interpreter_instruction_t * instruction, const char * first_token,
                             instruction_operands_t operands)
{
    for (size_t i = 0; i < instruction_definitions_size; i++)
    {
        if ((instruction_definitions[i].token != NULL) &&
            (strcasecmp(first_token, instruction_definitions[i].token) == 0))
        {
            return instruction_definitions[i].parse_func(instruction, operands);
        }
    }

    // Illegal instruction?
    puts("Unknown instruction");
    return -1;
}

static int read_interpreter_script_line(interpreter_instruction_t * instruction)
{
    int ret = 0;
    char * instruction_line = NULL;
    instruction_operands_t instruction_operands = {NULL};

    char * line = NULL;
    size_t line_len = 0;
    if ((getline(&line, &line_len, stdin) == -1) || strlen(line) == 0)
    {
        ret = -1;
        goto cleanup;
    }
    line[strlen(line) - 1] = '\0';

    ret = init_interpreter_instruction(instruction);
    if (ret != 0)
    {
        goto cleanup;
    }

    instruction_line = strdup(line);
    if (instruction_line == NULL)
    {
        ret = -1;
        goto cleanup;
    }

    char * saveptr = NULL;
    char * first_token = strtok_r(instruction_line, " ", &saveptr);
    if (first_token == NULL)
    {
        ret = -1;
        goto cleanup;
    }

    for (size_t operand_index = 0; operand_index < MAX_OPERANDS_COUNT; ++operand_index)
    {
        char * token = strtok_r(NULL, " ", &saveptr);
        if (token == NULL)
        {
            break;
        }
        instruction_operands[operand_index] = token;
    }

    ret = parse_instruction(instruction, first_token, instruction_operands);
    if (ret != 0)
    {
        printf("Illegal instruction encoding: \"%s\"\n", line);
        goto cleanup;
    }

cleanup:
    if (instruction_line != NULL)
    {
        free(instruction_line);
    }
    if (line != NULL)
    {
        free(line);
    }

    return ret;
}

static int read_interpreter_script_from_user(interpreter_script_t * script)
{
    int ret = 0;

    // Read lines of interpreter
    for (size_t i = 0; i < script->instruction_count; ++i)
    {
        ret = read_interpreter_script_line(&script->instructions[i]);
        if (ret != 0)
        {
            goto cleanup;
        }
    }

cleanup:
    return ret;
}

// Reads script from the user, creates it and runs its "main" function.
// Script is returned in the 'script_out' argument, must be destructed using
// 'destruct_interpreter_script' afterwards.
int run_single_interpreter_script(interpreter_script_t ** script_out)
{
    int ret = 0;
    interpreter_script_t * script = NULL;

    // Read number of lines
    int number_of_lines = 0;
    printf("Enter number of lines: ");
    if ((fscanf(stdin, "%d%*c", &number_of_lines) != 1) || (number_of_lines <= 0) ||
        (number_of_lines > INTERPETER_MAX_INSTRUCTION_COUNT))
    {
        puts("Illegal number of lines!");
        ret = -1;
        goto cleanup;
    }

    // Initiliaze script
    script = init_interpreter_script(number_of_lines);
    if (script == NULL)
    {
        ret = -1;
        goto cleanup;
    }
    *script_out = script;

    ret = read_interpreter_script_from_user(script);
    if (ret != 0)
    {
        goto cleanup;
    }

    printf("\nRunning script...\n");
    ret = execute_interpreter_function(script, "main");
    if (ret != 0)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

int parse_user_input(void)
{
    int ret = 0;

    while (true)
    {
        interpreter_script_t * script = NULL;
        ret = run_single_interpreter_script(&script);
        if (script != NULL)
        {
            destruct_interpreter_script(script);
            script = NULL;
        }

        if (ret != 0)
        {
            goto cleanup;
        }

        char continue_char = 0;
        printf("Another script? (y/N) ");
        if ((fscanf(stdin, "%c%*c", &continue_char) != 1))
        {
            ret = -1;
            goto cleanup;
        }

        if (continue_char != 'Y' && continue_char != 'y')
        {
            break;
        }
    }

    puts("Thanks for using our interpreter!");

cleanup:
    return ret;
}

/* Handler for SIGALRM.
 * Used to kill child upon reaching execution timeout.
 */
static void execution_timeout_handler(int sig, siginfo_t * siginfo, void * context)
{
    (void)siginfo;
    (void)context;
    if (sig == SIGALRM)
    {
        puts("Execution timeout reached!");
        exit(-1);
    }
}

/* Sets execution timeout for the program.
 */
static int set_execution_timeout(void)
{
    int ret = 0;
    struct sigaction act;
    struct itimerval timer;

    act.sa_handler = NULL;
    act.sa_sigaction = execution_timeout_handler;
    act.sa_flags = SA_SIGINFO | SA_RESETHAND;
    act.sa_restorer = NULL;
    ret = sigemptyset(&act.sa_mask);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = sigaction(SIGALRM, &act, NULL);
    if (ret != 0)
    {
        goto cleanup;
    }

    // one minute timeout
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    timer.it_value.tv_sec = EXECUTION_TIMEOUT_SECONDS;
    timer.it_value.tv_usec = 0;
    ret = setitimer(ITIMER_REAL, &timer, NULL);
    if (ret != 0)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

int main(void)
{
    int ret = 0;
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Print prompt to user
    puts("PPPP  Y   Y TTTTT H   H  OOO  N   N          4  \n"
         "P   P  Y Y    T   H   H O   O NN  N         44  \n"
         "PPPP    Y     T   HHHHH O   O N N N        4 4  \n"
         "P       Y     T   H   H O   O N  NN       44444 \n"
         "P       Y     T   H   H  OOO  N   N          4  \n");
    puts("Welcome to 2021! We decided to follow tradition and start working on the next python version.");
    puts("Don't worry, we made sure no vulnerabilities are exploitable, using modern mitigation techniques.");
    puts("Have fun running your scripts!!\n");

    ret = set_execution_timeout();
    if (ret != 0)
    {
        puts("Setting execution timeout failed");
        return ret;
    }
    return parse_user_input();
}
