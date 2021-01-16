/* This file contains initilizations of the program.
 */
#include <asm/prctl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

/* Implemented in glibc */
int arch_prctl(int code, unsigned long * addr);

#define NO_SHADOW_STACK_ATTR __attribute__((no_sanitize("shadow-call-stack")))
#define CONSTRUCTOR_ATTR __attribute__((constructor))

__attribute__((aligned(16))) uint8_t SHADOW_STACK[4096] = {0};

CONSTRUCTOR_ATTR NO_SHADOW_STACK_ATTR void initiliaze_shadow_stack(void)
{
    // In clang's 'shadow-call-stack', the shadow stack is stored in 'gs'.
    arch_prctl(ARCH_SET_GS, (void *)SHADOW_STACK);
}
