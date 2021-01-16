/*
 * Implementation of our sandbox.
 * Notice it requires the host to have kernel version >= 5.3,
 * in order to support the "PTRACE_GET_SYSCALL_INFO" feature.
 */
#define _GNU_SOURCE
#include "LIEF/LIEF.h"
#include <elf.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/resource.h>

#define MAX_ELF_SIZE (0x10000)
#define MAX_PATH_SIZE (256)
#define MARKER "deadbeef"
#define MARKER_SIZE (sizeof(MARKER) - 1)
#define ELF_FILENAME_TEMPLATE "/tmp/sandbox-elf-XXXXXX"
#define REGION_FILENAME_TEMPLATE "/tmp/sandbox-region-XXXXXX"
#define MEMORY_LIMIT_BYTES (8 * 1024 * 1024)
#define SYSCALL_OPCODE_SIZE (2)
#define PROTECTED_REGION_ADDRESS (0x600000000000ull)
#define PROTECTED_REGION_SIZE (PAGE_SIZE)
#define KEYSTORE_SIZE (256)

typedef struct tracer_data_s
{
    pid_t child_pid;
    int protected_region_fd;
} tracer_data_t;

pid_t child_pid_kill_upon_timeout = -1;
bool child_execution_timeout_exceeded = false;
uint64_t keystore[KEYSTORE_SIZE] = { 0 };

typedef struct injected_syscall_s
{
    uint64_t syscall_nr;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
} injected_syscall_t;

// tracer-call values
#define __NR_tracer_call (0x1337)
typedef enum tracer_call_command_e
{
    TRACER_CALL_COMMAND_NOP = 0,
    TRACER_CALL_COMMAND_WRITE_FLAG_TO_PROTECTED_REGION = 1,
    TRACER_CALL_COMMAND_CLEAR_PROTECTED_REGION = 2,
    TRACER_CALL_COMMAND_CHECKSUM_TRACEE_MEMORY = 3,
    TRACER_CALL_COMMAND_STORE_KEY_VALUE = 4,
    TRACER_CALL_COMMAND_GET_KEY_VALUE = 5,
} tracer_call_command_t;

#define PRINT_ERROR(format, ...) fprintf(stderr, "[-] " format "\n", ##__VA_ARGS__)
#define PRINT_INFO(format, ...) fprintf(stdout, "[*] " format "\n", ##__VA_ARGS__)

static int read_payload_elf(int fd, void * buf, size_t count)
{
    ssize_t n = 0;
    size_t i = 0;
    char * p = NULL;

    p = buf;
    i = count;
    while (i > 0)
    {
        n = read(fd, p, i);
        if (n == 0)
        {
            PRINT_ERROR("read failed");
            return -1;
        }
        else if (n == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            PRINT_ERROR("read failed");
            return -1;
        }
        i -= n;
        p += n;

        if (count - i >= MARKER_SIZE)
        {
            if (memcmp(p - MARKER_SIZE, MARKER, MARKER_SIZE) == 0)
            {
                PRINT_INFO("Received 0x%lx bytes", count - i);
                break;
            }
        }
    }

    return count - i;
}

static int write_all(int fd, void * buf, size_t count)
{
    ssize_t n = 0;
    size_t i = 0;
    char * p = NULL;

    p = buf;
    i = count;
    while (i > 0)
    {
        n = write(fd, p, i);
        if (n == 0)
        {
            PRINT_ERROR("write failed");
            return -1;
        }
        else if (n == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            PRINT_ERROR("write failed");
            return -1;
        }
        i -= n;
        p += n;
    }

    return 0;
}

// Validates host is compatible with sandbox
static bool is_host_compatible(void)
{
    struct utsname uts;
    if (uname(&uts) != 0)
    {
        return false;
    }

    // Validate the host is at least Linux 5.3
    // (because we rely on PTRACE_GET_SYSCALL_INFO).
    int kernel_major_ver = 0;
    int kernel_minor_ver = 0;
    if (sscanf(uts.release, "%d.%d.", &kernel_major_ver, &kernel_minor_ver) != 2)
    {
        return false;
    }

    return ((kernel_major_ver > 5) || ((kernel_major_ver == 5) && (kernel_minor_ver >= 3)));
}

static int recv_payload_elf(int infd, char * template)
{
    int ret = -1;
    char buf[MAX_ELF_SIZE] = { 0 };
    ssize_t count = 0;
    int outfd = -1;

    count = read_payload_elf(infd, buf, sizeof(buf));
    if (count == -1)
    {
        goto cleanup;
    }

    outfd = mkstemp(template);
    if (outfd == -1)
    {
        PRINT_ERROR("mkstemp failed");
        goto cleanup;
    }

    if (write_all(outfd, buf, count) != 0)
    {
        goto cleanup;
    }

    if (fchmod(outfd, 0500) != 0)
    {
        PRINT_ERROR("fchmod failed");
        goto cleanup;
    }

    // Success
    ret = 0;

cleanup:
    if (outfd != -1)
    {
        close(outfd);
    }

    return ret;
}

static int install_resource_limits(void)
{
    int ret = 0;
    struct rlimit memory_limit = { .rlim_cur = MEMORY_LIMIT_BYTES, .rlim_max = MEMORY_LIMIT_BYTES };

    ret = setrlimit(RLIMIT_AS, &memory_limit);
    return ret;
}

static int install_seccomp_filter(void)
{
    scmp_filter_ctx ctx;
    unsigned int i = 0;
    int ret = 0;
    int allowed_syscalls[] = {
        // Signals
        SCMP_SYS(rt_sigreturn), SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask), SCMP_SYS(sigreturn),

        // Exit
        SCMP_SYS(exit_group), SCMP_SYS(exit),

        // Filesystem
        SCMP_SYS(access), SCMP_SYS(fstat), SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(close), SCMP_SYS(stat),
        SCMP_SYS(lstat), SCMP_SYS(poll), SCMP_SYS(readlink), SCMP_SYS(pipe), SCMP_SYS(pread64), SCMP_SYS(pwrite64),
        SCMP_SYS(readv), SCMP_SYS(writev), SCMP_SYS(dup), SCMP_SYS(dup2), SCMP_SYS(dup3),

        // Memory
        SCMP_SYS(brk), SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(mincore), SCMP_SYS(madvise), SCMP_SYS(msync),

        // System information
        SCMP_SYS(uname), SCMP_SYS(getpid), SCMP_SYS(getppid), SCMP_SYS(arch_prctl), SCMP_SYS(futex),
        SCMP_SYS(nanosleep), SCMP_SYS(gettimeofday), SCMP_SYS(getuid), SCMP_SYS(getgid),

        // Additional must-have for the sandbox to work
        SCMP_SYS(execve),

        // Tracer-call
        __NR_tracer_call
    };

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL)
    {
        PRINT_ERROR("'seccomp_init' failed");
        goto cleanup;
    }

    // Allowed system-calls
    for (i = 0; i < sizeof(allowed_syscalls) / sizeof(allowed_syscalls[0]); i++)
    {
        ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed_syscalls[i], 0);
        if (ret != 0)
        {
            PRINT_ERROR("'seccomp_rule_add' failed");
            goto cleanup;
        }
    }

    // Prevent 'mprotect' with something other than PROT_NONE
    ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1, SCMP_A2(SCMP_CMP_EQ, PROT_NONE));
    if (ret != 0)
    {
        PRINT_ERROR("'seccomp_rule_add' failed");
        goto cleanup;
    }

    ret = seccomp_load(ctx);
    if (ret != 0)
    {
        PRINT_ERROR("'seccomp_load' failed");
        goto cleanup;
    }

    PRINT_INFO("seccomp-bpf filters installed");

cleanup:
    seccomp_release(ctx);
    return ret;
}

static int setup_sandbox(void)
{
    int ret = 0;

    ret = install_resource_limits();
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = install_seccomp_filter();
    if (ret != 0)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

static int child_become_tracee(void)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
    {
        return -1;
    }

    if (kill(getpid(), SIGSTOP) != 0)
    {
        return -1;
    }

    return 0;
}

/*
 * This is the child process. It will:
 * 1. Set up the sandbox.
 * 2. Get 'ptrace'-d by parent.
 * 3. 'execve' the given ELF.
 * This function does not return.
 */
static void child_execute(char * filename)
{
    int ret = -1;

    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0) != 0)
    {
        PRINT_ERROR("prctl(PR_SET_PDEATHSIG) failed");
        goto cleanup;
    }

    if (child_become_tracee() != 0)
    {
        PRINT_ERROR("child_become_tracee() failed");
        goto cleanup;
    }

    if (setup_sandbox() != 0)
    {
        PRINT_ERROR("setup_sandbox() failed");
        goto cleanup;
    }

    PRINT_INFO("Let's execute \"%s\" in our sandbox!", filename);
    char * argv[] = { filename, NULL };
    errno = 0;
    if (execve(filename, argv, NULL) != 0)
    {
        PRINT_ERROR("execve of \"%s\" failed, errno =%d", filename, errno);
        goto cleanup;
    }

    // never reached (hopefully!)
    ret = 0;

cleanup:
    exit(ret);
}

static void kill_child(pid_t child_pid)
{
    // Best-effort
    kill(child_pid, SIGKILL);
}

/* Handler for SIGALRM.
 * Used to kill child upon reaching execution timeout.
 */
static void child_execution_timeout_handler(int sig, siginfo_t * siginfo, void * context)
{
    (void)siginfo;
    (void)context;
    if ((sig == SIGALRM) && (child_pid_kill_upon_timeout != -1))
    {
        kill_child(child_pid_kill_upon_timeout);
        child_execution_timeout_exceeded = true;
    }
}

/* Sets timeout for the execution time of the child.
 * Returns 0 on success, and non-zero value on error.
 */
static int set_child_execution_timeout(tracer_data_t * tracer_data)
{
    int ret = 0;
    struct sigaction act;
    struct itimerval timer;

    child_pid_kill_upon_timeout = tracer_data->child_pid;

    act.sa_handler = NULL;
    act.sa_sigaction = child_execution_timeout_handler;
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

    // 2-seconds timeout
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    timer.it_value.tv_sec = 100; // 2;
    timer.it_value.tv_usec = 0;
    ret = setitimer(ITIMER_REAL, &timer, NULL);
    if (ret != 0)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

/* Traces the child process.
 * Because the child calls PTRACE_TRACEME and raises SIGSTOP, we just need to wait
 * for this signal.
 * This function returns 0 upon success - and leaves the child in a stopped state.
 */
static int trace_child(tracer_data_t * tracer_data)
{
    int status = 0;
    if (waitpid(tracer_data->child_pid, &status, 0) == -1)
    {
        PRINT_ERROR("waitpid failed");
        return -1;
    }
    else if (WIFSTOPPED(status) && (WSTOPSIG(status) == SIGSTOP))
    {
        return 0;
    }

    // WTF happened?
    return -1;
}

/* Continues the child until the 'execve' event.
 * Upon success - return 0 and leave the child in stopped state.
 * This function leaves the ptrace options in an undefined state.
 */
static int cont_child_until_execve(tracer_data_t * tracer_data)
{
    int ret = 0;
    int status = 0;

    // Run until 'execve'
    ret = ptrace(PTRACE_SETOPTIONS, tracer_data->child_pid, NULL, PTRACE_O_TRACEEXEC);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = ptrace(PTRACE_CONT, tracer_data->child_pid, NULL, 0);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = waitpid(tracer_data->child_pid, &status, 0);
    if (ret == -1)
    {
        goto cleanup;
    }

    if ((status >> 8) != (SIGTRAP | (PTRACE_EVENT_EXEC << 8)))
    {
        ret = -1;
        goto cleanup;
    }

    ret = 0;

cleanup:
    // Best effort
    ptrace(PTRACE_SETOPTIONS, tracer_data->child_pid, NULL, 0);

    return ret;
}

static int read_tracee_dword(tracer_data_t * tracer_data, void * tracee_addr, uint32_t * dword_out)
{
    uint64_t qword = 0;

    errno = 0;
    qword = ptrace(PTRACE_PEEKDATA, tracer_data->child_pid, tracee_addr, NULL);
    if (errno != 0)
    {
        return -1;
    }

    // Success
    *dword_out = (qword & 0xffffffff);
    return 0;
}

static bool validate_syscall_gadget(tracer_data_t * tracer_data, uintptr_t syscall_gadget)
{
    uint32_t syscall_gadget_data = 0;
    if (read_tracee_dword(tracer_data, (void *)syscall_gadget, &syscall_gadget_data) != 0)
    {
        return false;
    }
    return ((syscall_gadget_data & 0xFFFF) == 0x050F);
}

// Gets the first syscall gadget from the traced child. Assumptions:
// 1. This function calls after we got the PTRACE_EVENT_EXEC.
// 2. This function is called with PTRACE_O_TRACESYSGOOD option set.
// Out parameters:
// - syscall_gadget_out - address of the syscall gadget in the child
// - original_regs_out - the original registers that the first syscall was called with
static int get_child_first_syscall_gadget(tracer_data_t * tracer_data, uintptr_t * syscall_gadget_out,
                                          struct user_regs_struct * original_regs_out)
{
    int ret = 0;
    int status = 0;
    bool got_syscall_gadget = false;
    uintptr_t syscall_gadget = 0;
    struct ptrace_syscall_info syscall_info = { 0 };
    struct user_regs_struct original_regs = { 0 };
    struct user_regs_struct custom_regs = { 0 };
    struct iovec iov;

    // Get to the first syscall the user calls.
    // We abuse the first syscall to gain the address of the remote syscall gadget.
    while (true)
    {
        ret = ptrace(PTRACE_SYSCALL, tracer_data->child_pid, NULL, 0);
        if (ret != 0)
        {
            goto cleanup;
        }

        ret = waitpid(tracer_data->child_pid, &status, 0);
        if (ret == -1)
        {
            goto cleanup;
        }

        ret = ptrace(PTRACE_GET_SYSCALL_INFO, tracer_data->child_pid, sizeof(syscall_info), &syscall_info);
        if (ret == -1)
        {
            goto cleanup;
        }

        if ((syscall_info.op != PTRACE_SYSCALL_INFO_ENTRY) && (syscall_info.op != PTRACE_SYSCALL_INFO_EXIT))
        {
            ret = -1;
            goto cleanup;
        }
        else if (syscall_info.op == PTRACE_SYSCALL_INFO_ENTRY)
        {
            iov.iov_len = sizeof(original_regs);
            iov.iov_base = &original_regs;
            ret = ptrace(PTRACE_GETREGSET, tracer_data->child_pid, NT_PRSTATUS, &iov);
            if (ret == -1)
            {
                goto cleanup;
            }

            // The 'syscall' instruction is 2-bytes, and we get here the next instruction after 'syscall'.
            // So we need to substract 2 bytes. We will validate that we got a valid syscall gadget.
            syscall_gadget = syscall_info.instruction_pointer - SYSCALL_OPCODE_SIZE;
            got_syscall_gadget = true;
            PRINT_INFO("syscall_gadget: 0x%016lx", syscall_gadget);
            if (!validate_syscall_gadget(tracer_data, syscall_gadget))
            {
                ret = -1;
                goto cleanup;
            }

            // We get here in syscall-enter state; make sure we transition out
            // of it to syscall-exit state. In order to prevent the syscall taking any effect,
            // we replace the syscall number with 'getpid' syscall (which is harmless).
            memcpy(&custom_regs, &original_regs, sizeof(custom_regs));
            custom_regs.orig_rax = __NR_getpid;
            custom_regs.rax = __NR_getpid;

            iov.iov_len = sizeof(custom_regs);
            iov.iov_base = &custom_regs;
            ret = ptrace(PTRACE_SETREGSET, tracer_data->child_pid, NT_PRSTATUS, &iov);
            if (ret == -1)
            {
                goto cleanup;
            }
        }
        else if ((syscall_info.op == PTRACE_SYSCALL_INFO_EXIT) && got_syscall_gadget)
        {
            break;
        }
    }

    // Success - copy out params
    *syscall_gadget_out = syscall_gadget;
    memcpy(original_regs_out, &original_regs, sizeof(*original_regs_out));
    ret = 0;

cleanup:
    return ret;
}

// Inject syscalls in the child in order to create the protected region.
// Assumptions:
// 1. This function is called with PTRACE_O_TRACESYSGOOD option set.
// 2. The child has not yet called its first syscall.
// 2. original_regs argument contains the registers that the child tried to use when calling its first syscall.
static int inject_protected_region_syscalls(tracer_data_t * tracer_data, uintptr_t syscall_gadget,
                                            const struct user_regs_struct * original_regs)
{
    int ret = 0;
    int status = 0;
    struct iovec iov;
    struct ptrace_syscall_info syscall_info = { 0 };

    // We inject those system-calls in order to create the protected region in the tracee
    PRINT_INFO("Injecting syscalls...");
    injected_syscall_t injected_syscalls[] = {
        // Map protected region
        {
            .syscall_nr = __NR_mmap,
            .arg0 = PROTECTED_REGION_ADDRESS,
            .arg1 = PROTECTED_REGION_SIZE,
            .arg2 = PROT_READ,
            .arg3 = MAP_SHARED | MAP_POPULATE | MAP_FIXED,
            .arg4 = tracer_data->protected_region_fd,
            .arg5 = 0,
        },
        // Prevent reading/writing to it
        {
            .syscall_nr = __NR_mprotect,
            .arg0 = PROTECTED_REGION_ADDRESS,
            .arg1 = PROTECTED_REGION_SIZE,
            .arg2 = PROT_NONE,
        },
        // Close the mapped file-descriptor
        {
            .syscall_nr = __NR_close,
            .arg0 = tracer_data->protected_region_fd,
        },
    };

    for (size_t i = 0; i < sizeof(injected_syscalls) / sizeof(injected_syscalls[0]); i++)
    {
        struct user_regs_struct syscall_regs = { 0 };
        memcpy(&syscall_regs, original_regs, sizeof(syscall_regs));
        syscall_regs.rax = injected_syscalls[i].syscall_nr;
        syscall_regs.rdi = injected_syscalls[i].arg0;
        syscall_regs.rsi = injected_syscalls[i].arg1;
        syscall_regs.rdx = injected_syscalls[i].arg2;
        syscall_regs.r10 = injected_syscalls[i].arg3;
        syscall_regs.r8 = injected_syscalls[i].arg4;
        syscall_regs.r9 = injected_syscalls[i].arg5;
        syscall_regs.rip = syscall_gadget;

        iov.iov_len = sizeof(syscall_regs);
        iov.iov_base = &syscall_regs;
        ret = ptrace(PTRACE_SETREGSET, tracer_data->child_pid, NT_PRSTATUS, &iov);
        if (ret == -1)
        {
            goto cleanup;
        }

        // Call syscall (we need to do this twice - first entry, then exit)
        for (size_t state = 0; state < 2; state++)
        {
            ret = ptrace(PTRACE_SYSCALL, tracer_data->child_pid, NULL, 0);
            if (ret != 0)
            {
                goto cleanup;
            }

            ret = waitpid(tracer_data->child_pid, &status, 0);
            if (ret == -1)
            {
                goto cleanup;
            }

            ret = ptrace(PTRACE_GET_SYSCALL_INFO, tracer_data->child_pid, sizeof(syscall_info), &syscall_info);
            if (ret == -1)
            {
                goto cleanup;
            }

            if ((state == 0 && (syscall_info.op != PTRACE_SYSCALL_INFO_ENTRY ||
                                syscall_info.entry.nr != injected_syscalls[i].syscall_nr)) ||
                (state == 1 && (syscall_info.op != PTRACE_SYSCALL_INFO_EXIT || syscall_info.exit.is_error)))
            {
                PRINT_ERROR("Injection failed.");
                ret = -1;
                goto cleanup;
            }
        }
    }

    // Success
    ret = 0;

cleanup:
    return ret;
}

// Restores the context of the child so it can continue to execute its first syscall.
static int restore_child_original_syscall_context(tracer_data_t * tracer_data, uintptr_t syscall_gadget,
                                                  const struct user_regs_struct * original_regs)
{
    int ret = 0;
    struct user_regs_struct regs_to_restore = { 0 };
    struct iovec iov;

    // Notice that because the context is at the end of the syscall opcode,
    // and 'rax' was replaced, we need to fix those up to restore functionality.
    memcpy(&regs_to_restore, original_regs, sizeof(regs_to_restore));
    regs_to_restore.rip = syscall_gadget;
    regs_to_restore.rax = regs_to_restore.orig_rax;
    iov.iov_len = sizeof(regs_to_restore);
    iov.iov_base = &regs_to_restore;

    ret = ptrace(PTRACE_SETREGSET, tracer_data->child_pid, NT_PRSTATUS, &iov);
    if (ret == -1)
    {
        goto cleanup;
    }

    // Success
    ret = 0;

cleanup:
    return ret;
}

// We inject syscalls into the tracee in order to allocate the protected region.
// We do that by waiting for the tracee first syscall, thus gaining a gadget of the syscall
// opcode; then injection mmap+mprotect+close on the protected region fd.
// This function leaves the ptrace options in an undefined state.
static int inject_initial_syscalls(tracer_data_t * tracer_data)
{
    int ret = 0;
    uintptr_t syscall_gadget = 0;
    struct user_regs_struct original_regs = { 0 };

    ret = ptrace(PTRACE_SETOPTIONS, tracer_data->child_pid, NULL, PTRACE_O_TRACESYSGOOD);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = get_child_first_syscall_gadget(tracer_data, &syscall_gadget, &original_regs);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = inject_protected_region_syscalls(tracer_data, syscall_gadget, &original_regs);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = restore_child_original_syscall_context(tracer_data, syscall_gadget, &original_regs);
    if (ret != 0)
    {
        goto cleanup;
    }

    // Restore options
    ret = ptrace(PTRACE_SETOPTIONS, tracer_data->child_pid, NULL, 0);
    if (ret != 0)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

static bool is_in_protected_region(void * addr, size_t size)
{
    uintptr_t range_start = (uintptr_t)addr;
    uintptr_t range_end = range_start + size;
    uintptr_t protected_region_start = PROTECTED_REGION_ADDRESS;
    uintptr_t protected_region_end = protected_region_start + PROTECTED_REGION_SIZE;

    return ((range_start <= protected_region_end) && (protected_region_start <= range_end));
}

static int tracer_call_nop(tracer_data_t * tracer_data, uint64_t * call_result)
{
    (void)tracer_data;
    *call_result = 0;
    return 0;
}

static int tracer_call_write_flag_to_protected_region(tracer_data_t * tracer_data, uint64_t * call_result)
{
    int ret = -1;
    void * protected_region = NULL;
    int flag_fd = -1;
    struct stat flag_file_stat = { 0 };
    ssize_t flag_length = 0;

    protected_region =
        mmap(NULL, PROTECTED_REGION_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, tracer_data->protected_region_fd, 0);
    if (protected_region == MAP_FAILED)
    {
        goto cleanup;
    }

    flag_fd = open("./flag", O_RDONLY | O_CLOEXEC);
    if (flag_fd == -1)
    {
        goto cleanup;
    }

    if (fstat(flag_fd, &flag_file_stat) == -1)
    {
        goto cleanup;
    }
    flag_length = flag_file_stat.st_size;

    // Read flag to protected region
    size_t flag_bytes_read = 0;
    while (flag_bytes_read < flag_length)
    {
        errno = 0;
        ssize_t read_res = read(flag_fd, (char *)protected_region + flag_bytes_read, flag_length - flag_bytes_read);
        if (read_res == -1 && errno == EINTR)
        {
            continue;
        }
        else if (read_res == -1 || read_res == 0)
        {
            break;
        }
        else
        {
            flag_bytes_read += read_res;
        }
    }
    if (flag_length != flag_bytes_read)
    {
        goto cleanup;
    }

    // Success
    *call_result = 0;
    ret = 0;

cleanup:
    if (flag_fd != -1)
    {
        close(flag_fd);
    }

    if (protected_region != NULL && protected_region != MAP_FAILED)
    {
        munmap(protected_region, PROTECTED_REGION_SIZE);
    }

    return ret;
}

static int tracer_call_clear_protected_region(tracer_data_t * tracer_data, uint64_t * call_result)
{
    int ret = 0;
    void * protected_region = NULL;
    protected_region =
        mmap(NULL, PROTECTED_REGION_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, tracer_data->protected_region_fd, 0);
    if (protected_region == MAP_FAILED)
    {
        ret = -1;
        goto cleanup;
    }

    memset(protected_region, 0, PROTECTED_REGION_SIZE);

    // Success
    ret = 0;
    *call_result = 0;

cleanup:
    if (protected_region != NULL && protected_region != MAP_FAILED)
    {
        munmap(protected_region, PROTECTED_REGION_SIZE);
    }

    return ret;
}

// Checksum tracer-call is the following signature:
// checksum(void * address, size_t * size, uint8_t * checksum)
//  address - memory to checksum
//  size - contains size to checksum
//  checksum - 1 bytes memory that checksum will be written to
// Return 0 on success, or '-error' on error (standard errno numbers).
static int tracer_call_checksum_tracee_memory(tracer_data_t * tracer_data, uint64_t * call_result,
                                              void * tracee_memory_to_checksum, uint32_t * tracee_size_to_checksum,
                                              uint8_t * tracee_checksum_result)
{
    int ret = 0;
    uint32_t length_to_checksum = 0;
    uint8_t * memory_to_checksum = NULL;
    struct iovec local_iov;
    struct iovec remote_iov;
    ssize_t res = 0;
    uint8_t checksum_result = 0;

    if (read_tracee_dword(tracer_data, tracee_size_to_checksum, &length_to_checksum) == -1)
    {
        *call_result = -EFAULT;
        goto cleanup;
    }

    // Validate we don't checksum protected region
    if (is_in_protected_region(tracee_memory_to_checksum, length_to_checksum))
    {
        *call_result = -EPERM;
        goto cleanup;
    }

    // Calculate the checksum
    memory_to_checksum = (uint8_t *)malloc(length_to_checksum);
    if (memory_to_checksum == NULL)
    {
        *call_result = -ENOMEM;
        goto cleanup;
    }

    local_iov.iov_base = memory_to_checksum;
    local_iov.iov_len = length_to_checksum;
    remote_iov.iov_base = tracee_memory_to_checksum;
    remote_iov.iov_len = length_to_checksum;
    errno = 0;
    res = process_vm_readv(tracer_data->child_pid, &local_iov, 1, &remote_iov, 1, 0);
    if (res != length_to_checksum)
    {
        if (res != -1)
        {
            // Partial read
            *call_result = -E2BIG;
        }
        else if (errno != ESRCH)
        {
            *call_result = -errno;
        }
        else
        {
            // Fatal error
            ret = -1;
        }
        goto cleanup;
    }

    for (size_t i = 0; i < length_to_checksum; ++i)
    {
        checksum_result ^= memory_to_checksum[i];
    }

    // Return result
    if (is_in_protected_region(tracee_checksum_result, sizeof(checksum_result)))
    {
        *call_result = -EPERM;
        goto cleanup;
    }
    local_iov.iov_base = &checksum_result;
    local_iov.iov_len = sizeof(checksum_result);
    remote_iov.iov_base = tracee_checksum_result;
    remote_iov.iov_len = sizeof(checksum_result);
    errno = 0;
    res = process_vm_writev(tracer_data->child_pid, &local_iov, 1, &remote_iov, 1, 0);
    if (res == -1)
    {
        if (errno != ESRCH)
        {
            *call_result = -errno;
        }
        else
        {
            // Fatal error
            ret = -1;
        }
        goto cleanup;
    }

    // Success
    *call_result = 0;

cleanup:
    if (memory_to_checksum != NULL)
    {
        free(memory_to_checksum);
    }
    return ret;
}

static int tracer_call_store_key_value(tracer_data_t * tracer_data, uint64_t * call_result, int key_index,
                                       uint64_t key_value)
{
    int ret = 0;
    if (key_index < 0 || key_index >= KEYSTORE_SIZE)
    {
        *call_result = -EINVAL;
        goto cleanup;
    }

    keystore[key_index] = key_value;
    *call_result = 0;

cleanup:
    return ret;
}

static int tracer_call_get_key_value(tracer_data_t * tracer_data, uint64_t * call_result, int key_index,
                                     uint64_t * key_value_out)
{
    int ret = 0;
    uint64_t key_value = 0;
    int res = 0;
    struct iovec local_iov;
    struct iovec remote_iov;

    if (key_index < 0 || key_index >= KEYSTORE_SIZE)
    {
        *call_result = -EINVAL;
        goto cleanup;
    }

    if (is_in_protected_region(key_value_out, sizeof(*key_value_out)))
    {
        *call_result = -EPERM;
        goto cleanup;
    }

    key_value = keystore[key_index];
    local_iov.iov_base = &key_value;
    local_iov.iov_len = sizeof(key_value);
    remote_iov.iov_base = key_value_out;
    remote_iov.iov_len = sizeof(key_value);
    errno = 0;
    res = process_vm_writev(tracer_data->child_pid, &local_iov, 1, &remote_iov, 1, 0);
    if (res == -1)
    {
        if (errno != ESRCH)
        {
            *call_result = -errno;
        }
        else
        {
            // Fatal error
            ret = -1;
        }
        goto cleanup;
    }

    // Success
    *call_result = 0;

cleanup:
    return ret;
}

// We implement "tracer-call" concept: a fake syscall service, which the tracer (us) serves.
// The way for the tracee to issue tracer-call is by calling the "fake" syscall __NR_tracer_call (0x1337).
// Notice this function should only be called on PTRACE_SYSCALL_INFO_ENTRY state.
// Notice that tracer-calls can fail in one of 2 ways: failure in which the tracer can still proceed, which will
// be reported using the 'result' out param; and fatal error - which reported as usual in the return value of this
// function.
static int handle_single_tracer_call(tracer_data_t * tracer_data, struct ptrace_syscall_info * syscall_info,
                                     uint64_t * result)
{
    int ret = 0;
    uint64_t tracer_call_retval = 0;

    // Run the correct tracer-call
    uint64_t tracer_call_command = syscall_info->entry.args[0];
    uint64_t tracer_call_arg0 = syscall_info->entry.args[1];
    uint64_t tracer_call_arg1 = syscall_info->entry.args[2];
    uint64_t tracer_call_arg2 = syscall_info->entry.args[3];
    uint64_t tracer_call_arg3 = syscall_info->entry.args[4];
    switch (tracer_call_command)
    {
    case TRACER_CALL_COMMAND_NOP:
        ret = tracer_call_nop(tracer_data, &tracer_call_retval);
        break;

    case TRACER_CALL_COMMAND_WRITE_FLAG_TO_PROTECTED_REGION:
        ret = tracer_call_write_flag_to_protected_region(tracer_data, &tracer_call_retval);
        break;

    case TRACER_CALL_COMMAND_CLEAR_PROTECTED_REGION:
        ret = tracer_call_clear_protected_region(tracer_data, &tracer_call_retval);
        break;

    case TRACER_CALL_COMMAND_CHECKSUM_TRACEE_MEMORY:
        ret = tracer_call_checksum_tracee_memory(tracer_data, &tracer_call_retval, (void *)tracer_call_arg0,
                                                 (uint32_t *)tracer_call_arg1, (uint8_t *)tracer_call_arg2);
        break;

    case TRACER_CALL_COMMAND_STORE_KEY_VALUE:
        ret = tracer_call_store_key_value(tracer_data, &tracer_call_retval, (int)tracer_call_arg0,
                                          (uint64_t)tracer_call_arg1);
        break;

    case TRACER_CALL_COMMAND_GET_KEY_VALUE:
        ret = tracer_call_get_key_value(tracer_data, &tracer_call_retval, (int)tracer_call_arg0,
                                        (uint64_t *)tracer_call_arg1);
        break;

    default:
        tracer_call_retval = -ENOSYS;
        break;
    }

    if (result != NULL)
    {
        *result = tracer_call_retval;
    }

    return ret;
}

// Set the result of a tracer-call (in practice - just sets 'rax' to the result).
static int set_tracer_call_res(tracer_data_t * tracer_data, uint64_t result)
{
    int ret = 0;
    struct user_regs_struct original_user_regs = { 0 };
    struct iovec iov;

    iov.iov_len = sizeof(original_user_regs);
    iov.iov_base = &original_user_regs;
    ret = ptrace(PTRACE_GETREGSET, tracer_data->child_pid, NT_PRSTATUS, &iov);
    if (ret == -1)
    {
        goto cleanup;
    }

    original_user_regs.rax = result;

    ret = ptrace(PTRACE_SETREGSET, tracer_data->child_pid, NT_PRSTATUS, &iov);
    if (ret == -1)
    {
        goto cleanup;
    }

    ret = 0;

cleanup:
    return ret;
}

static int handle_tracer_calls(tracer_data_t * tracer_data)
{
    int ret = 0;
    int status = 0;
    struct ptrace_syscall_info syscall_info;
    int signal_to_forward = 0;

    uint64_t tracer_call_res = 0;
    bool should_set_tracer_call_res = false;

    ret = ptrace(PTRACE_SETOPTIONS, tracer_data->child_pid, NULL, PTRACE_O_TRACESYSGOOD);
    if (ret != 0)
    {
        goto cleanup;
    }

    // Trace all the tracee syscalls.
    PRINT_INFO("Handling tracer-calls...");
    while (true)
    {
        ret = ptrace(PTRACE_SYSCALL, tracer_data->child_pid, NULL, signal_to_forward);
        if (ret != 0)
        {
            goto cleanup;
        }

        ret = waitpid(tracer_data->child_pid, &status, 0);
        if (ret == -1)
        {
            goto cleanup;
        }

        // Implement the tracer-call
        ret = ptrace(PTRACE_GET_SYSCALL_INFO, tracer_data->child_pid, sizeof(syscall_info), &syscall_info);
        if (ret == -1)
        {
            goto cleanup;
        }

        if (syscall_info.op == PTRACE_SYSCALL_INFO_ENTRY)
        {
            switch (syscall_info.entry.nr)
            {
            // tracer-call handling
            case __NR_tracer_call:
                if (handle_single_tracer_call(tracer_data, &syscall_info, &tracer_call_res) == -1)
                {
                    ret = -1;
                    goto cleanup;
                }

                should_set_tracer_call_res = true;
                break;

            // Disallowed syscalls
            case __NR_execve:
                // Kill the child! Please don't run disallowed syscalls ;)
                ret = -1;
                goto cleanup;

            default:
                break;
            }
        }
        else if (syscall_info.op == PTRACE_SYSCALL_INFO_EXIT)
        {
            // tracer-call retval forwarding
            if (should_set_tracer_call_res)
            {
                should_set_tracer_call_res = false;
                if (set_tracer_call_res(tracer_data, tracer_call_res) != 0)
                {
                    ret = -1;
                    goto cleanup;
                }
            }
        }

        // Forward signal to tracee if this is not a syscall-stop
        if (WIFSTOPPED(status) && (WSTOPSIG(status) == (SIGTRAP | 0x80)))
        {
            // syscall - forward no signal
            signal_to_forward = 0;
        }
        else if (WIFSTOPPED(status))
        {
            signal_to_forward = WSTOPSIG(status);
        }
    }

    ret = ptrace(PTRACE_SETOPTIONS, tracer_data->child_pid, NULL, 0);
    if (ret != 0)
    {
        goto cleanup;
    }

cleanup:
    return ret;
}

/* This is the parent process. It will:
 * 1. Trace child process.
 * 2. Wait for 'execve' to occur.
 * 3. Inject syscalls to create desired effect.
 * 4. Let the user run safely, providing tracer-calls for it.
 * 5. When finished - kill child.
 */
static int parent_execute(pid_t child_pid, int protected_region_fd)
{
    int ret = 0;
    tracer_data_t tracer_data = { .child_pid = child_pid, .protected_region_fd = protected_region_fd };

    ret = set_child_execution_timeout(&tracer_data);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = trace_child(&tracer_data);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = cont_child_until_execve(&tracer_data);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = inject_initial_syscalls(&tracer_data);
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = handle_tracer_calls(&tracer_data);
    if (ret != 0)
    {
        goto cleanup;
    }

cleanup:
    if (child_execution_timeout_exceeded)
    {
        PRINT_ERROR("Child exceeded execution timeout! Please be more efficient :P");
    }

    // Best-effort
    kill_child(tracer_data.child_pid);

    return ret;
}

static int elf_check(const char * filename)
{
    Elf_Binary_t * elf_binary = elf_parse(filename);
    if (elf_binary == NULL)
    {
        PRINT_ERROR("failed to parse ELF binary");
        return -1;
    }

    Elf_Header_t header = elf_binary->header;
    uint8_t * identity = header.identity;
    int ret = 0;

    if (identity[EI_CLASS] != ELFCLASS64)
    {
        PRINT_ERROR("invalid ELF class \"%s\"", ELF_CLASS_to_string(identity[EI_CLASS]));
        ret = -1;
        goto cleanup;
    }

    if (elf_binary->interpreter != NULL)
    {
        PRINT_ERROR("Please statically-link everything =D");
        ret = -1;
        goto cleanup;
    }

    Elf_Section_t ** sections = elf_binary->sections;
    for (size_t i = 0; i < header.numberof_sections; ++i)
    {
        Elf_Section_t * section = sections[i];
        if (section == NULL || is_in_protected_region((void *)section->virtual_address, section->size))
        {
            PRINT_ERROR("Invalid ELF section");
            ret = -1;
            goto cleanup;
        }
    }

    Elf_Segment_t ** segments = elf_binary->segments;
    for (size_t i = 0; segments[i] != NULL; ++i)
    {
        Elf_Segment_t * segment = segments[i];
        if (is_in_protected_region((void *)segment->virtual_address, segment->virtual_size))
        {
            PRINT_ERROR("Invalid ELF segment");
            ret = -1;
            goto cleanup;
        }
    }

cleanup:
    elf_binary_destroy(elf_binary);
    return ret;
}

// Returns the fd number of the protected region file, or -1 on failure.
int init_protected_region(void)
{
    int result_fd = -1;
    int fd = -1;
    char filename[MAX_PATH_SIZE] = { 0 };

    strncpy(filename, REGION_FILENAME_TEMPLATE, sizeof(filename));
    fd = mkstemp(filename);
    if (-1 == fd)
    {
        goto cleanup;
    }

    // Zero-out entire page
    if (-1 == ftruncate(fd, PROTECTED_REGION_SIZE))
    {
        goto cleanup;
    }

    // Success
    result_fd = fd;

cleanup:
    if (result_fd == -1 && fd != -1)
    {
        close(fd);
    }

    return result_fd;
}

int main(void)
{
    int protected_region_fd = -1;
    char filename[MAX_PATH_SIZE] = { 0 };
    int ret = 0;
    pid_t pid = 0;

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (!is_host_compatible())
    {
        PRINT_ERROR("Host not compatiable with running this sandbox.");
        return EXIT_FAILURE;
    }

    PRINT_INFO("Run your executable! But we made sure you can't read the flag ;)");

    PRINT_INFO("Waiting for an ELF binary...");
    strncpy(filename, ELF_FILENAME_TEMPLATE, sizeof(filename));
    ret = recv_payload_elf(STDIN_FILENO, filename);
    if (ret != 0)
    {
        return EXIT_FAILURE;
    }

    ret = elf_check(filename);
    if (ret != 0)
    {
        goto cleanup;
    }

    protected_region_fd = init_protected_region();
    if (protected_region_fd == -1)
    {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    pid = fork();
    if (pid == -1)
    {
        PRINT_ERROR("fork failed?!");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    // child / parent
    if (pid == 0)
    {
        child_execute(filename);
    }
    ret = parent_execute(pid, protected_region_fd);

cleanup:
    if (unlink(filename) == -1)
    {
        PRINT_ERROR("unlink \"%s\" failed", filename);
    }

    return ret;
}
