#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <errno.h>

// Implemented in 'syscall.S'
long syscall_func(long number, ...);

#define __NR_tracer_call (0x1337)
#define CHECKSUM_STR "[!] Checksum: "
#define KEY_LOAD_STR "[!] Key loaded successfuly!"
#define NEWLINE "\n"

int _start(void)
{
    // Calculate and print checksum
    uint8_t checksum = 0;
    uint8_t data_to_checksum[] = {0xaa, 0xbb, 0x70};
    uint32_t data_to_checksum_size = sizeof(data_to_checksum);
    syscall_func(__NR_tracer_call, 3, &data_to_checksum, &data_to_checksum_size, &checksum);    
    syscall_func(__NR_write, 1, CHECKSUM_STR, sizeof(CHECKSUM_STR) - 1);
    syscall_func(__NR_write, 1, &checksum, sizeof(checksum));
    syscall_func(__NR_write, 1, NEWLINE, sizeof(NEWLINE) - 1);

    // Use the keystore (store/load to key_index=17)
    syscall_func(__NR_tracer_call, 4, 17, 0xdeadbeef);
    uint64_t key_value = 0;
    syscall_func(__NR_tracer_call, 5, 17, &key_value);
    if (key_value == 0xdeadbeef)
    {
        syscall_func(__NR_write, 1, KEY_LOAD_STR, sizeof(KEY_LOAD_STR) - 1);
        syscall_func(__NR_write, 1, NEWLINE, sizeof(NEWLINE) - 1);
    }

    // Exit
    syscall_func(__NR_exit, 0); 
}

