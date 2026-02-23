#include <stdint.h>

#define SYSCALL_SERIAL_PUTCHAR     1ULL
#define SYSCALL_SERIAL_PUTS        2ULL
#define SYSCALL_SERIAL_WRITE_U64   3ULL
#define SYSCALL_SERIAL_WRITE_U32   4ULL
#define SYSCALL_SERIAL_WRITE_U16   5ULL
#define SYSCALL_PROCESS_CREATE     6ULL
#define SYSCALL_PROCESS_YIELD      7ULL
#define SYSCALL_PROCESS_EXIT       8ULL
#define SYSCALL_THREAD_CREATE      9ULL
#define SYSCALL_PROCESS_SPAWN_ELF  36ULL

static inline uint64_t syscall0(uint64_t num)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(num)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline uint64_t syscall1(uint64_t num, uint64_t arg1)
{
    uint64_t ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(arg1)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static void serial_write_string(const char *str)
{
    (void)syscall1(SYSCALL_SERIAL_PUTS, (uint64_t)str);
}

static void serial_write_uint32(int32_t value)
{
    char buf[12];
    int idx = 0;
    uint64_t v;
    int64_t signed_value = (int64_t)value;

    if (signed_value < 0) {
        (void)syscall1(SYSCALL_SERIAL_PUTCHAR, (uint64_t)'-');
        v = (uint64_t)(-signed_value);
    } else {
        v = (uint64_t)signed_value;
    }

    if (v == 0) {
        (void)syscall1(SYSCALL_SERIAL_PUTCHAR, (uint64_t)'0');
        return;
    }

    while (v > 0) {
        buf[idx++] = (char)('0' + (v % 10u));
        v /= 10u;
    }

    while (idx > 0) {
        (void)syscall1(SYSCALL_SERIAL_PUTCHAR, (uint64_t)buf[--idx]);
    }
}

static int32_t process_spawn_elf(const char *path)
{
    return (int32_t)syscall1(SYSCALL_PROCESS_SPAWN_ELF, (uint64_t)path);
}

static void process_yield(void)
{
    (void)syscall0(SYSCALL_PROCESS_YIELD);
}

__attribute__((noreturn))
static void process_exit(void)
{
    (void)syscall0(SYSCALL_PROCESS_EXIT);
    while (1) {
    }
}

void _start(void)
{
    serial_write_string("[U][INIT] boot process started\n");

    int32_t pid = process_spawn_elf("Userland/SystemApps/UserApp.ELF");
    if (pid < 0) {
        serial_write_string("[U][INIT] spawn failed for UserApp.ELF\n");
        while (1) {
            process_yield();
        }
    }

    serial_write_string("[U][INIT] spawned UserApp.ELF pid=");
    serial_write_uint32(pid);
    serial_write_string("\n");
    serial_write_string("[U][INIT] exiting init process\n");

    process_exit();
}
