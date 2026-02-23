#pragma once

#include <stdint.h>

#define USER_CODE_BASE    0x0000000000400000ULL
#define USER_CODE_LIMIT   0x0000000004000000ULL
#define USER_HEAP_BASE    USER_CODE_LIMIT
#define USER_STACK_SIZE   (64 * 1024ULL)
#define USER_STACK_TOP    0x0000000008000000ULL
#define USER_STACK_BASE   (USER_STACK_TOP - USER_STACK_SIZE)
#define USER_HEAP_LIMIT   USER_STACK_BASE

#if (USER_CODE_BASE >= USER_CODE_LIMIT)
#error "Invalid user code range"
#endif

#if (USER_HEAP_BASE >= USER_HEAP_LIMIT)
#error "Invalid user heap range"
#endif

#if (USER_STACK_BASE >= USER_STACK_TOP)
#error "Invalid user stack range"
#endif

void process_manager_init(void);
int32_t process_register_boot_process(uint64_t entry, uint64_t user_stack_top);
int32_t process_create_user(uint64_t entry);
int32_t process_spawn_user_elf(const char *path);
void process_exit_current(void);
int32_t process_get_current_pid(void);
uint64_t process_get_current_user_rsp(void);
uint64_t process_get_current_cr3(void);
uint64_t process_schedule_on_syscall(uint64_t current_saved_rsp,
                                     uint64_t current_user_rsp,
                                     int request_switch,
                                     uint64_t *next_user_rsp_out);
uint64_t process_schedule_after_exit(uint64_t *next_user_rsp_out);
int process_user_buffer_is_valid(const void *ptr, uint64_t len);
int process_user_cstring_length(const char *str, uint64_t max_len, uint64_t *len_out);
void *process_user_alloc(uint32_t size);
int process_user_free(void *ptr);
