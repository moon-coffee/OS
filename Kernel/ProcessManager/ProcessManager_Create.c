#include "ProcessManager.h"

#include "../ELF/ELF_Loader.h"
#include "../GDT/GDT_Main.h"
#include "../Memory/Memory_Main.h"
#include "../Paging/Paging_Main.h"
#include "../Serial.h"
#include "../Syscall/Syscall_File.h"
#include "../Syscall/Syscall_Main.h"
#include "../WindowManager/WindowManager.h"

#include <stddef.h>
#include <stdint.h>

#define PROCESS_KERNEL_STACK_SIZE (16 * 1024)
#define PROCESS_USER_ALLOC_MAX 128
#define PROCESS_SIGNAL_MAX 32
#define PROCESS_RFLAGS_DEFAULT 0x202ULL
#define PROCESS_GUARD_PAGE_SIZE PAGE_SIZE

#define PROCESS_STATE_UNUSED 0
#define PROCESS_STATE_READY  1
#define PROCESS_STATE_RUNNING 2
#define PROCESS_STATE_DEAD 3

#define PROCESS_CONTEXT_QWORDS SYSCALL_FRAME_QWORDS
#define PROCESS_ELF_MAX_SIZE (2ULL * 1024ULL * 1024ULL)

typedef struct {
    uint8_t used;
    uint64_t addr;
    uint32_t size;
} user_alloc_t;

typedef struct {
    uint8_t state;
    process_capability_mask_t capability_mask;
    uint64_t entry;
    uint64_t saved_rsp;
    uint64_t saved_user_rsp;
    uint64_t cr3;
    uint8_t *kernel_stack_base;
    uint64_t kernel_stack_top;
    uint64_t user_code_base;
    uint64_t user_code_limit;
    uint64_t user_heap_base;
    uint64_t user_heap_cursor;
    uint64_t user_heap_limit;
    uint64_t user_heap_guard_page;
    uint64_t user_stack_base;
    uint64_t user_stack_top;
    uint64_t user_stack_guard_page;
    user_alloc_t user_allocs[PROCESS_USER_ALLOC_MAX];
    uint64_t signal_handlers[PROCESS_SIGNAL_MAX];
} process_t;

static process_t *g_processes = NULL;
static int32_t g_process_capacity = 0;
static int32_t g_current_pid = -1;

static void halt_forever(void)
{
    while (1) {
        __asm__ volatile ("hlt");
    }
}

static uint64_t align_up_u64(uint64_t value, uint64_t align)
{
    return (value + align - 1ULL) & ~(align - 1ULL);
}

static int is_valid_user_entry(uint64_t entry)
{
    return (entry >= USER_CODE_BASE) &&
           (entry < USER_CODE_LIMIT);
}

static int process_table_ready(void)
{
    return g_processes != NULL && g_process_capacity > 0;
}

static int is_valid_pid(int32_t pid)
{
    return process_table_ready() && pid >= 0 && pid < g_process_capacity;
}

static void reset_process_slot(process_t *proc)
{
    if (proc == NULL) {
        return;
    }

    proc->state = PROCESS_STATE_UNUSED;
    proc->capability_mask = 0;
    proc->entry = 0;
    proc->saved_rsp = 0;
    proc->saved_user_rsp = 0;
    proc->cr3 = 0;
    proc->kernel_stack_base = NULL;
    proc->kernel_stack_top = 0;
    proc->user_code_base = 0;
    proc->user_code_limit = 0;
    proc->user_heap_base = 0;
    proc->user_heap_cursor = 0;
    proc->user_heap_limit = 0;
    proc->user_heap_guard_page = 0;
    proc->user_stack_base = 0;
    proc->user_stack_top = 0;
    proc->user_stack_guard_page = 0;
    for (uint32_t i = 0; i < PROCESS_USER_ALLOC_MAX; ++i) {
        proc->user_allocs[i].used = 0;
        proc->user_allocs[i].addr = 0;
        proc->user_allocs[i].size = 0;
    }
    for (uint32_t i = 0; i < PROCESS_SIGNAL_MAX; ++i) {
        proc->signal_handlers[i] = 0;
    }
}

static void release_process_resources(process_t *proc)
{
    if (proc == NULL) {
        return;
    }

    if (proc->cr3 != 0) {
        paging_destroy_process_space(proc->cr3);
        proc->cr3 = 0;
    }
    if (proc->kernel_stack_base != NULL) {
        kfree(proc->kernel_stack_base);
        proc->kernel_stack_base = NULL;
    }
    proc->kernel_stack_top = 0;
    proc->capability_mask = 0;
    proc->user_code_base = 0;
    proc->user_code_limit = 0;
    proc->user_heap_base = 0;
    proc->user_heap_cursor = 0;
    proc->user_heap_limit = 0;
    proc->user_heap_guard_page = 0;
    proc->user_stack_base = 0;
    proc->user_stack_top = 0;
    proc->user_stack_guard_page = 0;
    for (uint32_t i = 0; i < PROCESS_USER_ALLOC_MAX; ++i) {
        proc->user_allocs[i].used = 0;
        proc->user_allocs[i].addr = 0;
        proc->user_allocs[i].size = 0;
    }
    for (uint32_t i = 0; i < PROCESS_SIGNAL_MAX; ++i) {
        proc->signal_handlers[i] = 0;
    }
}

static void release_process_table(void)
{
    if (!process_table_ready()) {
        return;
    }

    for (int32_t i = 0; i < g_process_capacity; ++i) {
        if (g_processes[i].state != PROCESS_STATE_UNUSED) {
            release_process_resources(&g_processes[i]);
            reset_process_slot(&g_processes[i]);
        }
    }

    kfree(g_processes);
    g_processes = NULL;
    g_process_capacity = 0;
    g_current_pid = -1;
}

static int32_t find_free_slot(void)
{
    if (!process_table_ready()) {
        return -1;
    }

    for (int32_t i = 0; i < g_process_capacity; ++i) {
        if (g_processes[i].state == PROCESS_STATE_UNUSED) {
            return i;
        }
        if (g_processes[i].state == PROCESS_STATE_DEAD && i != g_current_pid) {
            release_process_resources(&g_processes[i]);
            reset_process_slot(&g_processes[i]);
            return i;
        }
    }
    return -1;
}

static int32_t pick_next_ready(int32_t current_pid)
{
    if (!process_table_ready()) {
        return -1;
    }

    if (current_pid < 0) {
        for (int32_t i = 0; i < g_process_capacity; ++i) {
            if (g_processes[i].state == PROCESS_STATE_READY ||
                g_processes[i].state == PROCESS_STATE_RUNNING) {
                return i;
            }
        }
        return -1;
    }

    for (int32_t step = 1; step <= g_process_capacity; ++step) {
        int32_t idx = (current_pid + step) % g_process_capacity;
        if (g_processes[idx].state == PROCESS_STATE_READY) {
            return idx;
        }
    }
    if (g_processes[current_pid].state == PROCESS_STATE_RUNNING ||
        g_processes[current_pid].state == PROCESS_STATE_READY) {
        return current_pid;
    }
    return -1;
}

static void activate_process_context(process_t *proc)
{
    paging_switch_cr3(proc->cr3);
    syscall_set_kernel_rsp(proc->kernel_stack_top);
    gdt_set_kernel_rsp0(proc->kernel_stack_top);
}

static int initialize_process_memory(process_t *proc, uint64_t entry)
{
    if (proc == NULL) {
        return -1;
    }

    proc->kernel_stack_base = kmalloc(PROCESS_KERNEL_STACK_SIZE);
    if (!proc->kernel_stack_base) {
        return -1;
    }
    proc->kernel_stack_top = ((uint64_t)(uintptr_t)(proc->kernel_stack_base + PROCESS_KERNEL_STACK_SIZE)) & ~0xFULL;

    proc->cr3 = paging_create_process_space();
    if (!proc->cr3) {
        return -1;
    }

    proc->user_code_base = USER_CODE_BASE;
    proc->user_code_limit = USER_CODE_LIMIT;
    proc->user_heap_base = USER_HEAP_BASE;
    proc->user_heap_cursor = USER_HEAP_BASE;
    proc->user_heap_limit = USER_HEAP_LIMIT;
    proc->user_stack_base = USER_STACK_BASE;
    proc->user_stack_top = USER_STACK_TOP;
    proc->capability_mask = PROCESS_CAP_DEFAULT_MASK;

    if (proc->user_code_limit <= proc->user_code_base ||
        proc->user_heap_limit <= proc->user_heap_base ||
        proc->user_stack_top <= proc->user_stack_base ||
        proc->user_code_limit > proc->user_heap_base ||
        proc->user_heap_limit > proc->user_stack_base) {
        serial_write_string("[OS] [PROC] Invalid user layout\n");
        return -1;
    }

    if ((proc->user_heap_limit - proc->user_heap_base) <= PROCESS_GUARD_PAGE_SIZE ||
        (proc->user_stack_top - proc->user_stack_base) <= PROCESS_GUARD_PAGE_SIZE) {
        serial_write_string("[OS] [PROC] User memory layout too small for guard pages\n");
        return -1;
    }

    proc->user_heap_guard_page = proc->user_heap_limit - PROCESS_GUARD_PAGE_SIZE;
    proc->user_heap_limit -= PROCESS_GUARD_PAGE_SIZE;
    proc->user_stack_guard_page = proc->user_stack_base;
    proc->user_stack_base += PROCESS_GUARD_PAGE_SIZE;

    if (proc->user_heap_limit <= proc->user_heap_cursor ||
        proc->user_stack_top <= proc->user_stack_base ||
        proc->user_heap_limit > proc->user_stack_base) {
        serial_write_string("[OS] [PROC] User heap/stack collision risk\n");
        return -1;
    }

    if (paging_set_user_access(proc->cr3,
                               proc->user_code_base,
                               proc->user_code_limit - proc->user_code_base,
                               1) < 0) {
        return -1;
    }
    if (paging_set_user_access(proc->cr3,
                               proc->user_heap_base,
                               proc->user_heap_limit - proc->user_heap_base,
                               1) < 0) {
        return -1;
    }
    if (paging_set_user_access(proc->cr3,
                               proc->user_stack_base,
                               proc->user_stack_top - proc->user_stack_base,
                               1) < 0) {
        return -1;
    }

    if (paging_unmap_range(proc->cr3, proc->user_heap_guard_page, PROCESS_GUARD_PAGE_SIZE) < 0 ||
        paging_unmap_range(proc->cr3, proc->user_stack_guard_page, PROCESS_GUARD_PAGE_SIZE) < 0) {
        serial_write_string("[OS] [PROC] Failed to set guard pages\n");
        return -1;
    }

    uint64_t user_stack_top = proc->user_stack_top;
    uint64_t *frame = (uint64_t *)(uintptr_t)(user_stack_top - (PROCESS_CONTEXT_QWORDS * sizeof(uint64_t)));
    for (uint32_t i = 0; i < PROCESS_CONTEXT_QWORDS; ++i) {
        frame[i] = 0;
    }

    frame[SYSCALL_FRAME_RCX] = entry;
    frame[SYSCALL_FRAME_R11] = PROCESS_RFLAGS_DEFAULT;

    proc->saved_rsp = (uint64_t)(uintptr_t)frame;
    proc->saved_user_rsp = user_stack_top;

    return 0;
}

static int range_within(uint64_t addr, uint64_t len, uint64_t start, uint64_t end)
{
    if (len == 0) {
        return 1;
    }
    uint64_t addr_end = addr + len;
    if (addr_end <= addr) {
        return 0;
    }
    return (addr >= start) && (addr_end <= end);
}

void process_manager_init(void)
{
    int32_t desired_capacity = PROCESS_MAX_COUNT_CONFIG;
    if (desired_capacity < 1) {
        desired_capacity = 1;
    }

    release_process_table();

    uint64_t table_size_u64 = (uint64_t)desired_capacity * (uint64_t)sizeof(process_t);
    if (table_size_u64 == 0 || table_size_u64 > 0xFFFFFFFFULL) {
        serial_write_string("[OS] [PROC] Invalid process table size\n");
        halt_forever();
    }

    g_processes = (process_t *)kmalloc((uint32_t)table_size_u64);
    if (g_processes == NULL) {
        serial_write_string("[OS] [PROC] Failed to allocate process table\n");
        halt_forever();
    }

    g_process_capacity = desired_capacity;
    for (int32_t i = 0; i < g_process_capacity; ++i) {
        reset_process_slot(&g_processes[i]);
    }
    g_current_pid = -1;

    serial_write_string("[OS] [PROC] Process slot capacity=");
    serial_write_uint32((uint32_t)g_process_capacity);
    serial_write_string("\n");
}

int32_t process_register_boot_process(uint64_t entry, uint64_t user_stack_top)
{
    (void)user_stack_top;

    int32_t pid = process_create_user(entry);
    if (pid < 0) {
        serial_write_string("[OS] [PROC] No free slot for boot process\n");
        return -1;
    }

    process_t *proc = &g_processes[pid];

    proc->state = PROCESS_STATE_RUNNING;
    g_current_pid = pid;

    activate_process_context(proc);

    serial_write_string("[OS] [PROC] Boot process registered\n");
    return pid;
}

int32_t process_create_user(uint64_t entry)
{
    if (!process_table_ready() || !is_valid_user_entry(entry)) {
        return -1;
    }

    int32_t pid = find_free_slot();
    if (pid < 0) {
        serial_write_string("[OS] [PROC] No free slot for process create\n");
        return -1;
    }

    process_t *proc = &g_processes[pid];
    reset_process_slot(proc);

    if (initialize_process_memory(proc, entry) < 0) {
        release_process_resources(proc);
        reset_process_slot(proc);
        return -1;
    }

    proc->state = PROCESS_STATE_READY;
    proc->entry = entry;
    return pid;
}

int32_t process_spawn_user_elf(const char *path)
{
    if (!path || path[0] == '\0') {
        return -1;
    }

    elf_load_policy_t policy = {
        .max_file_size = PROCESS_ELF_MAX_SIZE,
        .min_vaddr = USER_CODE_BASE,
        .max_vaddr = USER_CODE_LIMIT,
    };
    uint64_t entry = 0;

    if (!elf_loader_load_from_path(path, &policy, &entry)) {
        serial_write_string("[OS] [PROC] Failed to load process ELF: ");
        serial_write_string(path);
        serial_write_string("\n");
        return -1;
    }

    int32_t pid = process_create_user(entry);
    if (pid < 0) {
        serial_write_string("[OS] [PROC] No free slot for process create\n");
        return -1;
    }

    return pid;
}

void process_exit_current(void)
{
    if (!is_valid_pid(g_current_pid)) {
        return;
    }

    uint32_t closed_fds = 0;
    uint32_t closed_dirs = 0;
    syscall_file_close_all_for_pid(g_current_pid, &closed_fds, &closed_dirs);
    int32_t closed_windows = window_manager_destroy_window_for_process(g_current_pid);

    serial_write_string("[OS] [PROC] exit_cleanup pid=");
    serial_write_uint32((uint32_t)g_current_pid);
    serial_write_string(" fds=");
    serial_write_uint32(closed_fds);
    serial_write_string(" dirs=");
    serial_write_uint32(closed_dirs);
    serial_write_string(" windows=");
    serial_write_uint32((closed_windows > 0) ? (uint32_t)closed_windows : 0);
    serial_write_string("\n");

    g_processes[g_current_pid].state = PROCESS_STATE_DEAD;
}

int32_t process_get_current_pid(void)
{
    return g_current_pid;
}

uint64_t process_get_current_user_rsp(void)
{
    if (!is_valid_pid(g_current_pid)) {
        return 0;
    }
    return g_processes[g_current_pid].saved_user_rsp;
}

uint64_t process_get_current_cr3(void)
{
    if (!is_valid_pid(g_current_pid)) {
        return paging_get_kernel_cr3();
    }
    return g_processes[g_current_pid].cr3;
}

uint64_t process_schedule_on_syscall(uint64_t current_saved_rsp,
                                     uint64_t current_user_rsp,
                                     int request_switch,
                                     uint64_t *next_user_rsp_out)
{
    if (next_user_rsp_out != NULL) {
        *next_user_rsp_out = current_user_rsp;
    }

    if (!is_valid_pid(g_current_pid)) {
        serial_write_string("[OS] [PROC] Invalid current PID\n");
        return current_saved_rsp;
    }

    process_t *current = &g_processes[g_current_pid];
    if (current->state == PROCESS_STATE_RUNNING || current->state == PROCESS_STATE_READY) {
        current->saved_rsp = current_saved_rsp;
        current->saved_user_rsp = current_user_rsp;
        current->state = PROCESS_STATE_READY;
    }

    if (!request_switch && current->state != PROCESS_STATE_DEAD) {
        current->state = PROCESS_STATE_RUNNING;
        activate_process_context(current);
        if (next_user_rsp_out != NULL) {
            *next_user_rsp_out = current->saved_user_rsp;
        }
        return current->saved_rsp;
    }

    int32_t next_pid = pick_next_ready(g_current_pid);
    if (next_pid < 0) {
        serial_write_string("[OS] [PROC] No runnable process. Halting.\n");
        halt_forever();
    }

    g_current_pid = next_pid;
    process_t *next = &g_processes[g_current_pid];
    next->state = PROCESS_STATE_RUNNING;

    activate_process_context(next);

    if (next_user_rsp_out != NULL) {
        *next_user_rsp_out = next->saved_user_rsp;
    }
    return next->saved_rsp;
}

uint64_t process_schedule_after_exit(uint64_t *next_user_rsp_out)
{
    if (next_user_rsp_out != NULL) {
        *next_user_rsp_out = 0;
    }

    if (!is_valid_pid(g_current_pid)) {
        serial_write_string("[OS] [PROC] Invalid current PID on exit schedule\n");
        halt_forever();
    }

    int32_t next_pid = pick_next_ready(g_current_pid);
    if (next_pid < 0) {
        serial_write_string("[OS] [PROC] No runnable process after exit. Halting.\n");
        halt_forever();
    }

    g_current_pid = next_pid;
    process_t *next = &g_processes[g_current_pid];
    next->state = PROCESS_STATE_RUNNING;

    activate_process_context(next);

    if (next_user_rsp_out != NULL) {
        *next_user_rsp_out = next->saved_user_rsp;
    }
    return next->saved_rsp;
}

int process_user_buffer_is_valid(const void *ptr, uint64_t len)
{
    if (!is_valid_pid(g_current_pid)) {
        return 0;
    }

    const process_t *proc = &g_processes[g_current_pid];
    uint64_t addr = (uint64_t)(uintptr_t)ptr;

    if (len == 0) {
        return 1;
    }

    if (range_within(addr, len, proc->user_code_base, proc->user_code_limit)) {
        return 1;
    }
    if (range_within(addr, len, proc->user_heap_base, proc->user_heap_limit)) {
        return 1;
    }
    if (range_within(addr, len, proc->user_stack_base, proc->user_stack_top)) {
        return 1;
    }
    return 0;
}

int process_user_cstring_length(const char *str, uint64_t max_len, uint64_t *len_out)
{
    if (str == NULL || max_len == 0) {
        return -1;
    }

    for (uint64_t i = 0; i < max_len; ++i) {
        if (!process_user_buffer_is_valid(str + i, 1)) {
            return -1;
        }
        if (str[i] == '\0') {
            if (len_out != NULL) {
                *len_out = i;
            }
            return 0;
        }
    }
    return -1;
}

void *process_user_alloc(uint32_t size)
{
    if (!is_valid_pid(g_current_pid) || size == 0) {
        return NULL;
    }

    process_t *proc = &g_processes[g_current_pid];
    if (proc->user_heap_base == 0 ||
        proc->user_heap_limit <= proc->user_heap_base ||
        proc->user_heap_cursor < proc->user_heap_base ||
        proc->user_heap_cursor > proc->user_heap_limit) {
        return NULL;
    }
    uint64_t alloc_size = align_up_u64((uint64_t)size, 16ULL);

    for (uint32_t i = 0; i < PROCESS_USER_ALLOC_MAX; ++i) {
        user_alloc_t *slot = &proc->user_allocs[i];
        if (!slot->used && slot->size != 0 && slot->size >= alloc_size) {
            slot->used = 1;
            return (void *)(uintptr_t)slot->addr;
        }
    }

    uint32_t new_slot = PROCESS_USER_ALLOC_MAX;
    for (uint32_t i = 0; i < PROCESS_USER_ALLOC_MAX; ++i) {
        if (proc->user_allocs[i].size == 0) {
            new_slot = i;
            break;
        }
    }
    if (new_slot == PROCESS_USER_ALLOC_MAX) {
        return NULL;
    }

    uint64_t addr = align_up_u64(proc->user_heap_cursor, 16ULL);
    uint64_t next = addr + alloc_size;
    if (next <= addr || next > proc->user_heap_limit) {
        return NULL;
    }

    proc->user_heap_cursor = next;
    proc->user_allocs[new_slot].used = 1;
    proc->user_allocs[new_slot].addr = addr;
    proc->user_allocs[new_slot].size = (uint32_t)alloc_size;

    uint8_t *p = (uint8_t *)(uintptr_t)addr;
    for (uint64_t i = 0; i < alloc_size; ++i) {
        p[i] = 0;
    }

    return (void *)(uintptr_t)addr;
}

int process_user_free(void *ptr)
{
    if (ptr == NULL) {
        return 0;
    }
    if (!is_valid_pid(g_current_pid)) {
        return -1;
    }

    process_t *proc = &g_processes[g_current_pid];
    uint64_t addr = (uint64_t)(uintptr_t)ptr;

    for (uint32_t i = 0; i < PROCESS_USER_ALLOC_MAX; ++i) {
        user_alloc_t *slot = &proc->user_allocs[i];
        if (slot->used && slot->addr == addr) {
            slot->used = 0;
            return 0;
        }
    }
    return -1;
}

void *process_user_mmap(uint64_t length, uint64_t flags)
{
    if (!is_valid_pid(g_current_pid) || length == 0) {
        return NULL;
    }

    if ((flags & ~1ULL) != 0) {
        return NULL;
    }

    uint64_t aligned_len = align_up_u64(length, PAGE_SIZE);
    if (aligned_len == 0 || aligned_len > UINT32_MAX) {
        return NULL;
    }

    return process_user_alloc((uint32_t)aligned_len);
}

uint64_t process_signal_set_handler(int32_t signum, uint64_t handler)
{
    if (!is_valid_pid(g_current_pid)) {
        return (uint64_t)-1;
    }
    if (signum <= 0 || signum >= PROCESS_SIGNAL_MAX) {
        return (uint64_t)-1;
    }

    if (handler != 0 &&
        !process_user_buffer_is_valid((const void *)(uintptr_t)handler, 1)) {
        return (uint64_t)-1;
    }

    process_t *proc = &g_processes[g_current_pid];
    uint64_t previous = proc->signal_handlers[(uint32_t)signum];
    proc->signal_handlers[(uint32_t)signum] = handler;
    return previous;
}

int process_is_guard_page_fault(uint64_t fault_addr)
{
    if (!is_valid_pid(g_current_pid)) {
        return 0;
    }

    const process_t *proc = &g_processes[g_current_pid];
    uint64_t fault_page = fault_addr & PAGE_MASK;
    return (fault_page == proc->user_heap_guard_page ||
            fault_page == proc->user_stack_guard_page);
}

process_capability_mask_t process_default_capabilities(void)
{
    return PROCESS_CAP_DEFAULT_MASK;
}

process_capability_mask_t process_get_current_capabilities(void)
{
    if (!is_valid_pid(g_current_pid)) {
        return 0;
    }
    return g_processes[g_current_pid].capability_mask;
}

int process_current_has_capability(process_capability_mask_t capability)
{
    if (capability == 0) {
        return 1;
    }

    process_capability_mask_t current = process_get_current_capabilities();
    return ((current & capability) == capability);
}

int process_set_capabilities(int32_t pid, process_capability_mask_t capabilities)
{
    if (!is_valid_pid(pid)) {
        return -1;
    }

    g_processes[pid].capability_mask = capabilities;
    return 0;
}

int process_get_capabilities(int32_t pid, process_capability_mask_t *capabilities_out)
{
    if (!is_valid_pid(pid) || capabilities_out == NULL) {
        return -1;
    }

    *capabilities_out = g_processes[pid].capability_mask;
    return 0;
}
