/* syscall_hook.c - Intercept system calls 
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#ifndef __SYSCALL_HOOK__
#define __SYSCALL_HOOK__

/* System call hook. */
struct syscall_hook {
    /* Pointer to the 32-bit system call table. */
    unsigned int *sys_call_table32;

    /* Pointer to the 64-bit system call table. */
    unsigned long long *sys_call_table64;

    /* Head of the linked list. */
    struct syscall_hook_entry *head;

    /* Tail of the linked list. */
    struct syscall_hook_entry *tail;
};

/* Type of system call hook.
 * 32-bit or 64-bit. */
enum syscall_hook_type {
    SYS_HOOK_32,
    SYS_HOOK_64,
};

/* Linked list structure for storing system call hook function pointer. */
struct syscall_hook_entry {
    /* Address of the next system call hook */
    struct syscall_hook_entry *next;

    /* ID of the Linux system call */
    unsigned int syscall_id;

    /* Address of the original function */
    uintptr_t original;

    /* Address of the hooked function */
    uintptr_t hooked;

    /* Type of system call hook. 32-bit or 64-bit */
    enum syscall_hook_type type;
};

/* The 16th bit of CR0 must be set in to order to disable write protection. */
#define CR0_WRITE_PROTECT (1 << 16)

struct syscall_hook *syscall_hook_init(unsigned int *, unsigned long long *);
int syscall_hook_create(struct syscall_hook*, unsigned int, void *);
uintptr_t syscall_hook_get_original(struct syscall_hook *, unsigned int);
void syscall_hook_free(struct syscall_hook *);

#endif
