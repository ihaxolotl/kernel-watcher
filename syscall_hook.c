/* syscall_hook.c - Intercept system calls 
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "syscall_hook.h"

/* Get the value stored in the protected cr0 register */
static uint64_t get_cr0(void)
{
    uint64_t ret;

    __asm__ volatile (
        "movq %%cr0, %[ret]"
        : [ret] "=r" (ret)
    );

    return ret;
}

/* Set the value stored in the protected cr0 register */
static void set_cr0(uint64_t cr0)
{
    __asm__ volatile (
        "movq %[cr0], %%cr0"
        :
        : [cr0] "r" (cr0)
    );
}

/* Create the linked list for storing system call hooks. */
struct syscall_hook *syscall_hook_init(unsigned int *kernel32, unsigned long long *kernel64)
{
    struct syscall_hook *sh = kmalloc(sizeof(struct syscall_hook), GFP_KERNEL);
    if (IS_ERR(sh)) {
        printk(KERN_INFO "could not allocate memory for hooks\n");
        return NULL;
    }

    sh->sys_call_table32 = kernel32;
    sh->sys_call_table64 = kernel64;
    sh->head = NULL;
    sh->tail = NULL;

    return sh;
}

/* Create a new hook. */
int syscall_hook_create(struct syscall_hook *hook, unsigned int syscall_id, void *func)
{
    struct syscall_hook_entry *entry;

    entry = kmalloc(sizeof (struct syscall_hook_entry), GFP_KERNEL);
    if (IS_ERR(entry)) {
        printk(KERN_INFO "could not allocate memory for a new syscall hook\n");
        return -1;
    }

    entry->next = NULL;
    entry->syscall_id = syscall_id;
    entry->original = hook->sys_call_table64[syscall_id];
    entry->hooked = (uintptr_t)func;
    entry->type = SYS_HOOK_64;

    set_cr0(get_cr0() & ~CR0_WRITE_PROTECT);
    hook->sys_call_table64[syscall_id] = (unsigned long long)entry->hooked;
    set_cr0(get_cr0() | CR0_WRITE_PROTECT);

    if (hook->head == NULL) {
        hook->head = entry;
        hook->tail = entry;
    } else {
        hook->tail->next = entry;
        hook->tail = entry;
    }

    return 0;
}

/* Get the original function pointer of the system call. */
uintptr_t syscall_hook_get_original(struct syscall_hook *hook, unsigned int syscall_id)
{
    struct syscall_hook_entry *s;
    for (s = hook->head; s != NULL; s = s->next) {
        if (s->type == SYS_HOOK_64 && s->syscall_id == syscall_id) {
            return s->original;
        }
    }

    return 0;
}

/* Free the system call hook. */
void syscall_hook_free(struct syscall_hook *hook)
{
    struct syscall_hook_entry *s;
    struct syscall_hook_entry *tmp;

    /* Check if there is nothing to free. */
    if (hook == NULL) {
        return;
    }

    /* Disable memory protection. */
    set_cr0(get_cr0() & ~CR0_WRITE_PROTECT);
    
    /* Go through the entire linked list of syscall hook entries, replace the original
     * function pointers and their allocated memory. */
    for (s = hook->head; s != NULL;) {
        /* Handle the system call patch according to the architecture. */
        switch (s->type) {
            case SYS_HOOK_64: {
                hook->sys_call_table64[s->syscall_id] = (unsigned long long)s->original;
            } break;

            case SYS_HOOK_32: {
                hook->sys_call_table32[s->syscall_id] = (unsigned int)s->original;
            } break;

            default:
                printk(KERN_EMERG "memory corruption detected!\n");
                break;
        }

        tmp = s->next;
        kfree(s);
        s = tmp;
    }

    /* Enable memory protection again */
    set_cr0(get_cr0() | CR0_WRITE_PROTECT);

    /* Free the hook table. */
    kfree(hook);
}
