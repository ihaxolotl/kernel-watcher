/* module.c - Kernel Module Main
 * Loadable kernel module for intercepting and hooking Linux system calls.
 *
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include "syscall_hook.h"
#include "hooks/registered_hooks.h"
#include "network.h"

struct syscall_hook *__syscall_hook;
struct socket *server_sock;

/* Pointer to the system call table. */
static unsigned long long *my_sys_call_table64;
static unsigned int *my_sys_call_table32;

/* Get the addresses of the system call table for both 64-bit and
 * 32-bit programs. */
static inline int setup_sys_call_table(void)
{
    /* Load the address of the 64-bit system call table. */
    my_sys_call_table64 = (void *)kallsyms_lookup_name("sys_call_table");
    if (my_sys_call_table64 == 0) {
        printk(KERN_ERR "Could not get the address of the x86_64 sys_call_table\n");
        return -1;
    }

    printk(KERN_INFO "x86_64 System Call Table Address: %p\n", my_sys_call_table64);

    /* Load the address of the 32-bit system call table. */
    my_sys_call_table32 = (void *)kallsyms_lookup_name("ia32_sys_call_table");
    if (my_sys_call_table32 == 0) {
        printk(KERN_ERR "Could not get the address of the x86 sys_call_table\n");
        return -1;
    }

    /* Initialize the system call hook table. */
    __syscall_hook = syscall_hook_init(my_sys_call_table32, my_sys_call_table64);
    if (__syscall_hook == NULL) {
        printk(KERN_INFO "Could not initialize syscall hook table.\n");
        return -1;
    }

    printk(KERN_INFO "x86 System Call Table Address: %p\n", my_sys_call_table32);
    return 0;
}

/* Hook the specified system calls. */
static inline void setup_sys_call_hooks(void)
{
    /* Hook mkdir, rmdir and execve */
    syscall_hook_create(__syscall_hook, __NR_mkdir, (void *)mkdir_hook);
    syscall_hook_create(__syscall_hook, __NR_rmdir, (void *)rmdir_hook);
    syscall_hook_create(__syscall_hook, __NR_execve, (void *)execve_hook);

    printk(KERN_INFO "watcher: hooked the specified system calls!\n");
}

/* LKM Init */
static int __init intercept_module_init(void)
{
    struct sockaddr_in s_addr;
    char data[] = "It worked!\n";
    int err = 0;
    
    server_sock = NULL;
    printk(KERN_INFO "watcher: module is loading...\n");

    /* Setup __syscall_hook */
    err = setup_sys_call_table();
    if (err != 0) {
        return 0;
    }

    setup_sys_call_hooks();

    /* Connect to the server */
    err = server_connect(&s_addr, "127.0.0.1", DEFAULT_PORT);
    if (err != 0) {
        return 0;
    }

    err = server_send(data, sizeof(data));
    if (err != 0) {
        return 0;
    }

    printk(KERN_INFO "watcher: module successfully loaded!\n");
    return 0;
}

/* LKM exit */
static void __exit intercept_module_exit(void)
{
    syscall_hook_free(__syscall_hook);
    server_free();
    printk(KERN_INFO "watcher: module exited.\n");
}

module_init(intercept_module_init);
module_exit(intercept_module_exit);
MODULE_LICENSE("GPL");
