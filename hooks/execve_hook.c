/* execve_hook.c - Syscall hook for execve()
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#include <linux/module.h>
#include <linux/cred.h>

#include "registered_hooks.h"
#include "syscall_hook.h"

#ifdef PTREGS_SYSCALL_STUBS

/* execve system call hook via ptregs. */
asmlinkage int execve_hook(const struct pt_regs *regs)
{
    ptregs_syscall_hook_t sys_execve;
    char __user *filename = (char *)regs->di;
    char __user **argv = (char **)regs->si;

    char **p_argv = (char **)argv;
    char *exec_str = NULL;
    size_t exec_line_size;
    kuid_t current_user_id = current_uid();

    /* Original system call */
    sys_execve = (ptregs_syscall_hook_t)syscall_hook_get_original(__syscall_hook, __NR_execve);

    /* Filter logging to human users and not root. */
    if (current_user_id.val == 0) {
        return sys_execve(regs);
    }

    /* Add the length of the uid string to the execve string. */
    exec_line_size = (strlen("UID: 60000\n") + 1);

    /* Add the length of the filename to the execve string. */
    exec_line_size += (strlen(filename) + 1);
    exec_line_size += 1;
    
    /* Calculate the size of the execve command string by checking all
     * elements in argv[]. */
    while (*p_argv != NULL) {
        exec_line_size += (strlen(*p_argv) + 1);
        (char **)p_argv++;
    }

    /* Allocate memory for the execve command string. */
    exec_str = vmalloc(exec_line_size);
    if (exec_str == NULL) {
        printk(KERN_EMERG "watcher: could not allocate memory for execve string!\n");
        return sys_execve(regs); 
    }

    memset(exec_str, 0, exec_line_size);

    /* Copy user id to execve string. */
    snprintf(exec_str, exec_line_size, "UID: %d\n", current_user_id.val);

    /* Copy filename to the execve string. */
    snprintf(exec_str, exec_line_size, "%s%s\n", exec_str, filename);
    p_argv = (char **)argv;

    /* Copy all execve argv elements to the execve string. */
    while (*p_argv != NULL) {
        snprintf(exec_str, exec_line_size, "%s%s ", exec_str, *p_argv);
        (char **)p_argv++;
    }

    snprintf(exec_str, exec_line_size, "%s\n", exec_str);
    server_send(exec_str, exec_line_size);

    /* Free the memory. */
    vfree(exec_str);
    return sys_execve(regs); 
}

#else

/* execve system call hook for older kernels. */
asmlinkage int execve_hook(const struct pt_regs *regs)
{
    ptregs_syscall_hook_t sys_execve;
    sys_execve = (ptregs_syscall_hook_t)syscall_hook_get_original(__syscall_hook, __NR_execve);
    return sys_execve(regs); 
}

#endif
