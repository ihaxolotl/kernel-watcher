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
    /* System call arguments */
    ptregs_syscall_hook_t sys_execve;
    char __user *filename = (char *)regs->di;
    char __user **argv = (char **)regs->si;

    /* Hook arguments */
    char **p_argv = (char **)argv;
    char *json_buffer = NULL;
    size_t json_buffer_size = DEFAULT_BUFFER_SIZE;
    kuid_t current_user_id = current_uid();

    /* Original system call */
    sys_execve = (ptregs_syscall_hook_t)syscall_hook_get_original(__syscall_hook, __NR_execve);

    /* Filter logging to human users and not root. */
    if (current_user_id.val == 0) {
        return sys_execve(regs);
    }

    /* Allocate memory for JSON buffer. */
    json_buffer = vmalloc(json_buffer_size);
    if (json_buffer == NULL) {
        printk(KERN_EMERG "watcher: could not allocate memory for execve string!\n");
        return sys_execve(regs); 
    }

    /* Clear the json buffer. */
    memset(json_buffer, 0, json_buffer_size);

    /* Copy uid and filename to the json_buffer */
    snprintf(json_buffer, json_buffer_size,
            "{\"uid\":%d,\"filename\":\"%s\",\"command\":\"",
            current_user_id.val, filename);

    /* Copy all execve argv elements to the JSON buffer. */
    p_argv = (char **)argv;
    while (*p_argv != NULL) {
        snprintf(json_buffer, json_buffer_size, "%s%s ", json_buffer, *p_argv);
        (char **)p_argv++;
    }

    /* Close off the JSON buffer. */
    snprintf(json_buffer, json_buffer_size, "%s\"}\n", json_buffer);

    /* Send off the JSON buffer. */
    server_send(json_buffer, json_buffer_size);

    /* Free the JSON buffer. */
    vfree(json_buffer);
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
