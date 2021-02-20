/* mkdir_hook.c - Syscall hook for mkdir()
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#include <linux/module.h>
#include <linux/cred.h>

#include "registered_hooks.h"
#include "syscall_hook.h"

#ifdef PTREGS_SYSCALL_STUBS
/* mkdir system call hook via ptregs. */
asmlinkage int mkdir_hook(const struct pt_regs *regs)
{
    ptregs_syscall_hook_t sys_mkdir;
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};
    long err;
    kuid_t current_user_id = current_uid();

    /* Original system call */
    sys_mkdir = (ptregs_syscall_hook_t)syscall_hook_get_original(__syscall_hook, __NR_mkdir);

    /* Filter logging to human users and not root. */
    if (current_user_id.val == 0) {
        return sys_mkdir(regs);
    }

    /* Copy string */
    err = strncpy_from_user(dir_name, pathname, NAME_MAX);
    if (err > 0 && current_user_id.val > 0) {
        printk(KERN_INFO "uid: %d, mkdir: %s\n", current_user_id.val, dir_name);
    }

    return sys_mkdir(regs); 
}

#else
/* mkdir hook for older kernels */
asmlinkage int mkdir_hook(const char *path, int mode)
{
    sys_mkdir_t sys_mkdir = (sys_mkdir_t)syscall_hook_get_original(__syscall_hook, __NR_mkdir);
    kuid_t current_user_id = current_uid();

    /* Filter logging to human users and not root. */
    if (current_user_id.val == 0) {
        return sys_mkdir(path, mode);
    }

    printk(KERN_INFO "User %u executed mkdir! :D\n", current_user_id.val);
    return sys_mkdir(path, mode);
}
#endif
