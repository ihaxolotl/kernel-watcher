/* rmdir_hook.c - Syscall hook for rmdir()
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#include <linux/module.h>
#include <linux/cred.h>

#include "registered_hooks.h"
#include "syscall_hook.h"

extern struct syscall_hook *__syscall_hook;

#ifdef PTREGS_SYSCALL_STUBS

/* rmdir system call hook via ptregs. */
asmlinkage int rmdir_hook(const struct pt_regs *regs)
{
    ptregs_syscall_hook_t sys_rmdir;
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};
    long err;
    kuid_t current_user_id = current_uid();

    sys_rmdir = (ptregs_syscall_hook_t)syscall_hook_get_original(__syscall_hook, __NR_rmdir);
    err = strncpy_from_user(dir_name, pathname, NAME_MAX);
    if (err > 0 && current_user_id.val > 0) {
        printk(KERN_INFO "uid: %d, rmdir: %s\n", current_user_id.val, dir_name);
    }

    return sys_rmdir(regs); 
}

#else

/* rmdir hook for older kernels */
asmlinkage int rmdir_hook(const char *path)
{
    sys_rmdir_t sys_rmdir = (sys_rmdir_t)syscall_hook_get_original(__syscall_hook, __NR_rmdir);
    return sys_rmdir(path, mode);
}
#endif
