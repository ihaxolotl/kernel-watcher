/* registered_hooks.h - Registered System Call Hook Functions
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#ifndef __REGISTERED_HOOKS__
#define __REGISTERED_HOOKS__

#include <linux/syscalls.h>
#include <linux/version.h>

/* Check for an updated kernel. */
    #if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
        #define PTREGS_SYSCALL_STUBS 1
    #endif

    #ifdef PTREGS_SYSCALL_STUBS
        /* Ptregs syscall */
        typedef asmlinkage long (*ptregs_syscall_hook_t)(const struct pt_regs *);

        /* mkdir syscall hook */
        asmlinkage int mkdir_hook(const struct pt_regs *regs);

        /* rmdir syscall hook */
        asmlinkage int rmdir_hook(const struct pt_regs *regs);

        /* execve syscall hook */
        asmlinkage int execve_hook(const struct pt_regs *regs);
    
    #else
        /* Types of hook function pointers */
        typedef asmlinkage int (*sys_mkdir_t)(const char *, int);

        /* Hook function definitions */
        asmlinkage int mkdir_hook(const char *, int);
        asmlinkage int rmdir_hook(const char *);
        asmlinkage int execve_hook(
            const char __user *filename,
            const char __user *const __user *argv,
            const char __user *const __user *envp);
    #endif
#endif
