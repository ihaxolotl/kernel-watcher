# Kernel Watcher 
This is a simple project to demonstrate intercepting system calls and communicating back to a remote server.

This technique is often used in Kernel-mode rootkits.

## Goals
Kernel watcher is a simple 'pseudo-rootkit' that hooks system calls and sends the results to a remote server.
The server is not included. If you want to use parts of this project for your own needs, you can figure it out.
To even run this kernel module, you must have a server listening on a port that the module wants to connect to.

## Challenges
### The Kernel
The kernel is very unforgiving. You can easily bring down your system if you're not careful.
A lot of quality of life functions do not exist because of the absence of the C standard library.
You work directly with GNU/Linux kernel functions. This can be both a lot of fun and a healthy dose of trauma.

Different versions of the Linux kernel have differing levels of security and implementation for hooking system calls.
Since having direct access to kernel structures poses a significant risk to end users of a system, more work needs to be done for recent kernel versions.
Direct addresses of the system call table or other structures may not be available as the kernel matures.
However, this can be overcome by bruteforcing kernel memory, which is not difficult.

For this project, my environment was on Debian 10 with a kernel version greater than 4.17.0.
In kernel versions 4.17.0 and higher, arguments to system calls are passed as an argument via the pt_regs struct.
This struct has pointers to general purpose registers used in system calls.

In kernel versions prior to 4.17.0, arguments are passed directly to each function that handles system calls.
Analogous to how we invoke system calls with prototypes defined in <unistd.h>.

### System Calls
Every program that gets executed fires off numerous system calls.
Some system calls are much simpler to hook and may also be called a lot less than others.

For example, read() and write() are incredibly common while reboot() or mount() may be called more sparingly.
Percautions need to be taken, since functions called inside system call hooks can cause recursive interception.
There are ways to prevent this, but I didn't really care to.

The mkdir() and rmdir() system calls are very easy to intercept, given the fact that they only have one string argument.
I have included proof of concepts for them in the hooks/ directory.

However, the real challenge I wanted to take on was execve().
Hooking execve() would reveal every program execution on a target system.
To make it the task even more fun, I wanted the following:
- the UNIX id of the user executing the program
- the current directory of the user when they executed the program
- the path of the program being executed
- the command line arguments passed to the program

Extracting this data involved a lot of research, though the kernel has all of this data ready.
You just need to know where to look.
<linux/cred.h> is used to get the current user id.
<linux/fs_struct.h> is used to get the current working directory of the current user.

I intentionally drop any system call hook that is executed by root, since the kernel also invokes system calls...and very often!
There is a simple check if the current user has the UNIX id of 0 (root). If so, return now.

## Outcomes
If you set up a server to listen for the kernel module to connect back to:
- A connection will be established
- All registered hooks will send data in JSON format
- JSON can be parsed for a variety of application functionality.

## Final Thoughts
This was a lot of fun. It took about 2-3 days to get working right, but I'm pretty happy with it.
