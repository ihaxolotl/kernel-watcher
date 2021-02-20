# Makefile for the simple kernel module
obj-m := haxx.o 
haxx-objs += module.o
haxx-objs += syscall_hook.o
haxx-objs += hooks/mkdir_hook.o
haxx-objs += hooks/rmdir_hook.o
haxx-objs += hooks/execve_hook.o
haxx-objs += network.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

EXTRA_CFLAGS = -g

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -f *.o modules.order Module.symvers
