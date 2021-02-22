/* network.c - Networking capabilites 
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <net/sock.h>

#include "network.h"

/* Connect to a remote server from the kernel. */
int server_connect(
        struct sockaddr_in *s_addr,
        const char *host,
        const int port
)
{
    int ret = 0; /* Return code */
    
    /* Set up the socket struct. */
    memset(s_addr, 0, sizeof(struct sockaddr_in));
    s_addr->sin_family = AF_INET;
    s_addr->sin_port = htons(port);
    s_addr->sin_addr.s_addr = in_aton(host);

    /* Create the kernel socket */
    server_sock = (struct socket *)kmalloc(sizeof(struct socket), GFP_KERNEL);
    if (server_sock == NULL) {
        printk(KERN_EMERG "watcher: could not allocate memory for kernel socket!\n");
        return -1;
    }

    /* Create the kernel socket */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &server_sock);
    if (ret < 0) {
        printk(KERN_EMERG "watcher: could not create kernel TCP socket!\n");
        return ret;
    }

    /* Connect to the new socket */
    ret = server_sock->ops->connect(server_sock, (struct sockaddr *)s_addr, sizeof(*s_addr), 0);
    if (ret != 0) {
        printk(KERN_EMERG "watcher: could not connect to the kernel socket!\n");
        return ret;
    }

    return 0;
}

/* Send data to a remote server from the kernel. */
int server_send(char *send_buffer, size_t buff_len) {
    struct kvec send_vec;   /* Send Vector */
    struct msghdr send_msg; /* Message header */
    int ret = 0;            /* Returned byte count */
    
    memset(&send_msg, 0, sizeof(send_msg));
    memset(&send_vec, 0, sizeof(send_vec));
    send_vec.iov_base = send_buffer;
    send_vec.iov_len = buff_len;

    /* Send data over the socket */
    ret = kernel_sendmsg(server_sock, &send_msg, &send_vec, 1, buff_len);
    if (ret < 0) {
        printk(KERN_EMERG "watcher: could not send buffer over socket!\n");
        return ret;
    } 

    return 0;
}

/* Shutdown and free the connection structure memory. */
void server_free()
{
    kernel_sock_shutdown(server_sock, SHUT_RDWR);
    sock_release(server_sock);
}
