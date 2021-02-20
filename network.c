/* network.c - Networking capabilites 
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <net/sock.h>

#include "network.h"

/* Setup needed structures for sending data over a kernel socket. */
void setup_send_buffer(char *send_buffer, struct kvec *send_vec, struct msghdr *send_msg)
{
    memset(send_msg, 0, sizeof(*send_msg));
    memset(send_vec, 0, sizeof(*send_vec));
    send_vec->iov_base = send_buffer;
    send_vec->iov_len = DEFAULT_BUFFER_SIZE;
}

/* Connect to a remote server from the kernel. */
int server_connect(
        struct socket *sock,
        struct sockaddr_in *s_addr,
        const char *host,
        const int port
)
{
    int ret = 0; /* Return code */

    /* Check if the socket pointer is NULL */
    if (sock != NULL) {
        printk(KERN_ERR "watcher: socket structure already initialized\n");
        return -1;
    }
    
    /* Set up the socket struct. */
    memset(s_addr, 0, sizeof(*s_addr));
    s_addr->sin_family = AF_INET;
    s_addr->sin_port = htons(port);
    s_addr->sin_addr.s_addr = in_aton(host);

    /* Create the kernel socket */
    sock = (struct socket *)kmalloc(sizeof(struct socket), GFP_KERNEL);
    if (sock == NULL) {
        printk(KERN_EMERG "watcher: could not allocate memory for kernel socket!\n");
        return -1;
    }

    /* Create the kernel socket */
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret < 0) {
        printk(KERN_EMERG "watcher: could not create kernel TCP socket!\n");
        return ret;
    }

    printk(KERN_INFO "watcher: successfully created a kernel socket!\n");

    /* Connect to the new socket */
    ret = sock->ops->connect(sock, (struct sockaddr *)s_addr, sizeof(*s_addr), 0);
    if (ret != 0) {
        printk(KERN_EMERG "watcher: could not connect to the kernel socket!\n");
        return ret;
    }

    printk(KERN_INFO "watcher: connection established!\n");
    return 0;
}

/* Send data to a remote server from the kernel. */
int server_send(struct socket *sock, char *send_buffer) {
    struct kvec send_vec;   /* Send Vector */
    struct msghdr send_msg; /* Message header */
    int ret = 0;            /* Returned byte count */

    if (send_buffer == NULL) {
        printk(KERN_ERR "watcher: no data to send\n");
        return -1;
    }

    /* Send data over the socket */
    setup_send_buffer(send_buffer, &send_vec, &send_msg);
    ret = kernel_sendmsg(sock, &send_msg, &send_vec, 1, DEFAULT_BUFFER_SIZE);
    if (ret < 0) {
        printk(KERN_EMERG "watcher: could not send buffer over socket!\n");
        return ret;
    } else if (ret != DEFAULT_BUFFER_SIZE){
        printk(KERN_ERR "watcher: bytes sent did not equal the buffer size!\n");
    }

    printk("watcher: sent data successfully!\n");
    return 0;
}


/* Shutdown and free the connection structure memory. */
void server_free(struct socket *sock)
{
    kernel_sock_shutdown(sock, SHUT_RDWR);
    sock_release(sock);
}
