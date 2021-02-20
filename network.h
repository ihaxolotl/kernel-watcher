/* network.h - Networking capabilities 
 * Written by Brett Broadhurst <brettbroadhurst@gmail.com>
 */

#ifndef __WATCHER_NETWORK__
#define __WATCHER_NETWORK__

#include <linux/socket.h>
#include <net/sock.h>

#define DEFAULT_BUFFER_SIZE 1024
#define DEFAULT_PORT 8888

/* Connect to a remote server from the kernel. */
int server_connect(struct sockaddr_in *s_addr, const char *host, const int port);

/* Send data to a remote server from the kernel. */
int server_send(char *send_buffer, size_t buff_len); 

/* Shutdown and free the connection structure memory. */
void server_free(void);
#endif
