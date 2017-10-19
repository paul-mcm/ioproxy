#ifndef RBUF_H
#define RBUF_H

#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "../configuration/config.h"

#define RBUFF_SIZE	512

struct rbuf_entry *new_rbuf();

struct rbuf_entry {
	int	id;
        char	line[BUFF_SIZE];
        struct	iovec iov[1];
        pthread_mutex_t	lock;
	struct	rbuf_entry *next;
};

int rbuf_readfrom(struct io_params *);
int rbuf_writeto(struct io_params *);
void read_cleanup(void *);
struct rbuf_entry *rbuf_new(void);
void free_rbuf(struct rbuf_entry *);
#endif
