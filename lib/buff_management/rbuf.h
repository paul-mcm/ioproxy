/* Copyright (c) 2017-2018 Paul McMath <paulm@tetrardus.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <tls.h>
#include <unistd.h>

#include "../configuration/config.h"

#define BUFF_SIZE 1024

extern pthread_mutex_t sighupstat_lock;

#define RD_LOCK(m)                              \
if ((r = pthread_rwlock_rdlock(m)) != 0) {      \
    log_die("rdlock error: %d\n", r);           \
}

#define WR_LOCK(m)                              \
if ((r = pthread_rwlock_wrlock(m)) != 0) {      \
    log_die("wrlock error: %d\n", r);           \
}

#define RW_UNLOCK(m)                            \
if ((r = pthread_rwlock_unlock(m)) != 0) {      \
    log_die("rwlock unlock: %d\n", r);          \
}

#define MTX_LOCK(m)                             \
if ((r = pthread_mutex_lock(m)) != 0) {         \
    log_die("mtx lock error: %d\n", r);         \
}

#define MTX_UNLOCK(m)                           \
if ((r = pthread_mutex_unlock(m)) != 0) {       \
    log_die("mtx unlock error:  %d\n", r);      \
}

#define UNLOCK(m, l)				\
if (*m->cfgtype_p != TYPE_2) {			\
    MTX_UNLOCK(&l->mtx_lock);			\
} else {					\
    RW_UNLOCK(&l->rw_lock);			\
}

#define LOCK(m, l)				\
if (*m->cfgtype_p != TYPE_2) {			\
    MTX_LOCK(&l->mtx_lock);			\
} else if (*m->cfgtype_p == TYPE_2) {		\
    RD_LOCK(&l->rw_lock);			\
} else	{					\
    printf("THE NO CASE\n");			\
}

struct rbuf_entry *new_rbuf();

struct rbuf_entry { 
	int			id;
        char			*line;
	ssize_t			len;
        pthread_mutex_t		mtx_lock;
        pthread_rwlock_t	rw_lock;
	struct	rbuf_entry	*next;
};

int rbuf_readfrom(struct io_params *);
int rbuf_writeto(struct io_params *);
int rbuf_tls_writeto(struct io_params *);
int rbuf_tls_readfrom(struct io_params *);
int rbuf_ssh_writeto(struct io_params *);
int rbuf_dgram_writeto(struct io_params *);
int rbuf_dgram_readfrom(struct io_params *);

int rbuf_t3_readfrom(struct io_params *);
int rbuf_t3_tlsreadfrom(struct io_params *);

struct rbuf_entry *new_rbuf(int, int);
void free_rbuf(struct io_params *);
void sleep_unlocked(struct io_params *, int, struct rbuf_entry *);

int io_error(struct io_params *, int, int);
int do_wrerr(struct io_params *, struct rbuf_entry *);
int do_rderr(struct io_params *, struct rbuf_entry *);
int do_poll(struct io_params *);

void rbuf_locksync0(struct io_params *);
void rbuf_locksync(struct io_params *);

void do_close(struct io_params *, struct rbuf_entry *);
void close_desc(struct io_params *);
void release_locks(void *);

#endif
