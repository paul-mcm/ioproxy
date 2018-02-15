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
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "../configuration/config.h"

#define BUFF_SIZE 1024

struct rbuf_entry *new_rbuf();

struct rbuf_entry { 
	int			id;
        char			*line;
	int			len;
        pthread_mutex_t		mtx_lock;
        pthread_rwlock_t	rw_lock;
	struct	rbuf_entry	*next;
};

int rbuf_rwlock_readfrom(struct io_params *);
int rbuf_rwlock_writeto(struct io_params *);

int rbuf_mtx_readfrom(struct io_params *);
int rbuf_mtx_writeto(struct io_params *);

int rbuf_t3_readfrom(struct io_params *);

void read_cleanup(void *);
struct rbuf_entry *new_rbuf(int, int);
void free_rbuf(struct rbuf_entry *);
void sleep_unlocked(struct io_params *, int, void *);

int io_error(struct io_params *, int);

void rbuf_locksync0(struct io_params *);
void rbuf_locksync(struct io_params *);

#endif
