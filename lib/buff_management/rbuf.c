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

#include "rbuf.h"

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

int rbuf_mtx_writeto(struct io_params *iop)
{
	struct rbuf_entry *w_ptr;
	int i, r;

	w_ptr = iop->rbuf_p;

	/* CALL pthread_conf_signal() TO SYNCHRONIZE 
	* LOCKING OF FIRST ENTRY IN LIST.  THIS THREAD 
	* MUST GET THE LOCK FIRST.
	*/

	/* GRAB LOCK */
	MTX_LOCK(&w_ptr->mtx_lock);

	MTX_LOCK(&iop->listlock);
	*iop->listready = 1;
	MTX_UNLOCK(&iop->listlock);

	/* SIGNAL WRITE THREAD */
	pthread_cond_signal(&iop->readable);

	for (;;) {
	    if ((i = read(iop->io_fd, w_ptr->line, iop->buf_sz)) > 0) {
		w_ptr->len = i;
		MTX_LOCK(&w_ptr->next->mtx_lock);
		MTX_UNLOCK(&w_ptr->mtx_lock);
		iop->bytes += i;
		iop->io_cnt++;
		w_ptr = w_ptr->next;
		continue;
	    } else if (i == 0) {
		/* read returned EOF - not an error 
		* COULD SET UP ASYNC IO NOTIFICATION
		*/
		sleep(3);
		continue;
	    } else {
		if (io_error(iop, errno) == 0) {
		    sleep(3);
		    continue;
		} else {
		    MTX_UNLOCK(&w_ptr->mtx_lock);
		    return -1;
 		}
	    }
	}
}

int rbuf_mtx_readfrom(struct io_params *iop)
{
        struct rbuf_entry *r_ptr;
	int nleft;
        int r, nw;
	char *lptr;

        MTX_LOCK(&iop->listlock);
        while (*iop->listready == 0)
                pthread_cond_wait(&iop->readable, &iop->listlock);
        MTX_UNLOCK(&iop->listlock);

	r_ptr = iop->rbuf_p;
	MTX_LOCK(&r_ptr->mtx_lock);

        for (;;) {
	    lptr = r_ptr->line;
	    nleft = r_ptr->len;

	    while (nleft > 0) {
		nw = write(iop->io_fd, lptr, r_ptr->len);
		if (nw == r_ptr->len) {
		    nleft -= nw;
		    iop->bytes += nw;
		    iop->io_cnt++;
		    MTX_LOCK(&r_ptr->next->mtx_lock);
		    MTX_UNLOCK(&r_ptr->mtx_lock);
		    r_ptr = r_ptr->next;
		    continue;
		} else if (nw < r_ptr->len && nw > 0) {
		    nleft -= nw;
		    lptr += nw;
		    iop->bytes += nw;
		    continue;
		} else if (nw == 0) {
		    sleep_unlocked(3, &r_ptr->mtx_lock);
		    continue;
		} else if (nw < 0) {
		    if (io_error(iop, errno) == 0) {
			sleep_unlocked(3, &r_ptr->mtx_lock);
			continue;
		    } else {
			/* UNKOWN ERROR; * ASSUME DESC INVALID */
			MTX_UNLOCK(&r_ptr->mtx_lock);
			log_ret("write() error", errno);
			return -1;
		    }
		}
	    }
        }       
}

int rbuf_rwlock_writeto(struct io_params *iop)
{
	struct rbuf_entry *w_ptr;
	int i, r;

	w_ptr = iop->rbuf_p;
	/* CALL pthread_conf_signal() TO SYNCHRONIZE 
	* LOCKING OF FIRST ENTRY IN LIST.  THIS THREAD 
	* MUST GET THE LOCK FIRST.
	*/

	/* GRAB LOCK */
	WR_LOCK(&w_ptr->rw_lock);

	MTX_LOCK(&iop->listlock);
	*iop->listready = 1;
	MTX_UNLOCK(&iop->listlock);

	/* SIGNAL WRITE THREAD */
	pthread_cond_signal(&iop->readable);

	for (;;) {
	    if ((i = read(iop->io_fd, w_ptr->line, iop->buf_sz)) > 0) {
/*		log_msg("w_ptr read %d bytes from %d into ringbuff\n", i, iop->io_fd); */
		w_ptr->len = i;
	
		WR_LOCK(&w_ptr->next->rw_lock);
		RW_UNLOCK(&w_ptr->rw_lock);

		iop->bytes += i;
		iop->io_cnt++;
		w_ptr = w_ptr->next;
	    } else if (i == 0) {
		/* read returned EOF - not an error */
		sleep(3);
		continue;
	    } else {
		if (io_error(iop, errno) == 0) {
		    sleep(3);
		    continue;
		} else {
		    RW_UNLOCK(&w_ptr->rw_lock);
		    return -1;
		}
	    }
	}
}

int rbuf_rwlock_readfrom(struct io_params *iop)
{
	struct rbuf_entry *r_ptr;
	char *buf_ptr;
	int nleft;
	int r, nw;
	char *lptr;

	MTX_LOCK(&iop->listlock);
	while (*iop->listready == 0)
	    pthread_cond_wait(&iop->readable, &iop->listlock);
	MTX_UNLOCK(&iop->listlock);

	r_ptr = iop->rbuf_p;
	RD_LOCK(&r_ptr->rw_lock);

	for (;;) {
	    lptr = r_ptr->line;
	    nleft = r_ptr->len;

	    while (nleft > 0) {
		nw = write(iop->io_fd, lptr, r_ptr->len);
		if (nw == r_ptr->len) {
		    nleft -= nw;
		    iop->bytes += nw;
		    iop->io_cnt++;
		    RD_LOCK(&r_ptr->next->rw_lock);
		    RW_UNLOCK(&r_ptr->rw_lock);
		    r_ptr = r_ptr->next;
		    continue;
		} else if (nw < r_ptr->len && nw > 0) {
		    nleft -= nw;
		    lptr += nw;
		    iop->bytes += nw;
		    continue;
		} else if (nw == 0) {
		    RW_UNLOCK(&r_ptr->rw_lock);
		    sleep(3);
		    RD_LOCK(&r_ptr->rw_lock);
		    continue;
		} else if (nw < 0) {
		    /* SOME KNOWN ERROR; WORTH RETRYING? */
		    if (io_error(iop, errno) == 0) {
			pthread_rwlock_unlock(&r_ptr->rw_lock);
			sleep(3);
			pthread_rwlock_rdlock(&r_ptr->rw_lock);
			continue;
		    } else {
			/* UNKOWN ERROR; * ASSUME DESC INVALID */
			RW_UNLOCK(&r_ptr->rw_lock);
			return -1;
		    }
		}
	    }
	}
}

int rbuf_t3_readfrom(struct io_params *iop)
{
        struct rbuf_entry *r_ptr;
        int r, nw, nleft;
	char *lptr;

        MTX_LOCK(&iop->listlock);
        while (*iop->listready == 0)
                pthread_cond_wait(&iop->readable, &iop->listlock);
        MTX_UNLOCK(&iop->listlock);

	r_ptr = iop->rbuf_p;
	MTX_LOCK(&r_ptr->mtx_lock);
	MTX_LOCK(&iop->fd_lock);
	
        for (;;) {
	    lptr = r_ptr->line;
	    nleft = r_ptr->len;

	    while (nleft > 0) {
		nw = write(*iop->iofd_p, lptr, r_ptr->len);
		if (nw == r_ptr->len) {
		    nleft -= nw;
		    iop->bytes += nw;
		    iop->io_cnt++;
		    MTX_UNLOCK(&iop->fd_lock);
		    MTX_LOCK(&r_ptr->next->mtx_lock);
		    MTX_UNLOCK(&r_ptr->mtx_lock);
		    MTX_LOCK(&iop->fd_lock);
		    r_ptr = r_ptr->next;
		    continue;
		} else if (nw < r_ptr->len && nw > 0) {
		    nleft -= nw;
		    lptr += nw;
		    iop->bytes += nw;
		    continue;
		} else if (nw == 0) {
		    sleep_unlocked(3, &iop->fd_lock);
		    continue;
		} else if (nw < 0) {
		    if (io_error(iop, errno) == 0) {
			sleep_unlocked(3, &r_ptr->mtx_lock);
			continue;
		    } else {
			MTX_UNLOCK(&iop->fd_lock);
			MTX_UNLOCK(&r_ptr->mtx_lock);
			return -1;
		    }
		}
	    }
	}      
}

struct rbuf_entry *new_rbuf(int t, int sz)
{
	int i;
	struct rbuf_entry *e, *prev_ptr, *head;
	pthread_mutexattr_t mtx_attrs;
	pthread_rwlockattr_t rwlock_attrs;

	if (t == TYPE_2)
	    pthread_rwlockattr_init(&rwlock_attrs);
	else
	    pthread_mutexattr_init(&mtx_attrs);

	prev_ptr = NULL;

	/* INITIALIZE LIST OF BUFFERS */
	for (i = 64; i >= 1; i--) {
	    if ((e = malloc(sizeof(struct rbuf_entry))) == NULL)
		log_syserr("rbuf malloc error");

	    e->id = i;
	    if ((e->line = malloc(sz)) == NULL)
		log_syserr("rbuf malloc error");
	    else
		e->len = 0;

	    if (t == TYPE_2)
		pthread_rwlock_init(&e->rw_lock, &rwlock_attrs);
	    else
		pthread_mutex_init(&e->mtx_lock, &mtx_attrs);

	    if (prev_ptr != NULL) {
		prev_ptr->next = e;
	    } else {
		head = e;
	    }
	    prev_ptr = e;
	}
	e->next = head;
	return head;
}

void free_rbuf(struct rbuf_entry *rbuf)
{
	int i;
	struct rbuf_entry *rb, *rb_nxt;
	rb = rbuf;

	/* FREE LIST OF BUFFERS */
	for (i = 1; i < 65; i++) {
	    rb_nxt = rb->next;
	    free(rb);
	    rb = rb_nxt;
	}
}

int io_error(struct io_params *iop, int e)
{
	if (e == EPIPE 		|| \
	    e == ENETDOWN 	|| \
	    e == EDESTADDRREQ 	|| \
	    e == ENOTCONN) {
		log_ret("io error - remote end closed for %d: %s", \
		    iop->io_fd, iop->path);
		return 0;
	    } else {
		log_ret("unknown io error %d %s", e, iop->path);
		return 1;
	    }
}

void sleep_unlocked(int n, pthread_mutex_t *l)
{
	int r;
	
	MTX_UNLOCK(l);
	sleep(n);
	MTX_LOCK(l);
}
