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

#define UNLOCK(m, l)				\
if (m->desc_type != TYPE_2) {			\
    MTX_UNLOCK(&l->mtx_lock);			\
} else {					\
    RW_UNLOCK(&l->rw_lock);			\
}

#define LOCK(m, l)				\
if (m->desc_type != TYPE_2) {			\
    MTX_LOCK(&l->mtx_lock);			\
} else {					\
    RD_LOCK(&l->rw_lock);			\
}

#define CNT_UPDATE(a, b)			\
a->bytes += b;					\
a->io_cnt++;


int rbuf_tls_writeto(struct io_params *iop)
{
	struct sock_param	*sop;
	struct rbuf_entry	*w_ptr;
	int 			i, r;

	sop = iop->sock_data;
	w_ptr = iop->w_ptr;

	if (*iop->listready == 0) {
	    /* THIS THREAD MUST GET THE LOCK FIRST */
	    LOCK(iop, w_ptr);
	    rbuf_locksync0(iop);
	}

	if (*iop->type_p != TYPE_2) {
	    for (;;) {
		if ((w_ptr->len = tls_read(sop->tls_ctx, w_ptr->line, iop->buf_sz)) > 0) {
		    MTX_LOCK(&w_ptr->next->mtx_lock);
		    MTX_UNLOCK(&w_ptr->mtx_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    continue;
		} else {
		    if (do_rderr(iop, w_ptr) < 0)
			return -1;
		}
	    }
	} else {
	    for (;;) {
		if ((w_ptr->len = tls_read(sop->tls_ctx, w_ptr->line, iop->buf_sz)) > 0) {
		    WR_LOCK(&w_ptr->next->rw_lock);
		    RW_UNLOCK(&w_ptr->rw_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    continue;
		} else {
		    if (do_rderr(iop, w_ptr) < 0)
			return -1;
		}
	    }
	}
}

int rbuf_tls_readfrom(struct io_params *iop)
{
        struct rbuf_entry	*r_ptr;
	struct sock_param	*sop;
	int 			nleft, nw, r;
	char			*lptr;

	sop = iop->sock_data;
	r_ptr = set_rbuf_lock(iop);

	if (*iop->type_p != TYPE_2) {
	    for (;;) {
		lptr = r_ptr->line;
		nleft = r_ptr->len;
		while (nleft > 0) {
		    nw = tls_write(sop->tls_ctx, lptr, r_ptr->len);
		    if (nw == r_ptr->len) {
			nleft -= nw;
			MTX_LOCK(&r_ptr->next->mtx_lock);
			MTX_UNLOCK(&r_ptr->mtx_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			continue;
		    } else if (nw < r_ptr->len && nw > 0) {
			nleft -= nw;
			lptr += nw;
			iop->bytes += nw;
			continue;
		    } else if (nw <= 0) {
			if (do_wrerr(iop, r_ptr) < 0)
			    return -1;
		    }
		}
	    }
	} else {
	    for (;;) {
		lptr = r_ptr->line;
		nleft = r_ptr->len;
		while (nleft > 0) {
		    nw = tls_write(sop->tls_ctx, lptr, r_ptr->len);
		    if (nw == r_ptr->len) {
			nleft -= nw;
			RD_LOCK(&r_ptr->next->rw_lock);
			RW_UNLOCK(&r_ptr->rw_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			continue;
		    } else if (nw < r_ptr->len && nw > 0) {
			nleft -= nw;
			lptr += nw;
			iop->bytes += nw;
			continue;
		    } else if (nw <= 0) {
			if (do_wrerr(iop, r_ptr) < 0)
			    return -1;
		    }
		}
	    }
	}
}

int rbuf_writeto(struct io_params *iop)
{
	struct rbuf_entry	*w_ptr;
	int 			i, r;

	w_ptr = iop->w_ptr;

	if (*iop->listready == 0) {
	    /* THIS THREAD MUST GET THE LOCK FIRST */
	    LOCK(iop, w_ptr);
	    rbuf_locksync0(iop);
	}

	if (*iop->type_p != TYPE_2) {
	    for (;;) {
		if ((w_ptr->len = read(iop->io_fd, w_ptr->line, iop->buf_sz)) > 0) {
		    MTX_LOCK(&w_ptr->next->mtx_lock);
		    MTX_UNLOCK(&w_ptr->mtx_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    continue;
		} else {
		    if (do_rderr(iop, w_ptr) < 0) {
			return -1;
		    }
		}
	    }
	} else {
	    for (;;) {
		if ((w_ptr->len = read(iop->io_fd, w_ptr->line, iop->buf_sz)) > 0) {
		    WR_LOCK(&w_ptr->next->rw_lock);
		    RW_UNLOCK(&w_ptr->rw_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    continue;
		} else {
		    if (do_rderr(iop, w_ptr) < 0)
			return -1;
		}
	    }
	}
}

int rbuf_readfrom(struct io_params *iop)
{
        struct rbuf_entry *r_ptr;
	int nleft;
        int r, nw;
	char *lptr;

	r_ptr = set_rbuf_lock(iop);

	if (*iop->type_p != TYPE_2) {
	    for (;;) {
		lptr = r_ptr->line;
		nleft = r_ptr->len;
		while (nleft > 0) {
		    nw = write(iop->io_fd, lptr, r_ptr->len);
		    if (nw == r_ptr->len) {
			nleft -= nw;
			MTX_LOCK(&r_ptr->next->mtx_lock);
			MTX_UNLOCK(&r_ptr->mtx_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			continue;
		    } else if (nw < r_ptr->len && nw > 0) {
			nleft -= nw;
			lptr += nw;
			iop->bytes += nw;
			continue;
		    } else if (nw <= 0) {
			if (do_wrerr(iop, r_ptr) < 0)
			    return -1;
		    }
		}
	    }
	} else { 
	    for (;;) {
		lptr = r_ptr->line;
		nleft = r_ptr->len;
		while (nleft > 0) {
		    nw = write(iop->io_fd, lptr, r_ptr->len);
		    if (nw == r_ptr->len) {
			nleft -= nw;
			RD_LOCK(&r_ptr->next->rw_lock);
			RW_UNLOCK(&r_ptr->rw_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			continue;
		    } else if (nw < r_ptr->len && nw > 0) {
			nleft -= nw;
			lptr += nw;
			iop->bytes += nw;
			continue;
		    } else if (nw <= 0) {
			if (do_wrerr(iop, r_ptr) < 0)
			    return -1;
		    }
		}
	    }
	}
}

int rbuf_t3_tlsreadfrom(struct io_params *iop)
{
        struct rbuf_entry 	*r_ptr;
	struct sock_param	*sop;
	char			*lptr;
        int 			r, nw, nleft;

	sop = iop->sock_data;
	r_ptr = set_rbuf_lock(iop);

	MTX_LOCK(&iop->fd_lock);
	
        for (;;) {
	    lptr = r_ptr->line;
	    nleft = r_ptr->len;
	    while (nleft > 0) {
		nw = tls_write(sop->tls_ctx, lptr, r_ptr->len);
		if (nw == r_ptr->len) {
		    MTX_UNLOCK(&iop->fd_lock);
		    nleft -= nw;
		    MTX_LOCK(&r_ptr->next->mtx_lock);
		    MTX_UNLOCK(&r_ptr->mtx_lock);
		    MTX_LOCK(&iop->fd_lock);
		    CNT_UPDATE(iop, nw);
		    r_ptr = r_ptr->next;
		    continue;
		} else if (nw < r_ptr->len && nw > 0) {
		    nleft -= nw;
		    lptr += nw;
		    iop->bytes += nw;
		    continue;
		} else if (nw <= 0) {
		    MTX_UNLOCK(&iop->fd_lock);
		    if (do_wrerr(iop, r_ptr) < 0) {
			return -1;
		    } else {
			MTX_LOCK(&iop->fd_lock);
			continue;
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

	r_ptr = set_rbuf_lock(iop);
	MTX_LOCK(&iop->fd_lock);
	
        for (;;) {
	    lptr = r_ptr->line;
	    nleft = r_ptr->len;

	    while (nleft > 0) {
		nw = write(*iop->iofd_p, lptr, r_ptr->len);
		if (nw == r_ptr->len) {
		    nleft -= nw;
		    CNT_UPDATE(iop, nw);
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
		} else if (nw <= 0) {
		    MTX_UNLOCK(&iop->fd_lock);
		    if (do_wrerr(iop, r_ptr) < 0) {
			return -1;
		    } else {
			MTX_LOCK(&iop->fd_lock);
			continue;
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

int io_error(struct io_params *iop, int e, int n)
{
	struct sock_param	*sop;

	sop = iop->sock_data;

	if (sop->tls == TRUE) {
	    if (n == TLS_WANT_POLLIN || \
		n == TLS_WANT_POLLOUT) {
		    return 1;
	    }
	} else if (is_netsock(iop) && e == EPIPE) {
	    return -1;
	} else if (e == EPIPE	|| \
	    e == ENETDOWN 	|| \
	    e == EDESTADDRREQ 	|| \
	    e == ENOTCONN) {
		log_ret("io error - remote end closed for %d: %d: %s", \
		    iop->io_fd, e, iop->path);
		return 0;
	} else if (errno == EAGAIN || errno == EINTR) {
	    return 1;
	} else {
	    log_ret("unknown io error %d %s", e, iop->path);
	    return 2;
	}
}

void rbuf_locksync0(struct io_params *iop)
{
	int r;

	MTX_LOCK(&iop->listlock);
	*iop->listready = 1;
	MTX_UNLOCK(&iop->listlock);

	/* SIGNAL WRITE THREAD */
	pthread_cond_signal(&iop->readable);
}

void rbuf_locksync(struct io_params *iop)
{
	int r;

	MTX_LOCK(&iop->listlock);
        while (*iop->listready == 0)
                pthread_cond_wait(&iop->readable, &iop->listlock);
        MTX_UNLOCK(&iop->listlock);
}

int do_rderr(struct io_params *iop, struct rbuf_entry *rb)
{
	int	r;

	if (rb->len == 0 && iop->desc_type == TCP_SOCK) {
	    do_close(iop, rb);
	    return -1;
	} else if (rb->len == 0) {
	    sleep(3);
	    return 0;
	}

	if ((r = io_error(iop, errno, rb->len)) == 0) {
	    sleep(3); /* XXX BETTER TO CALL select() HERE? */
	    return 0;
	} else if (r == 1) {
	    return 0;
	} else {
	    do_close(iop, rb);
	    return -1;
	}
}

int do_wrerr(struct io_params *iop, struct rbuf_entry *rb)
{
	int r;

	if (rb->len == 0) {
	    sleep_unlocked(iop, 3, rb);
	    return 0;
	}

	r = io_error(iop, errno, rb->len);
	if (r == 1) /* recv'd EAGAIN or EINTR */
	   return 0;
	else if (r == 0) {
	    sleep_unlocked(iop, 3, rb);
	    return 0;
	} else
	    /* LOG SOMETHING? */
	    return -1;
}

void sleep_unlocked(struct io_params *iop, int n, struct rbuf_entry *rb)
{
	int r;
	pthread_mutex_t		*mtx;
	pthread_rwlock_t	*rwlk;

	UNLOCK(iop, rb);
	sleep(n);
	LOCK(iop, rb);
}

struct rbuf_entry *set_rbuf_lock(struct io_params *iop)
{
	int	r;

	if (*iop->listready == 0)
	    rbuf_locksync(iop);

	LOCK(iop, iop->r_ptr);
	return iop->r_ptr;
}

void do_close(struct io_params *iop, struct rbuf_entry *rb)
{
	struct sock_param	*sop;
	int			r;

	if (is_sock(iop))
	    sop = iop->sock_data;

	if (use_tls(iop)) {
	    tls_close(sop->tls_ctx);
	    tls_free(sop->tls_ctx);
	}

	if (is_src(iop))
	    iop->w_ptr = rb;
	else
	    iop->r_ptr = rb;

	if (is_dst(iop))
	    UNLOCK(iop, rb);

	report_close_error(iop);
}

void report_close_error(struct io_params *iop)
{
	char	*h;
	struct sock_param	*sop;

	sop = iop->sock_data;

	if (is_netsock(iop)) {
	    if (sop->ip != NULL)
		h = sop->ip;
	    else
		h = sop->hostname;

	    if (sop->conn_type == SRVR) {
		if (use_tls(iop))
		    log_msg("Lost TLS connection to client\n");
	        else
		    log_msg("Lost connection to client\n");
	    } else {
		if (use_tls(iop))
		    log_msg("Lost TLS connection to server %s\n", h);
	        else
		    log_msg("Lost connection to server %s\n", h);
	    }
	} else if (iop->desc_type == UNIX_SOCK) {
	    log_msg("Lost connection to unix sock %s\n", iop->path);
	} else {
	    log_msg("Descriptor closed for %s\n", iop->path);
	}
}

