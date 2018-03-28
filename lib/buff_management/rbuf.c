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
extern volatile sig_atomic_t SIGHUP_STAT;

#define IS_TYPE2(i)				\
if (i->cfgtype_p == TYPE_2)			\
    return TRUE;				\
else						\
    return FALSE;				\
}

#define CNT_UPDATE(a, b)			\
a->bytes += b;					\
a->io_cnt++;

#define SHORT_WRTCNT(a, b, c, d)		\
b -= a;						\
c += a;						\
d += a;

int rbuf_ssh_writeto(struct io_params *iop)
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

	r = ssh_channel_request_exec(sop->ssh_chan, sop->ssh_cmd);
	if (r != SSH_OK) {
	    printf("ssh_channel_request_exec() not ok!\n");
            ssh_channel_close(sop->ssh_chan);
            ssh_channel_free(sop->ssh_chan);
            return -1;
        }

	if (*iop->cfgtype_p != TYPE_2) {
	    for (;;) {
		if ((w_ptr->len = ssh_channel_read(sop->ssh_chan, w_ptr->line, iop->buf_sz, 0)) > 0) {
		    MTX_LOCK(&w_ptr->next->mtx_lock);
		    MTX_UNLOCK(&w_ptr->mtx_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    continue;
		} else {
		    sleep(2);
		    continue;
		}
	    }
	} else {
	    for (;;) {
		if ((w_ptr->len = ssh_channel_read(sop->ssh_chan, w_ptr->line, iop->buf_sz, 0)) > 0) {
		    WR_LOCK(&w_ptr->next->rw_lock);
		    RW_UNLOCK(&w_ptr->rw_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    continue;
		} else {
		    return 0;
		}
	    }
	}
}

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

	if (*iop->cfgtype_p != TYPE_2) {
	    for (;;) {
		if ((w_ptr->len = tls_read(sop->tls_ctx, w_ptr->line, iop->buf_sz)) > 0) {
		    MTX_LOCK(&w_ptr->next->mtx_lock);
		    MTX_UNLOCK(&w_ptr->mtx_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    continue;
		} else if ((r = do_rderr(iop, w_ptr)) < 0) {
		    return r;
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
		} else if ((r = do_rderr(iop, w_ptr)) < 0) {
		    return r;
		}
	    }
	}
}

int rbuf_tls_readfrom(struct io_params *iop)
{
        struct rbuf_entry	*r_ptr;
	struct sock_param	*sop;
	ssize_t			nw;
	int 			nleft, r;
	char			*lptr;

	sop = iop->sock_data;
	r_ptr = set_rbuf_lock(iop);

	if (*iop->cfgtype_p != TYPE_2) {
	    for (;;) {
		lptr = r_ptr->line;
		nleft = r_ptr->len;
		while (nleft > 0) {
		    nw = tls_write(sop->tls_ctx, lptr, r_ptr->len);
		    if (nw == r_ptr->len) {
			MTX_LOCK(&r_ptr->next->mtx_lock);
			MTX_UNLOCK(&r_ptr->mtx_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			break;
		    } else if (nw < r_ptr->len && nw > 0) {
			SHORT_WRTCNT(nw, nleft, lptr, iop->bytes);
			continue;
		    } else if (nw <= 0 && (r = do_wrerr(iop, r_ptr)) < 0) {
			    return r;
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
			RD_LOCK(&r_ptr->next->rw_lock);
			RW_UNLOCK(&r_ptr->rw_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			break;
		    } else if (nw < r_ptr->len && nw > 0) {
			SHORT_WRTCNT(nw, nleft, lptr, iop->bytes);
			continue;
		    } else if (nw <= 0 && (r = do_wrerr(iop, r_ptr)) < 0) {
			    return r;
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

	if (*iop->cfgtype_p != TYPE_2) {
	    for (;;) {
		if ((w_ptr->len = read(iop->io_fd, w_ptr->line, iop->buf_sz)) > 0) {
		    MTX_LOCK(&w_ptr->next->mtx_lock);
		    MTX_UNLOCK(&w_ptr->mtx_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    iop->w_ptr = w_ptr;
		    continue;
		} else if ((r = do_rderr(iop, w_ptr)) < 0) {
			return r;
		}
	    }
	} else {
	    for (;;) {
		if ((w_ptr->len = read(iop->io_fd, w_ptr->line, iop->buf_sz)) > 0) {
		    WR_LOCK(&w_ptr->next->rw_lock);
		    RW_UNLOCK(&w_ptr->rw_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    iop->w_ptr = w_ptr;
		    continue;
		} else if ((r = do_rderr(iop, w_ptr)) < 0) {
			return r;
		}
	    }
	}
}

int rbuf_readfrom(struct io_params *iop)
{
        struct rbuf_entry 	*r_ptr;
	int 			nleft, r;
	ssize_t			nw;
	char			*lptr;

	r_ptr = iop->r_ptr;

	nw = 0;
	r_ptr = set_rbuf_lock(iop);

	if (*iop->cfgtype_p != TYPE_2) {
	    for (;;) {
		lptr = r_ptr->line;
		nleft = r_ptr->len;
		while (nleft > 0) {
		    nw = write(iop->io_fd, lptr, r_ptr->len);
		    if (nw == r_ptr->len) {
			MTX_LOCK(&r_ptr->next->mtx_lock);
			MTX_UNLOCK(&r_ptr->mtx_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			iop->r_ptr = iop->r_ptr;
		    } else if (nw < r_ptr->len && nw > 0) {
			SHORT_WRTCNT(nw, nleft, lptr, iop->bytes);
			continue;
		    } else if (nw <= 0 && (r = do_wrerr(iop, r_ptr)) < 0) {
			    return r;
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
			RD_LOCK(&r_ptr->next->rw_lock);
			RW_UNLOCK(&r_ptr->rw_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			iop->r_ptr = r_ptr;
			break;
		    } else if (nw < r_ptr->len && nw > 0) {
			SHORT_WRTCNT(nw, nleft, lptr, iop->bytes);
			continue;
		    } else if (nw <= 0 && (r = do_wrerr(iop, r_ptr)) < 0) {
			    return r;
		    }
		}
	    }
	}
}

int rbuf_dgram_writeto(struct io_params *iop)
{
	struct sock_param	*sop;
	struct rbuf_entry	*w_ptr;
	socklen_t		len;
	int 			i, r;

	sop = iop->sock_data;
	w_ptr = iop->w_ptr;

	len = sizeof(*sop->host_addr);

	if (*iop->listready == 0) {
	    /* THIS THREAD MUST GET THE LOCK FIRST */
	    LOCK(iop, w_ptr);
	    rbuf_locksync0(iop);
	}

	if (*iop->cfgtype_p != TYPE_2) {
	    for (;;) {
		if ((w_ptr->len = recvfrom(sop->listenfd, w_ptr->line, iop->buf_sz, 0, sop->host_addr, &len)) > 0) {
		    MTX_LOCK(&w_ptr->next->mtx_lock);
		    MTX_UNLOCK(&w_ptr->mtx_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    continue;
		} else if ((r = do_rderr(iop, w_ptr)) < 0) {
			return r;
		}
	    }
	} else {
	    for (;;) {
		if ((w_ptr->len = recvfrom(sop->listenfd, w_ptr->line, iop->buf_sz, 0, sop->host_addr, &len)) > 0) {
		    WR_LOCK(&w_ptr->next->rw_lock);
		    RW_UNLOCK(&w_ptr->rw_lock);
		    CNT_UPDATE(iop, w_ptr->len);
		    w_ptr = w_ptr->next;
		    continue;
		} else if ((r = do_rderr(iop, w_ptr)) < 0) {
			return r;
		}
	    }
	}
}

int rbuf_dgram_readfrom(struct io_params *iop)
{
        struct rbuf_entry 	*r_ptr;
	struct sock_param	*sop;
	socklen_t		len;
	int 			nleft, r;
	ssize_t			nw;
	char			*lptr;

	sop = iop->sock_data;
	r_ptr = set_rbuf_lock(iop);
	len = sizeof(*sop->host_addr);

	if (*iop->cfgtype_p != TYPE_2) {
	    for (;;) {
		lptr = r_ptr->line;
		nleft = r_ptr->len;
		while (nleft > 0) {
		    nw = sendto(iop->io_fd, r_ptr->line, r_ptr->len, 0, sop->host_addr, len);
		    if (nw == r_ptr->len) {
			MTX_LOCK(&r_ptr->next->mtx_lock);
			MTX_UNLOCK(&r_ptr->mtx_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			break;
		    } else if (nw < r_ptr->len && nw > 0) {
			SHORT_WRTCNT(nw, nleft, lptr, iop->bytes);
			continue;
		    } else if (nw <= 0 && (r = do_wrerr(iop, r_ptr)) < 0) {
			    return r;
		    }
		}
	    }
	} else {
	    for (;;) {
		lptr = r_ptr->line;
		nleft = r_ptr->len;
		while (nleft > 0) {
		    nw = sendto(iop->io_fd, r_ptr->line, r_ptr->len, 0, sop->host_addr, len);
		    if (nw == r_ptr->len) {
			RD_LOCK(&r_ptr->next->rw_lock);
			RW_UNLOCK(&r_ptr->rw_lock);
			CNT_UPDATE(iop, nw);
			r_ptr = r_ptr->next;
			break;
		    } else if (nw < r_ptr->len && nw > 0) {
			SHORT_WRTCNT(nw, nleft, lptr, iop->bytes);
			continue;
		    } else if (nw <= 0 && (r = do_wrerr(iop, r_ptr)) < 0) {
			    return r;
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
	ssize_t			nw;
        int 			r, nleft;

	sop = iop->sock_data;
	r_ptr = set_rbuf_lock(iop);

	FDMTX_LOCK(iop->fdlock_p);
	
        for (;;) {
	    lptr = r_ptr->line;
	    nleft = r_ptr->len;
	    while (nleft > 0) {
		nw = tls_write(sop->tls_ctx, lptr, r_ptr->len);
		if (nw == r_ptr->len) {
		    FDMTX_UNLOCK(iop->fdlock_p);
		    MTX_LOCK(&r_ptr->next->mtx_lock);
		    MTX_UNLOCK(&r_ptr->mtx_lock);
		    FDMTX_LOCK(iop->fdlock_p);
		    CNT_UPDATE(iop, nw);
		    r_ptr = r_ptr->next;
		    break;
		} else if (nw < r_ptr->len && nw > 0) {
		    SHORT_WRTCNT(nw, nleft, lptr, iop->bytes);
		    continue;
		} else if (nw <= 0) {
		    FDMTX_UNLOCK(iop->fdlock_p);
		    if ((r = do_wrerr(iop, r_ptr)) < 0) {
			return r;
		    } else {
			FDMTX_LOCK(iop->fdlock_p);
			continue;
		    }
		}
	    }
	}      
}

int rbuf_t3_readfrom(struct io_params *iop)
{
        struct rbuf_entry	*r_ptr;
	ssize_t			nw;
        int 			r, nleft;
	char			*lptr;

	r_ptr = set_rbuf_lock(iop);
	FDMTX_LOCK(iop->fdlock_p);

	for (;;) {
	    lptr = r_ptr->line;
	    nleft = r_ptr->len;

	    while (nleft > 0) {
		nw = write(*iop->iofd_p, lptr, r_ptr->len);
		if (nw == r_ptr->len) {
		    CNT_UPDATE(iop, nw);
		    FDMTX_UNLOCK(iop->fdlock_p);
		    MTX_LOCK(&r_ptr->next->mtx_lock);
		    MTX_UNLOCK(&r_ptr->mtx_lock);
		    FDMTX_LOCK(iop->fdlock_p);
		    r_ptr = r_ptr->next;
		    break;
		} else if (nw < r_ptr->len && nw > 0) {
		    SHORT_WRTCNT(nw, nleft, lptr, iop->bytes);
		    continue;
		} else if (nw <= 0) {
		    FDMTX_UNLOCK(iop->fdlock_p);
		    if ((r = do_wrerr(iop, r_ptr)) < 0) {
			return r;
		    } else {
			MTX_LOCK(iop->fdlock_p);
			continue;
		    }
		}
	    }
	}      
}

struct rbuf_entry *new_rbuf(int t, int sz)
{
	int i, r;
	struct rbuf_entry *e, *prev_ptr, *head;
	pthread_mutexattr_t mtx_attrs;
	pthread_rwlockattr_t rwlock_attrs;

	if (t == TYPE_2) {
	    pthread_rwlockattr_init(&rwlock_attrs);
	} else {
	    pthread_mutexattr_init(&mtx_attrs);
	    if ((r = pthread_mutexattr_settype(&mtx_attrs, PTHREAD_MUTEX_ERRORCHECK)) != 0)
		log_syserr("ATTR SETTYPE FAILED: %d\n", r);
	}

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

void free_rbuf(struct io_params *iop)
{
	int i;
	struct rbuf_entry *rb, *rb_nxt;
	rb = iop->rbuf_p;

	/* FREE LIST OF BUFFERS */
	for (i = 1; i < 65; i++) {
	    rb_nxt = rb->next;
	    if (*iop->cfgtype_p != TYPE_2) {
		pthread_mutex_destroy(&rb->mtx_lock);
	    } else {
		pthread_rwlock_destroy(&rb->rw_lock);
	    }

	    free(rb->line);

	    free(rb);
	    rb = rb_nxt;
	}
}

int io_error(struct io_params *iop, int e, int n)
{
	/* RETURN VALS:
	 *  0  no eror - call epoll/kqueue
	 * -1 transient error; call read/write again
	 * -2 permanent error; close descriptor; exit thread
         */

	struct sock_param	*sop;
	sop = iop->sock_data;

	if (n == 0) {/* zero bytes read/written */
	    return 0;
	}

	if (is_netsock(iop) && sop->tls == TRUE) {
	    if (n == TLS_WANT_POLLIN || \
		n == TLS_WANT_POLLOUT) {
		    return -1;
	    }
	} else if (is_netsock(iop) && e == EPIPE) {
	    return -1;
	} else if ( e == ENETDOWN 	|| \
		    e == EDESTADDRREQ 	|| \
		    e == ENOTCONN) {
	    log_ret("io error - remote end closed for %d: %d: %s", \
		iop->io_fd, e, iop->path);
	    return 0;
	} else if (errno == EAGAIN || errno == EINTR) {
	    return -1;
	} else if (errno == EPIPE || iop->io_type == FIFO) {
	    return -1;
	} else if (errno == EPIPE || iop->io_type == PIPE) {
	    return -2;
	} else {
	    log_ret("unknown io error %d %s", e, iop->path);
	    return -2;
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

struct rbuf_entry *set_rbuf_lock(struct io_params *iop)
{
	int	r;

	MTX_LOCK(&iop->listlock);
        while (*iop->listready == 0)
                pthread_cond_wait(&iop->readable, &iop->listlock);
        MTX_UNLOCK(&iop->listlock);
	LOCK(iop, iop->r_ptr);

	return iop->r_ptr;
}

int do_rderr(struct io_params *iop, struct rbuf_entry *rb)
{
	int	r, n;

	MTX_LOCK(&sighupstat_lock);
	n = SIGHUP_STAT;
	MTX_UNLOCK(&sighupstat_lock);
	if (n) { 	/* WE'RE SIGHUP'D */
	    return -2;
	}

	if (rb->len == 0 && iop->io_type == TCP_SOCK) { /* SOCKET CLOSED */
	    do_close(iop, rb);
	    return -1;
	} else if (rb->len == 0 && iop->io_type == PIPE) { /* NO WRITER? */
	    do_close(iop, rb);
	    return -2;
	}

	r = io_error(iop, errno, rb->len);

	if (r == 0) {
	/* POLL WILL JUST RETURN IMMEDIATELY ON EOF */
	    if (iop->io_type == REG_FILE) {
		sleep(3);
		return 0;
	    }

	    if ((r = do_poll(iop)) == -1) {
		do_close(iop, rb);
		return -1;
	    } else {
		return 0;
	    }
	} else if (r == -1) {
	    return 0;
	} else if (r == -2) {
	    do_close(iop, rb);
	    return r;
	}
}

int do_wrerr(struct io_params *iop, struct rbuf_entry *rb)
{
	int r, n;

	MTX_LOCK(&sighupstat_lock);
	n = SIGHUP_STAT;
	MTX_UNLOCK(&sighupstat_lock);

	if (n) /* WE'RE SIGHUP'D */
	    return -2;

	if (rb->len == 0) {
	    sleep_unlocked(iop, 3, rb);
	    return 0;
	}

	r = io_error(iop, errno, rb->len);
	if (r == 0) /* recv'd EAGAIN or EINTR */
	   return 0;
	else if (r == 0) {
	    sleep_unlocked(iop, 3, rb);
	    return 0;
	} else
	    /* LOG SOMETHING? */
	    do_close(iop, rb);
	    return r;
}

int do_poll(struct io_params *iop)
{
	struct pollfd   pfd[1];

	pfd[0].fd = iop->io_fd;

	if (is_src(iop))
	    pfd[0].events = POLLRDNORM;
	else
	    pfd[0].events = POLLWRNORM;

#ifdef BSD
	if (poll(pfd, 1, INFTIM) == -1) {
#else
       if (poll(pfd, 1, -1) == -1) {
#endif
	    log_syserr("poll() error\n");
	    exit(-1);
	}

	if ((pfd[0].revents & (POLLERR|POLLNVAL))) {
	    log_msg("revents error; bad descriptor for %s?\n", iop->path);
	    return -1;
	} else if (pfd[0].revents & (POLLHUP)) { /* DISCONNECTED */
	    printf("poll() returned POLLHUP\n");
		return -1;
	} else {
	    return 0;
	}
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

	if (is_dst(iop) || (is_src(iop) && iop->io_type == PIPE))
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
	} else if (iop->io_type == UNIX_SOCK) {
	    log_msg("Lost connection to unix sock %s\n", iop->path);
	} else if (iop->io_type == PIPE) {
	    log_msg("Process close: %s\n", iop->pipe_cmd);
	} else {
	    log_msg("Descriptor closed for %s\n", iop->path);
	}
}

void close_desc(struct io_params *iop)
{
	struct sock_param	*sop;
	int			d;
	sop = iop->sock_data;

	if (is_dst(iop) && *iop->cfgtype_p == TYPE_3)
	    d = *iop->iofd_p;
	else
	    d = iop->io_fd;

	if (iop->io_type != PIPE || iop->io_type != SSH) {
	    close(d);
	} else if (iop->io_type == SSH) {
	    ssh_disconnect(sop->ssh_s);
	    ssh_free(sop->ssh_s);
	} else if (iop->io_type == PIPE) {
	    if (kill(iop->pipe_cmd_pid, SIGTERM) != 0)
		log_syserr("kill() failed for %s\n", iop->pipe_cmd);
	    close(d);
	}
}

void release_locks(void *arg)
{
	struct iop1_params	*iop1;
	struct io_params	*iop;
	struct rbuf_entry	*rb;
	int			r;

	iop = (struct io_params *)arg;

	if (is_src(iop))
	    rb = iop->w_ptr;
	else
	    rb = iop->r_ptr;

	if (is_src(iop)) {
	    if (rb->len <= 0)
		rb->len = 1;
	    if (*iop->listready == 0) {
		MTX_LOCK(&iop->listlock);
		if (*iop->listready == 0) {
		    *iop->listready = 1;
		    MTX_UNLOCK(&iop->listlock);

		    /* SIGNAL WRITE THREAD */
		    pthread_cond_signal(&iop->readable);
		}
	    }

	    if (pthread_mutex_unlock(&rb->mtx_lock) != 0) {
		log_die("mutex unlock error\n");
	    }
	} else {
	    if (*iop->cfgtype_p == TYPE_1) {
		r = pthread_mutex_lock(&rb->mtx_lock);
		if (r == 0 || r == EDEADLK) {
		    pthread_mutex_unlock(&rb->mtx_lock);
		}
	    } else if (*iop->cfgtype_p == TYPE_3) {
		r = pthread_mutex_lock(iop->fdlock_p);
		if (r == 0 || r == EDEADLK) {
		    pthread_mutex_unlock(iop->fdlock_p);
		}

		r = pthread_mutex_lock(&rb->mtx_lock);
		if (r == 0 || r == EDEADLK) {
		    pthread_mutex_unlock(&rb->mtx_lock);
		}
	    } else { /* TYPE_2 */
		r = pthread_rwlock_tryrdlock(&rb->rw_lock);
		if (r == EDEADLK || r == 0) {
		    pthread_rwlock_unlock(&rb->rw_lock);
		}
	    }
	}
}
