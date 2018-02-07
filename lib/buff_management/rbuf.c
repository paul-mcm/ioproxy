/* Copyright (c) 2017 Paul McMath <paulm@tetrardus.net>
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

int rbuf_mtx_writeto(struct io_params *iop)
{
	struct rbuf_entry *w_ptr;
	int i, r;

	w_ptr = iop->rbuf_p;

/*	printf("writeto: Buff: %p, %s\n", iop->rbuf_p, iop->path); */

	/* CALL pthread_conf_signal() TO SYNCHRONIZE 
	* LOCKING OF FIRST ENTRY IN LIST.  THIS THREAD 
	* MUST GET THE LOCK FIRST.
	*/

	/* GRAB LOCK */
	if (pthread_mutex_lock(&w_ptr->mtx_lock) != 0)
		log_die("pthread_mutex_lock locking error %d");

	pthread_mutex_lock(&iop->listlock);
	*iop->listready = 1;
	pthread_mutex_unlock(&iop->listlock);

	/* SIGNAL WRITE THREAD */
	pthread_cond_signal(&iop->readable);

	for (;;) {
		if ((i = readv(iop->io_fd, w_ptr->iov, 1)) > 0) {
			printf("w_ptr read %d bytes from %d into ringbuff\n", i, iop->io_fd);
			w_ptr->iov[0].iov_len = i;
	
			if (pthread_mutex_lock(&w_ptr->next->mtx_lock) < 0)
				log_die("pthread_mutex_lock locking error: %d");
 
			if (pthread_mutex_unlock(&w_ptr->mtx_lock) < 0)
                                printf("pthread_mutex_unlock unlocking error");

			w_ptr = w_ptr->next;
		} else if (i == 0) {
			/* readv returned EOF - not an error */
			sleep(3);
			continue;
		} else {
			if (errno == EPIPE || errno == ENETDOWN || errno == EDESTADDRREQ || EBADF)
				log_ret("readv error - read end closed");

			if (pthread_mutex_unlock(&w_ptr->mtx_lock) < 0)
				printf("pthread_mutex_unlock unlocking error");

			return -1;
		}
	}
}

int rbuf_mtx_readfrom(struct io_params *iop)
{
        struct rbuf_entry *r_ptr;
        int r;

	r_ptr = iop->rbuf_p;

        pthread_mutex_lock(&iop->listlock);

        while (*iop->listready == 0)
                pthread_cond_wait(&iop->readable, &iop->listlock);
        pthread_mutex_unlock(&iop->listlock);

	if (pthread_mutex_lock(&r_ptr->mtx_lock) != 0)
		printf("W.1.1: Failed to get lock for %d\n", r_ptr->id);

        for (;;) {
	    printf("r_ptr id: %d\n", r_ptr->id);
	    if ( (r = writev(iop->io_fd, r_ptr->iov, 1)) < 0) {
		if (errno == EPIPE || errno == ENETDOWN || errno == EDESTADDRREQ || errno == EBADF || errno == ENOTCONN) {
		    log_ret("writev error - read end closed for %d", iop->io_fd);				
		    pthread_mutex_unlock(&r_ptr->mtx_lock);
		    sleep(5);
		    if (pthread_mutex_lock(&r_ptr->mtx_lock) != 0)
			printf("W.1.1: Failed to get lock for %d\n", r_ptr->id);
		    continue;
		} else {
		    log_ret("unknown writev error", errno);
		    pthread_mutex_unlock(&r_ptr->mtx_lock);
		    return -1;
		}
	    } else if (r == 0) {
		printf("writev(2) returned 0\n");
		sleep(1);
		continue;
	    } else if (r < r_ptr->cnt) {
		r_ptr->cnt -= r;
		continue;
	    } else {
		printf("\nWee: WROTE %d bytes from ringbuff to %d\n", iop->io_fd);

		if (pthread_mutex_lock(&r_ptr->next->mtx_lock) != 0)
		    printf("W.1.1: Failed to get lock for %d\n", r_ptr->id);

		if (pthread_mutex_unlock(&r_ptr->mtx_lock) < 0)
		    printf("W.3.1: failed to unlock %d %s\n",  r_ptr->id);

		r_ptr = r_ptr->next;
	    }
        }       
}

int rbuf_t3_readfrom(struct io_params *iop)
{
        struct rbuf_entry *r_ptr;
        int r;

	r_ptr = iop->rbuf_p;

/*	printf("readfrom: Buff: %p, %s\n", iop->rbuf_p, iop->path); */

        pthread_mutex_lock(&iop->listlock);

        while (*iop->listready == 0)
                pthread_cond_wait(&iop->readable, &iop->listlock);
        pthread_mutex_unlock(&iop->listlock);

	if (pthread_mutex_lock(&r_ptr->mtx_lock) != 0)
		printf("W.1.1: Failed to get lock for %d\n", r_ptr->id);

	if (pthread_mutex_lock(iop->fd_lock) != 0)
		printf("Locking error in rbuf_t3\n");

        for (;;) {
	    if ((r = writev(*iop->iofd_p, r_ptr->iov, 1)) < 0) {
		log_ret("T:writev error:  %d", errno);
		if (errno == EPIPE || errno == ENETDOWN || errno == EDESTADDRREQ || EBADF) {
		    log_ret("writev() error - read end closed", errno);
		    *iop->iofd_p = -1;
		    pthread_mutex_unlock(iop->fd_lock);
		    pthread_mutex_unlock(&r_ptr->mtx_lock);
		    return -1;
		} else {	/* HOW TO HANDLE THESE ? */
		    pthread_mutex_unlock(iop->fd_lock);
		    pthread_mutex_unlock(&r_ptr->mtx_lock);
		    return -1;
		}
	    } else if (r == 0) {
		printf("writev(2) returned 0\n");
		pthread_mutex_unlock(iop->fd_lock);
		sleep(1);
		if (pthread_mutex_lock(iop->fd_lock) != 0)
			printf("Locking error in rbuf_t3\n");
		continue;
	    } else if (r < r_ptr->cnt) {
		r_ptr->cnt -= r;
		continue;
	    } else {
		log_msg("T3 RBUFF->%d: %d bytes\n", *iop->iofd_p, r);

		if (pthread_mutex_unlock(iop->fd_lock) < 0)
		    printf("W.3.1: failed to unlock %d\n", iop->fd_lock);

		if (pthread_mutex_lock(&r_ptr->next->mtx_lock) != 0)
		    printf("W.1.1: Failed to get lock for %d\n", r_ptr->id);

		if (pthread_mutex_unlock(&r_ptr->mtx_lock) < 0)
		    printf("W.3.1: failed to unlock %d %s\n",  r_ptr->id);

		if (pthread_mutex_lock(iop->fd_lock) != 0)
			printf("Locking error in rbuf_t3\n");

		r_ptr = r_ptr->next;
	    }
        }      
}

int rbuf_rwlock_writeto(struct io_params *iop)
{
	struct rbuf_entry *w_ptr;
	int i, r;

	w_ptr = iop->rbuf_p;
/*	printf("R.1: Grabbing lock for %d\n", w_ptr->id); */

	/* CALL pthread_conf_signal() TO SYNCHRONIZE 
	* LOCKING OF FIRST ENTRY IN LIST.  THIS THREAD 
	* MUST GET THE LOCK FIRST.
	*/

	/* GRAB LOCK */
	if (pthread_rwlock_wrlock(&w_ptr->rw_lock) != 0)
		log_die("pthread_mutex_lock locking error %d");

	pthread_mutex_lock(&iop->listlock);
	*iop->listready = 1;
	pthread_mutex_unlock(&iop->listlock);

	/* SIGNAL WRITE THREAD */
	pthread_cond_signal(&iop->readable);

	for (;;) {
/*		printf("w_ptr id: %d\n", w_ptr->id); */
		if ((i = readv(iop->io_fd, w_ptr->iov, 1)) > 0) {
			printf("w_ptr read %d bytes from %d into ringbuff\n", i, iop->io_fd);
			w_ptr->iov[0].iov_len = i;
	
			if (pthread_rwlock_wrlock(&w_ptr->next->rw_lock) < 0)
				log_die("pthread_mutex_lock locking error: %d");
 
			if (pthread_rwlock_unlock(&w_ptr->rw_lock) < 0)
                                printf("pthread_mutex_unlock unlocking error");

			w_ptr = w_ptr->next;
		} else if (i == 0) {
			/* readv returned EOF - not an error */
			sleep(3);
			continue;
		} else {
			if (errno == EPIPE || errno == ENETDOWN || errno == EDESTADDRREQ || EBADF)
				log_ret("readv error - read end closed");

			if (pthread_rwlock_unlock(&w_ptr->rw_lock) < 0)
				printf("pthread_mutex_unlock unlocking error");

			return -1;
		}
	}
}

int rbuf_rwlock_readfrom(struct io_params *iop)
{
        struct rbuf_entry *r_ptr;
        int r;

	r_ptr = iop->rbuf_p;

        pthread_mutex_lock(&iop->listlock);

        while (*iop->listready == 0)
                pthread_cond_wait(&iop->readable, &iop->listlock);
        pthread_mutex_unlock(&iop->listlock);

	printf("Proceeding...%d\n", iop->io_fd);

        for (;;) {
/*		printf("r_ptr id: %d\n", r_ptr->id); */

	        if (pthread_rwlock_rdlock(&r_ptr->rw_lock) != 0)
			printf("W.1.1: Failed to get lock for %d\n", r_ptr->id);

                if ( (r = writev(iop->io_fd, r_ptr->iov, 1)) < 0) {
                        log_msg("writev error:  %d", errno);
			if (errno == EPIPE || errno == ENETDOWN || errno == EDESTADDRREQ || EBADF)
				log_ret("readv error - read end closed");
                        pthread_rwlock_unlock(&r_ptr->rw_lock);
			return -1;
                } else if (r == 0) {
			printf("writev(2) returned 0\n");
			pthread_rwlock_unlock(&r_ptr->rw_lock);
			sleep(1);
			continue;
		} else if (r < r_ptr->cnt) {
			r_ptr->cnt -= r;
			continue;
		} else {
                        printf("\nWhhhh: WROTE %d bytes from ringbuff to %d\n", r, iop->io_fd);
                }

                if (pthread_rwlock_unlock(&r_ptr->rw_lock) < 0)
                        printf("W.3.1: failed to unlock %d %s\n",  r_ptr->id);

                r_ptr = r_ptr->next;
        }       
}

struct rbuf_entry *new_rbuf(struct io_cfg *iocfg)
{
	int i;
	struct rbuf_entry *e, *prev_ptr, *head;
	pthread_mutexattr_t mtx_attrs;
	pthread_rwlockattr_t rwlock_attrs;

	if (iocfg->io_type == TYPE_2)
	    pthread_rwlockattr_init(&rwlock_attrs);
	else
	    pthread_mutexattr_init(&mtx_attrs);

	prev_ptr = NULL;

	/* INITIALIZE LIST OF BUFFERS */
	for (i = 64; i >= 1; i--) {
	    if ((e = malloc(sizeof(struct rbuf_entry))) == NULL)
		log_syserr("rbuf malloc error");

	    e->id = i;
	    e->iov[0].iov_len = BUFF_SIZE;
	    e->iov[0].iov_base = e->line;

	    if (iocfg->io_type == TYPE_2)
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
