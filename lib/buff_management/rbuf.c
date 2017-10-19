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

int rbuf_writeto(struct io_params *iop)
{
	struct rbuf_entry *w_ptr;
	int i, r;

	w_ptr = iop->rbuf_p;
/*	pthread_cleanup_push(read_cleanup, NULL); */
/*	printf("R.1: Grabbing lock for %d\n", w_ptr->id); */

	/* CALL pthread_conf_signal() TO SYNCHRONIZE 
	* LOCKING OF FIRST ENTRY IN LIST.  THIS THREAD 
	* MUST GET THE LOCK FIRST.
	*/

	/* GRAB LOCK */
	if (pthread_mutex_lock(&w_ptr->lock) != 0)
		log_die("pthread_mutex_lock locking error %d");

	pthread_mutex_lock(&iop->listlock);
	*iop->listready = 1;
	pthread_mutex_unlock(&iop->listlock);

	/* SIGNAL WRITE THREAD */
	pthread_cond_signal(&iop->readable);

	for (;;) {
		printf("w_ptr id: %d\n", w_ptr->id);
		if ((i = readv(iop->io_fd, w_ptr->iov, 1)) > 0) {
			printf("w_ptr read %d bytes from %d into ringbuff\n", i, iop->io_fd);
			w_ptr->iov[0].iov_len = i;
	
			if (pthread_mutex_lock(&w_ptr->next->lock) < 0)
				log_die("pthread_mutex_lock locking error: %d");
 
			if (pthread_mutex_unlock(&w_ptr->lock) < 0)
                                printf("pthread_mutex_unlock unlocking error");

			w_ptr = w_ptr->next;
		} else if (i == 0) {
			sleep(2);
			continue;
		} else {
			if (errno == EPIPE || errno == ENETDOWN || errno == EDESTADDRREQ)
			log_msg("readv error - read end closed\n");
			return -1;
		}
		sleep(2);
	}
/*	pthread_cleanup_pop(0); */
}

int rbuf_readfrom(struct io_params *iop)
{
        struct rbuf_entry *r_ptr;
        int r;

	r_ptr = iop->rbuf_p;

        pthread_mutex_lock(&iop->listlock);

        while (*iop->listready == 0)
                pthread_cond_wait(&iop->readable, &iop->listlock);
        pthread_mutex_unlock(&iop->listlock);

        if (pthread_mutex_lock(&r_ptr->lock) != 0 )
                printf("W.1.1: Failed to get lock for %d\n", r_ptr->id);

        for (;;) {
		printf("r_ptr id: %d\n", r_ptr->id);
                if ( (r = writev(iop->io_fd, r_ptr->iov, 1)) < 0) {
                        log_ret("writev error:  %d", errno);
                        pthread_mutex_unlock(&r_ptr->lock);
                        pthread_exit(NULL);
                } else if (r == 0) {
			printf("writev(2) returned 0\n");
			sleep(2);
			continue;
		} else {
                        printf("\nW: WROTE %d bytes from ringbuff to %d\n", iop->io_fd);
                }

                r_ptr->iov[0].iov_len = BUFF_SIZE;

                if (pthread_mutex_lock(&r_ptr->next->lock) != 0 )
                        log_syserr("pthread_mutex_lock error: %d %s\n", errno, strerror(errno));

                if (pthread_mutex_unlock(&r_ptr->lock) < 0)
                        printf("W.3.1: failed to unlock %d %s\n",  r_ptr->id);
                r_ptr = r_ptr->next;
        }       
}

struct rbuf_entry *new_rbuf(void)
{
	int i;
	struct rbuf_entry *e, *prev_ptr, *head;
	pthread_mutexattr_t attrs;

	prev_ptr = NULL;
        pthread_mutexattr_init(&attrs);

	/* INITIALIZE LIST OF BUFFERS */
	for (i = 64; i >= 1; i--) {
	    if ((e = malloc(sizeof(struct rbuf_entry))) == NULL)
		log_syserr("rbuf malloc error");

	    e->id = i;
	    e->iov[0].iov_len = BUFF_SIZE;
	    e->iov[0].iov_base = e->line;
 	    pthread_mutex_init(&e->lock, &attrs);

	    if ( prev_ptr != NULL ) {
		prev_ptr->next = e;
	    } else {
		head = e;
	    }
	    prev_ptr = e;
	}
	e->next = head;

	rb = head;
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
