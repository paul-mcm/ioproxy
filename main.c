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

#include "ioproxy.h"

int debug = 1;

void *iocfg_manager(void *);
void *io_thread(void *);

volatile sig_atomic_t SIGHUP_STAT;
volatile sig_atomic_t SIGTERM_STAT;

int main(int argc, char *argv[])
{
	int		r;
	pthread_t	tid, sigterm_tid, sighup_tid;
	struct io_cfg	*iocfg;
	sigset_t	sig_set;
	int		sig;
	pthread_attr_t  dflt_attrs;

	sigemptyset(&sig_set);
        sigaddset(&sig_set, SIGTERM);
        sigaddset(&sig_set, SIGHUP);	
	sigprocmask(SIG_BLOCK, &sig_set, NULL);

	SIGTERM_STAT = FALSE;
	SIGHUP_STAT  = FALSE;

	LIST_INIT(&all_cfg);
	read_config(&all_cfg);

	/* ITERATE OVER EACH CFG IN all_cfg AND 
	 * START CONTROL THREAD.
	 */

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
		iop_setup(iocfg);

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
		show_config(iocfg);

        if ((r = pthread_attr_init(&dflt_attrs)) != 0)
            log_die("Error initing thread attrs: %d\n", r);

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
		if (pthread_create(&tid, &dflt_attrs, iocfg_manager, (void *)iocfg) != 0)
                	log_ret("error pthread_create: ");

	if (pthread_create(&sigterm_tid, &dflt_attrs, sigterm_thrd, NULL) != 0)
		log_die("error pthread_create()");

	/* BLOCK */
	pthread_join(sigterm_tid, NULL);
	terminate();
	exit(0);
}

void iop_setup(struct io_cfg *iocfg)
{
	struct io_params	*iop;
	struct iop0_params	*iop0, *newiop0;
	struct iop1_params	*iop1, *newiop1;
	pthread_mutexattr_t	mxattrs;
	int			r;

	if (iocfg->io_type == TYPE_1 || iocfg->io_type == TYPE_2) {

	    /* AT THIS STAGE, iop0_paths HAS ONLY 1 MEMBER */
	    iop0 = LIST_FIRST(&iocfg->iop0_paths);
	    iop = iop0->iop;

	    pthread_cond_init(&iop->readable, NULL);
	    iop0->iop->listlock = PTHREAD_MUTEX_INITIALIZER;

	    iop0->iop->rbuf_p = new_rbuf(iocfg->io_type, iop->buf_sz);
	    iop0->iop->listready = malloc(sizeof(int));
	    *iop0->iop->listready = 0;

	    LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
		iop1->iop->rbuf_p	= iop0->iop->rbuf_p;
		iop1->iop->buf_sz	= iop0->iop->buf_sz;
		iop1->iop->listready	= iop0->iop->listready;
		iop1->iop->listlock	= iop0->iop->listlock;
		iop1->iop->readable	= iop0->iop->readable;
		iop1->iop->io_fd	= iop0->iop->io_fd;
		iop1->iop->io_thread	= io_thread;
		iop1->iop->io_drn 	= DST;
	    }

	    if (iocfg->io_type == TYPE_1) {
		iop0->iop->rbuf_writeto = rbuf_mtx_writeto;
		LIST_FOREACH(iop1, &iop0->io_paths, io_paths)
			iop1->iop->rbuf_readfrom = rbuf_mtx_readfrom;
	    } else if (iocfg->io_type == TYPE_2) {
		iop0->iop->rbuf_writeto = rbuf_rwlock_writeto;
		LIST_FOREACH(iop1, &iop0->io_paths, io_paths)
			iop1->iop->rbuf_readfrom = rbuf_rwlock_readfrom;
	    }

	} else if (iocfg->io_type == TYPE_3) {
	    int i = 0;
	    /* AT THIS POINT, ONLY ONE ITEM IN LIST */
	    iop0 = LIST_FIRST(&iocfg->iop0_paths); 

	    LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
		newiop0 = NULL;
		newiop1 = NULL;

		newiop0 = iop0_alloc();
		newiop1 = iop1_alloc();
		newiop0->iop = iop_alloc();
		newiop1->iop = iop_alloc();
		
		/* SWAP */
		copy_io_params(iop1->iop, newiop0->iop); 
		copy_io_params(iop0->iop, newiop1->iop); 

		newiop0->iop->fd_lock = PTHREAD_MUTEX_INITIALIZER;
		newiop0->iop->listlock = PTHREAD_MUTEX_INITIALIZER;

		pthread_cond_init(&newiop0->iop->readable, NULL);
		newiop0->iop->listready = malloc(sizeof(int));
		*newiop0->iop->listready = 0;

		newiop0->iop->rbuf_p = new_rbuf(iocfg->io_type, newiop0->iop->buf_sz);
		newiop0->iop->rbuf_writeto = rbuf_mtx_writeto;
		newiop1->iop->rbuf_readfrom = rbuf_t3_readfrom;
		newiop1->iop->io_thread = io_t3_thread;

		newiop0->iop->io_drn	= SRC;
		newiop1->iop->rbuf_p 	= newiop0->iop->rbuf_p;
		newiop1->iop->buf_sz	= newiop0->iop->buf_sz;

		newiop1->iop->listready	= newiop0->iop->listready;
		newiop1->iop->listlock 	= newiop0->iop->listlock;
		newiop1->iop->readable 	= newiop0->iop->readable;

		newiop1->iop->fd_lock	= newiop0->iop->fd_lock;
		newiop1->iop->io_fd	= newiop0->iop->io_fd;

		LIST_INSERT_HEAD(&newiop0->io_paths, newiop1, io_paths);
		LIST_INSERT_HEAD(&iocfg->iop0_paths, newiop0, iop0_paths);

	    }

	    LIST_REMOVE(iop0, iop0_paths);
	    newiop0 = LIST_FIRST(&iocfg->iop0_paths);
	    newiop1 = LIST_FIRST(&newiop0->io_paths);

	    if ((newiop1->iop->iofd_p = malloc(sizeof(int))) == NULL)
		log_syserr("malloc error");
	    else
		*newiop1->iop->iofd_p = -1;

	    newiop1->iop->fd_lock = malloc(sizeof(pthread_mutex_t));
	    if (pthread_mutex_init(&newiop1->iop->fd_lock, NULL) != 0) {
                log_die("fd_lock init error\n");
                exit(-1);
            }

 	    LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths) {		    
		iop1 = LIST_FIRST(&iop0->io_paths); /* ONLY 1 IN LIST */
		iop1->iop->fd_lock = newiop1->iop->fd_lock;
		iop1->iop->iofd_p  = newiop1->iop->iofd_p;
	    }
	}	
}

void *iocfg_manager(void *arg)
{
	struct io_cfg		*iocfg;
	struct iop0_params	*iop0;
	pthread_attr_t		dflt_attrs;

	iocfg = (struct io_cfg *)arg;

        if (pthread_attr_init(&dflt_attrs) != 0)
		log_die("Error initing thread attrs\n");

	LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths) {
	    if (pthread_create(&iop0->iop->tid, &dflt_attrs, iop0_thrd, (void *)iop0) != 0)
		log_die("error pthread_create: %s", strerror(errno));
	}
/*	FOR TYPE 3: 
 *	OPEN DESC FOR iop0
 *	COPY DESC TO ALL OTHER io_params
 *	CALL THREAD FOR EACH iop_param
 */
}

void *iop0_thrd(void *arg)
{
	pthread_t		tid;
	struct iop1_params	*iop1;
	struct iop0_params	*iop0;
	struct io_params	*iop;
	pthread_attr_t		dflt_attrs;
	int			r;

	struct io_cfg		*iocfg;
	iop0 = (struct iop0_params *)arg;
	iop = iop0->iop;

        if (pthread_attr_init(&dflt_attrs) != 0)
		log_die("Error initing thread attrs\n");

	if (pthread_create(&iop->tid, &dflt_attrs, io_thread, (void *)iop) != 0)
	    log_die("pthread_create() error");

	LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
	    if (pthread_create(&iop1->iop->tid, &dflt_attrs, iop1->iop->io_thread, (void *)iop1->iop) != 0)
		log_die("error pthread_create()");
	}

	r = pthread_join(iop->tid, NULL);
	log_msg("pthread_join() returned\n");
	pthread_exit(NULL);
}

void *io_t3_thread(void *arg)
{
	struct io_params	*iop;
	int			r;
	sigset_t		sig_set;

	iop = (struct io_params *)arg;
	
	set_thrd_sigmask(&sig_set);
	pthread_cleanup_push(release_mtx, iop);

	log_msg("Running io_t3_thread %s\n", iop->path);

	for (;;) {
	    if (*iop->iofd_p < 0) {
		pthread_mutex_lock(&iop->fd_lock);

		if (*iop->iofd_p < 0) {
		    log_msg("opening fd for %s\n", iop->path);
		    if ((*iop->iofd_p = open_desc(iop)) < 0) {
			log_msg("open error. Sleeping...\n");
			sleep(10);
			pthread_mutex_unlock(&iop->fd_lock);
			continue;
		    } else {
			log_msg("Releasing lock: %s Desc: %d\n\n", iop->path, *iop->iofd_p);
			pthread_mutex_unlock(&iop->fd_lock);
		    }
		} else {
		    log_msg("Releasing lock: %s Desc: %d\n\n", iop->path, *iop->iofd_p);
		    pthread_mutex_unlock(&iop->fd_lock);
		}
	    }
	    if (is_src(iop))
		r = iop->rbuf_writeto(iop);
	    else
		r = iop->rbuf_readfrom(iop);

	    if (SIGTERM_STAT == TRUE) {
		log_msg("SIGTERM_STAT is TRUE\n");
		break;
	    }
	}

	log_msg("io_thread returning for %s\n", iop->path);
	pthread_exit((void *)0);
	pthread_cleanup_pop(0);
}

void *io_thread(void *arg)
{
	struct io_params	*iop;
	int			r;
	sigset_t		sig_set;

	iop = (struct io_params *)arg;

	set_thrd_sigmask(&sig_set);
	pthread_cleanup_push(release_mtx, iop);

	for (;;) {
	    if (iop->io_fd < 0) {
		log_msg("opening fd for %s\n", iop->path);
		if ((iop->io_fd = open_desc(iop)) < 0) {
		    log_msg("open error. Sleeping...\n");
		    sleep(10);
		    continue;
		}

		/* BLOCK */
		if (is_src(iop))
			r = iop->rbuf_writeto(iop);
		else
			r = iop->rbuf_readfrom(iop);

		/* ONLY HERE IF DESCRIPTOR CLOSED */
		close(iop->io_fd);
		iop->io_fd = -1;

		if (SIGTERM_STAT == TRUE) {
			log_msg("SIGTERM_STAT is TRUE\n");
			if (iop->desc_type == UNIX_SOCK)
			    if (unlink(iop->path) != 0)
				log_ret("unlinkk error: %s %s\n", iop->path, errno);

			break;
		}
	    }
	}

	log_msg("io_thread returning for %s\n", iop->path);
	pthread_exit((void *)0);
	pthread_cleanup_pop(0);
}

void release_mtx(void *arg)
{
	struct io_params *iop;
	int		 r;

	iop = (struct io_params *)arg;

	log_msg("Cleanup called for %s\n", iop->path);
/*
*	if ((r = pthread_mutex_trylock(&iop->rbuf_p->lock)) != 0) {
*		if (r != EBUSY)
*			log_die("pthread_mutex_trylock() error: %d\n", r);
*	} else {
*		log_msg("trylock returned %d\n", r);
*	}
*/

	log_msg("Unlokcking MTX\n");
	if ((r = pthread_mutex_unlock(&iop->rbuf_p->mtx_lock)) != 0)
		log_msg("unlock error: %d\n", r);

	log_msg("release_mtx() returning ro %s\n", iop->path);
}

int validate_path(struct io_params *iop)
{
	struct stat sb;

	if (valid_path(iop->path, &sb) != 0)
		return 0;

	if (validate_ftype(iop, &sb) != 0) {
		log_msg("CONFIG ERR: Incorrect file type for %s\n", iop->path);
		return 1;
	}
}

int validate_ftype(struct io_params *iop, struct stat *s)
{
	if ((iop->desc_type == REG_FILE) && (!S_ISREG(s->st_mode))) {
		log_msg("CONFIG ERR: %s is not a regular file\n", iop->path);
		return -1;
	}

	if ((iop->desc_type == FIFO) && (!S_ISFIFO(s->st_mode))) {
		log_msg("%s is not a FIFO\n", iop->path);
		return -1;
	}

	if ((iop->desc_type == UNIX_SOCK) && (!S_ISSOCK(s->st_mode))) {
		log_msg("%s is not a UNIX socket\n", iop->path);
		return -1;
	}
	return 0;
}

void ioparam_list_kill(struct io_cfg *iocfg)
{	
	struct iop0_params	*iop0;
	struct iop1_params	*iop1;
	
	LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths) {
		LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
			close(iop1->iop->io_fd);
			pthread_cancel(iop1->iop->tid);
		}
	}	
}



void * sigterm_thrd(void *arg)
{
        int			sig;
        sigset_t		sig_set;

        sigemptyset(&sig_set);
        sigaddset(&sig_set, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &sig_set, NULL);

	/* BLOCK */
        sigwait(&sig_set, &sig);
        SIGTERM_STAT = TRUE;
        pthread_exit(NULL);
}

void set_thrd_sigmask(sigset_t *s)
{
	int 	r;
	
	sigemptyset(s);
        sigaddset(s, SIGTERM);
        sigaddset(s, SIGHUP);

        if ((r = pthread_sigmask(SIG_BLOCK, s, NULL)) != 0)
		log_die("pthread_sigmask error: %d\n", r);
}


void terminate(void)
{
	struct io_cfg		*iocfg;
	struct iop0_params	*iop0;
	int			r;

	log_msg("Terminating\n");

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs) {

		LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths)
		    close(iop0->iop->io_fd);

		LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths)
		    cancel_ioparam(iop0->iop);	
	}

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
	    LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths)
		if ((r = pthread_cancel(iop0->iop->tid)) != 0)
		    log_die("pthread_cancel() error: %d\n", r);
}

int cancel_ioparam(struct io_params *iop)
{
	int r;
	int error;

	error = 0;
	
	log_msg("cancel_iopraram() --- for %s\n", iop->path);

	if ((r = pthread_cancel(iop->tid)) != 0)
		log_die("pthread_cancel() error: %d\n", r);

	if ((r = pthread_join(iop->tid, NULL)) != 0) {
		if (r == EINVAL)
			log_msg("pthread_join() returned EINVAL\n");
		else
			error = r;
	} 

	log_msg("cancel_ioparam returning %d\n", error);
	return error;	
}

void copy_io_params(struct io_params *src, struct io_params *dst)
{
	memcpy(dst, src, sizeof(struct io_params)); 

	if (src->sock_data != NULL)
		memcpy(dst->sock_data, src->sock_data, sizeof(struct sock_param));
}
