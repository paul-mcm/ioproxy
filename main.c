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
int			debug;
char			*prog;
char			*config_file = "/etc/ioproxyd.conf";
volatile sig_atomic_t	SIGHUP_STAT;
volatile sig_atomic_t	SIGTERM_STAT;
pthread_mutex_t		sighupstat_lock;
pthread_cond_t		thrd_stat;
int			thread_cnt;
pthread_barrier_t	thrd_b;
void			*io_thread(void *);

int main(int argc, char *argv[])
{
	pthread_t		sigterm_tid, tid;
	pthread_attr_t		dflt_attrs;
	struct io_cfg		*iocfg;
	sigset_t		sig_set;
	struct rlimit           rlim_ptr;
	int			sig, r;
	char			*host_file = '\0';
	char			ch;
	int			daemonize;

	prog = basename(argv[0]);

	if (strcasecmp(prog, "ioproxyd") == 0)
	    daemonize = TRUE;
	else
	    daemonize = FALSE;

	while ((ch = getopt(argc, argv, "dH:f:")) != -1) {
	    switch (ch) {
	    case 'f':
		config_file = optarg;
		break;
	    case 'H':
		host_file = optarg;
		if (validate_path(host_file) != 0)
		    log_die("Host file path invalid\n");
		break;
	    case 'd':
		debug = TRUE;
		daemonize = FALSE;
		break;
	    case '?':
		log_die("Exiting\n");
           }
	}

	argc -= optind;
	argv += optind;

	if (getrlimit(RLIMIT_NOFILE, &rlim_ptr) < 0)
	    log_syserr("rlimit failed %d", errno);

	for (r = 3; r <= (int)rlim_ptr.rlim_cur; r++)
	    close(r);

	if (debug == FALSE) {
	    if (daemon(0, 0) < 0)
		log_die("Failed to daemonize", errno);
	}

	if (validate_path(config_file) != 0)
	    log_die("Config file path invalid\n");

	if (tls_init() < 0)
	    log_die("tls_init() error\n");

	sigemptyset(&sig_set);
        sigaddset(&sig_set, SIGTERM);
        sigaddset(&sig_set, SIGHUP);
	if (pthread_sigmask(SIG_BLOCK, &sig_set, NULL) != 0)
	    log_die("pthread_sigmask() error\n");

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
            log_syserr("Failed to ignore SIGPIPE:", errno);

	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
            log_syserr("Failed to ignore SIGPIPE:", errno);

	SIGTERM_STAT = FALSE;
	SIGHUP_STAT  = FALSE;
	if (pthread_mutex_init(&sighupstat_lock, NULL) != 0)
	    log_syserr("mutex init error");

	ssh_threads_set_callbacks(ssh_threads_get_pthread());
	ssh_init();

	LIST_INIT(&all_cfg);
	read_config(&all_cfg, config_file);

	/* ITERATE OVER EACH CFG IN all_cfg AND 
	 * START CONTROL THREAD.
	 */

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
	    iop_setup(iocfg);

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
	    validate_cfg(iocfg);

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
	    show_config(iocfg);

	if (pthread_create(&tid, NULL, iocfg_manager, (void *)&all_cfg) != 0)
	    log_die("error pthread_create()");

	if (pthread_create(&sigterm_tid, NULL, sigterm_thrd, NULL) != 0)
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
	pthread_mutexattr_t	mtx_attrs;
	int			r;

	if (iocfg->cfg_type == TYPE_1 || iocfg->cfg_type == TYPE_2) {

	    /* AT THIS STAGE, iop0_paths HAS ONLY 1 MEMBER */
	    iop0 = LIST_FIRST(&iocfg->iop0_paths);
	    iop = iop0->iop;

	    pthread_cond_init(&iop->readable, NULL);
	    if (pthread_mutex_init(&iop0->iop->listlock, NULL) != 0)
		log_syserr("mutex init error");

	    iop0->iop->rbuf_p = new_rbuf(iocfg->cfg_type, iop->buf_sz);
	    iop0->iop->w_ptr = iop0->iop->rbuf_p;
	    iop0->iop->r_ptr = iop0->iop->rbuf_p;
	    iop0->iop->listready = malloc(sizeof(int));
	    *iop0->iop->listready = 0;

	    LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
		iop1->iop->rbuf_p	= iop0->iop->rbuf_p;
		iop1->iop->r_ptr	= iop0->iop->rbuf_p;
		iop1->iop->w_ptr	= iop0->iop->rbuf_p;
		iop1->iop->buf_sz	= iop0->iop->buf_sz;
		iop1->iop->listready	= iop0->iop->listready;
		iop1->iop->listlock	= iop0->iop->listlock;
		iop1->iop->readable	= iop0->iop->readable;
		iop1->iop->io_fd	= iop0->iop->io_fd;
		iop1->iop->io_thread	= io_thread;
		iop1->iop->io_drn 	= DST;
	    }

	} else if (iocfg->cfg_type == TYPE_3) {
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

		if (pthread_mutex_init(&newiop0->iop->listlock, NULL) != 0)
		    log_syserr("mutex init error");

		pthread_cond_init(&newiop0->iop->readable, NULL);
		newiop0->iop->listready = malloc(sizeof(int));
		*newiop0->iop->listready = 0;

		newiop0->iop->rbuf_p = new_rbuf(iocfg->cfg_type, newiop0->iop->buf_sz);
		newiop0->iop->w_ptr = newiop0->iop->rbuf_p;
		newiop0->iop->r_ptr = newiop0->iop->rbuf_p;

		newiop1->iop->io_thread = io_t3_thread;

		newiop0->iop->io_drn	= SRC;
		newiop1->iop->rbuf_p 	= newiop0->iop->rbuf_p;
		newiop1->iop->w_ptr	= newiop0->iop->rbuf_p;
		newiop1->iop->r_ptr	= newiop0->iop->rbuf_p;

		newiop1->iop->buf_sz	= newiop0->iop->buf_sz;

		newiop1->iop->listready	= newiop0->iop->listready;
		newiop1->iop->listlock 	= newiop0->iop->listlock;
		newiop1->iop->readable 	= newiop0->iop->readable;

		newiop1->iop->io_fd	= newiop0->iop->io_fd;

		LIST_INSERT_HEAD(&newiop0->io_paths, newiop1, io_paths);
		LIST_INSERT_HEAD(&iocfg->iop0_paths, newiop0, iop0_paths);
	    }

	    /* REMOVE/FREE ORIGINAL */
	    LIST_REMOVE(iop0, iop0_paths);
	    LIST_FOREACH(iop1, &iop0->io_paths, io_paths)
		free_iop(iop1->iop);

	    free_iop(iop0->iop);
	    free(iop0);

	    newiop0 = LIST_FIRST(&iocfg->iop0_paths);
	    newiop1 = LIST_FIRST(&newiop0->io_paths);

	    if ((newiop1->iop->iofd_p = malloc(sizeof(int))) == NULL)
		log_syserr("malloc error");

	    *newiop1->iop->iofd_p = -1;

	    pthread_mutexattr_init(&mtx_attrs);
	    if ((r = pthread_mutexattr_settype(&mtx_attrs, PTHREAD_MUTEX_ERRORCHECK)) \
		!= 0)
		log_syserr("ATTR SETTYPE FAILED: %d\n", r);

	    if (pthread_mutex_init(&newiop1->iop->fd_lock, &mtx_attrs) != 0) {
		log_die("fd_lock init error\n");
		exit(-1);
	    }

	    LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths) {
		iop1 = LIST_FIRST(&iop0->io_paths); /* ONLY 1 UNIQUE IN LIST */
		iop1->iop->fdlock_p = &newiop1->iop->fd_lock;
		iop1->iop->iofd_p  = newiop1->iop->iofd_p;
	    }
	}
}

void *iocfg_manager(void *arg)
{
	struct io_cfg		*iocfg;
	struct all_cfg_list	*acfg;
	struct iop0_params	*iop0;
	pthread_attr_t		dflt_attrs;
	pthread_t		sighup_tid;
	int			n;

	acfg = (struct all_cfg_list *)arg;

	if (pthread_cond_init(&thrd_stat, NULL) != 0)
	    log_die("pthread_cond_init() error\n");

	if (pthread_attr_init(&dflt_attrs) != 0)
	    log_die("error initing attrs\n");

	if (pthread_attr_setdetachstate(&dflt_attrs, PTHREAD_CREATE_DETACHED) != 0)
	    log_die("error setting detach state\n");

	for (;;) {
	    thread_cnt = 1;
	    SIGHUP_STAT = FALSE;

	    if (pthread_create(&sighup_tid, NULL, sighup_thrd, NULL) != 0)
		log_die("error pthread_create()");

	    n = 0;
	    LIST_FOREACH(iocfg, acfg, io_cfgs) {
		LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths)
		    n++;
	    }

	    if (pthread_barrier_init(&thrd_b, NULL, n) != 0)
		log_die("BARIER INIT ERROR\n");

	    LIST_FOREACH(iocfg, acfg, io_cfgs) {
		LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths) {
		    if (pthread_create(&iop0->iop->tid, &dflt_attrs, iop0_thrd, (void *)iop0) != 0)
			log_die("error pthread_create: %s", strerror(errno));
		}
	    }

	    pthread_join(sighup_tid, NULL);
	    pthread_barrier_destroy(&thrd_b);
	}
}

void *iop0_thrd(void *arg)
{
	pthread_t		tid;
	struct iop1_params	*iop1;
	struct iop0_params	*iop0;
	struct io_params	*iop;
	pthread_attr_t		dflt_attrs;
	int			cnt, r;

	struct io_cfg		*iocfg;
	iop0 = (struct iop0_params *)arg;
	iop = iop0->iop;

	if (pthread_create(&iop->tid, NULL, io_thread, (void *)iop) != 0)
	    log_die("pthread_create() error");

	LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
	    if (pthread_create(&iop1->iop->tid, NULL, iop1->iop->io_thread, (void *)iop1->iop) != 0)
		log_die("error pthread_create()");
	}

	r = pthread_join(iop->tid, NULL);

	r = cancel_threads(iop0);

	/* ALL I/O THREADS SHOULD BE GONE BY THIS POINT */
	if (SIGHUP_STAT == TRUE) {
	    if (pthread_barrier_wait(&thrd_b) == PTHREAD_BARRIER_SERIAL_THREAD) {
		pthread_mutex_lock(&sighupstat_lock);
		thread_cnt = 0;
		pthread_mutex_unlock(&sighupstat_lock);
		if (pthread_cond_signal(&thrd_stat) != 0)
		    log_syserr("ERROR sending SIGHUP thread signal\n");
	    }
	}

	pthread_exit((void *)0);
}

void *io_t3_thread(void *arg)
{
	/* THIS IF FOR TYPE 3 DESTINATIONS ONLY
	 * NB: iop->drn IS ALWAYS 'dst';
	 * USES A MTX LOCK TO OBVIATE INTERLEAVED DATA WRITTEN TO COMMON
	 * DESCRIPTOR BY DIFFERENT THREADS (NOT NECESSARY FOR DGRAM
	 * SOCKETS)
	 */

	struct iop1_params	*iop1;
	struct io_params	*iop;
	struct sock_param	*sop;
	int			r;
	sigset_t		sig_set;

	iop = (struct io_params *)arg;
	sop = iop->sock_data;

	set_thrd_sigmask();

	pthread_cleanup_push(release_locks, iop);

	for (;;) {
	    if (*iop->iofd_p < 0) {
		pthread_mutex_lock(&iop->fd_lock);

		if (*iop->iofd_p > 0) {
		    pthread_mutex_unlock(&iop->fd_lock);
		} else {

 		    if (is_netsock(iop))
			log_msg("opening fd for %s\n", sop->hostname);
		    else
			log_msg("opening dscrptr for %s\n", iop->path);

		    r = open_desc(iop);
		    if (r == -2) { /* NON RECOVERABLE ERROR */
			pthread_mutex_unlock(&iop->fd_lock);
			break;
		    } else if (r <= 0) {
			log_msg("open error. Sleeping...\n");
			pthread_mutex_unlock(&iop->fd_lock);
			sleep(10);
			continue;
		    } else {
			*iop->iofd_p = r;
			pthread_mutex_unlock(&iop->fd_lock);
		    }
		}
	    }

	    if (use_tls(iop)) {
		r = rbuf_t3_tlsreadfrom(iop);
	    } else if (is_sock(iop) && sop->sockio == DGRAM) {
		r = rbuf_dgram_readfrom(iop);
	    } else {
		r = rbuf_t3_readfrom(iop);
	    }

	    /* ONLY HERE IF DESCRIPTOR CLOSED */
	    if (r == -2)
		break;

	    if (is_netsock(iop) || iop->io_type == FIFO) {
		close_desc(iop);
		*iop->iofd_p = -1;
	    }

	    if (SIGTERM_STAT == TRUE)
		break;
	    else if (SIGHUP_STAT == TRUE)
		break;
	}

	if (is_netsock(iop) || iop->io_type == FIFO)
	    close_desc(iop);

	if (iop->io_type == UNIX_SOCK && unlink(iop->path) != 0)
	    log_ret("unlink error: %s, %s\n", iop->path);	

	log_msg("T3 io_thread returning for %s %p\n", iop->path, iop);
	pthread_exit((void *)0);
	pthread_cleanup_pop(0);
}

void *io_thread(void *arg)
{
	struct iop1_params	*iop1;
	struct io_params	*iop;
	struct sock_param	*sop;
	int			r;

	iop = (struct io_params *)arg;
	sop = iop->sock_data;

	set_thrd_sigmask();

	pthread_cleanup_push(release_locks, arg);
	for (;;) {
	    if (iop->io_fd < 0) {
		if (is_netsock(iop)) {
		    log_msg("creating socket for %s\n", sop->ip);
		} else {
		    log_msg("opening dscrptr for %s\n", iop->path);
		}

		/* Returns:
		 *  -2 = non-recoverable error
		 *  -1 = error; retry later;
		 *   0 = successful open; I/O not through fd (SSH)
		 *  >0 = successful open; fd is returned;
		 */
		if ((r = open_desc(iop)) < 0) {
		    if (r == -2) { /* NON RECOVERABLE ERROR */
			break;
		    } else {
			log_msg("open error. Sleeping...\n");
			sleep(10);
			continue;
		    }
		} else if (r != 0) {
		    iop->io_fd = r;
		}

		/* BLOCK */
		if (is_src(iop)) {
		    if (use_tls(iop)) {
			r = rbuf_tls_writeto(iop);
		    } else if (use_ssh(iop)) {
			r = rbuf_ssh_writeto(iop);
		    } else if (is_sock(iop) && sop->sockio == DGRAM) {
			r = rbuf_dgram_writeto(iop);
		    } else {
			r = rbuf_writeto(iop);
		    }
		} else {
		    if (use_tls(iop)) {
			r = rbuf_tls_readfrom(iop);
		    } else if (is_sock(iop) && sop->sockio == DGRAM) {
			r = rbuf_dgram_readfrom(iop);
		    } else {
			r = rbuf_readfrom(iop);
		    }
		}

		/* ONLY HERE IF DESCRIPTOR CLOSED */
		if (r == -2)
		    break;

		if (is_netsock(iop) || iop->io_type == FIFO) {
		    close_desc(iop);
		    iop->io_fd = -1;
		}

		if (SIGTERM_STAT == TRUE)
		    break;
		else if (SIGHUP_STAT == TRUE)
		    break;	    }
	}

	if (is_netsock(iop)) {
	    close_desc(iop);
	    iop->io_fd = -1;
	}

	if (iop->io_type == PIPE) {
	    close_desc(iop);
	}

	if (iop->io_type == UNIX_SOCK && unlink(iop->path) != 0)
	    log_ret("unlinkk error: %s %s\n", iop->path, errno);

	release_locks((void *)iop);
	log_msg("io_thread returning for %s\n", iop->path);
	pthread_cleanup_pop(0);
	pthread_exit((void *)0);
}

int validate_ftype(struct io_params *iop, struct stat *s)
{
	if ((iop->io_type == REG_FILE) && (!S_ISREG(s->st_mode))) {
		log_msg("CONFIG ERR: %s is not a regular file\n", iop->path);
		return -1;
	}

	if ((iop->io_type == FIFO) && (!S_ISFIFO(s->st_mode))) {
		log_msg("%s is not a FIFO\n", iop->path);
		return -1;
	}

	if ((iop->io_type == UNIX_SOCK) && (!S_ISSOCK(s->st_mode))) {
		log_msg("%s is not a UNIX socket\n", iop->path);
		return -1;
	}
	return 0;
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
        pthread_exit((void *)0);
}

void set_thrd_sigmask(void)
{
	sigset_t	s;
	int		r;
	
	sigemptyset(&s);
        sigaddset(&s, SIGTERM);
        sigaddset(&s, SIGHUP);

        if ((r = pthread_sigmask(SIG_BLOCK, &s, NULL)) != 0)
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
		    close_desc(iop0->iop);

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
	struct sock_param	*sop, *src_sop;
	int			r;

	memcpy(dst, src, sizeof(struct io_params)); 

	if (src->path != NULL) {
	    if ((dst->path = malloc(strlen(src->path) + 1)) == NULL)
		log_syserr("malloc() error\n");
	    strlcpy(dst->path, dst->path, strlen(src->path) + 1);
	}

	if (src->pipe_cmd != NULL) {
	    if ((dst->pipe_cmd = malloc(strlen(src->pipe_cmd) + 1)) == NULL)
		log_syserr("malloc() error");
	    strlcpy(dst->pipe_cmd, src->pipe_cmd, strlen(src->pipe_cmd) + 1);
	}

	if (src->sock_data != NULL) {
	    dst->sock_data = sock_param_alloc();
	    sop = dst->sock_data;
	    src_sop = src->sock_data;

	    memcpy(sop, src_sop, sizeof(struct sock_param));

	    if (src_sop->hostname != NULL) {
		if ((sop->hostname = malloc(strlen(src_sop->hostname) + 1)) == NULL)
		    log_syserr("malloc() error");
		r = strlcpy(sop->hostname, src_sop->hostname, strlen(src_sop->hostname) + 1);
	    }

	    if (src_sop->ip != NULL) {
		if ((sop->ip = malloc(strlen(src_sop->ip) + 1)) == NULL)
		    log_syserr("malloc() error");
		strlcpy(sop->ip, src_sop->ip, strlen(src_sop->ip) + 1);
	    }

	    if (src_sop->tls_port != NULL) {
		if ((sop->tls_port = malloc(strlen(src_sop->tls_port) + 1)) == NULL)
		    log_syserr("malloc() error");
		strlcpy(sop->tls_port, src_sop->tls_port, strlen(src_sop->tls_port) + 1);
	    }

	    if (src_sop->cacert_path != NULL) {
		if ((sop->cacert_path = malloc(strlen(src_sop->cacert_path) + 1)) == NULL)
		    log_syserr("malloc() error");
		strlcpy(sop->cacert_path, src_sop->cacert_path, strlen(src_sop->cacert_path) + 1);
	    }

	    if (src_sop->cacert_dirpath != NULL) {
		if ((sop->cacert_dirpath = malloc(strlen(src_sop->cacert_dirpath) + 1)) == NULL)
		    log_syserr("malloc() error");
		strlcpy(sop->cacert_dirpath, src_sop->cacert_dirpath, strlen(src_sop->cacert_dirpath) + 1);
	    }

	    if (src_sop->host_cert != NULL) {
		if ((sop->host_cert = malloc(strlen(src_sop->host_cert) + 1)) == NULL)
		    log_syserr("malloc() error");
		strlcpy(sop->host_cert, src_sop->host_cert, strlen(src_sop->host_cert) + 1);
	    }

	    if (src_sop->host_key != NULL) {
		if ((sop->host_key = malloc(strlen(src_sop->host_key) + 1)) == NULL)
		    log_syserr("malloc() error");
		strlcpy(sop->host_key, src_sop->host_key, strlen(src_sop->host_key) + 1);
	    }

	    if (src_sop->ssh_cmd != NULL) {
		if ((sop->ssh_cmd = malloc(strlen(src_sop->ssh_cmd) + 1)) == NULL)
		    log_syserr("malloc() error");
		strlcpy(sop->ssh_cmd, src_sop->ssh_cmd, strlen(src_sop->ssh_cmd) + 1);
	    }

	    if (src_sop->sockpath != NULL) {
		if ((sop->sockpath = malloc(strlen(src_sop->sockpath) + 1)) == NULL)
		    log_syserr("malloc() error");
		strlcpy(sop->sockpath, src_sop->sockpath, strlen(src_sop->sockpath) + 1);
	    }
	}
}

void * sighup_thrd(void *a)
{
	int			sig;
	sigset_t		sig_set;
	struct io_cfg		*iocfg;
	struct iop0_params 	*iop0;
	struct iop1_params	*iop1;
	int			n, r;

	pthread_mutex_lock(&sighupstat_lock);
	SIGHUP_STAT = FALSE;
	pthread_mutex_unlock(&sighupstat_lock);

	sigemptyset(&sig_set);
	sigaddset(&sig_set, SIGHUP); /* SIGHUP BLOCKED IN main() */

	sigwait(&sig_set, &sig);

	pthread_sigmask(SIG_BLOCK, &sig_set, NULL);

	pthread_mutex_lock(&sighupstat_lock);
	SIGHUP_STAT = TRUE;
	pthread_mutex_unlock(&sighupstat_lock);

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs) {
	    LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths) {
		LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
		    close_desc(iop1->iop);
		}
		close_desc(iop0->iop);

		/* NEED TO FIGURE OUT WHAT *NEEDS* CANCELLING AND WHAT DOESN'T 
		* E.G., FIFOS RETURN AFTER DESCRIPTOR CLOSE
		*/
		pthread_cancel(iop0->iop->tid);
	    }
	}

	MTX_LOCK(&sighupstat_lock);
	while (thread_cnt == 1) {
	    pthread_cond_wait(&thrd_stat, &sighupstat_lock);
	}
	MTX_UNLOCK(&sighupstat_lock);

	/* EMPTY CFG LIST HERE */
	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
	    free_iocfg(iocfg);

	while (!LIST_EMPTY(&all_cfg)) {
	    iocfg = LIST_FIRST(&all_cfg);
	    LIST_REMOVE(iocfg, io_cfgs);
	    free(iocfg);
	}

	read_config(&all_cfg, config_file);

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
	    iop_setup(iocfg);

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
	    validate_cfg(iocfg);  /* XXX COULD CAUSE PROG TO EXIT. NEEDS FIXING */

	LIST_FOREACH(iocfg, &all_cfg, io_cfgs)
	    show_config(iocfg);

	pthread_exit((void *)0);
}

int cancel_threads(struct iop0_params *iop0)
{
	struct iop1_params	*iop1;
	int			 n, r;

	n = 0;

	sleep(1);  /* Give some time for threads to exit themselves */

	LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
	    if ((r = pthread_cancel(iop1->iop->tid)) != 0) {
		log_msg("pthread_cancel() failed: %d\n", r);
		continue;
	    }
	}
	LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
	    if (pthread_join(iop1->iop->tid, NULL) == 0) {
		log_msg("pthread_join() returned for : %s\n", iop1->iop->path);
	    } else {
		log_msg("pthread_join() returned badly!\n");
	    }
	    n++;
	}
	return n;
}
