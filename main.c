#include "ioproxy.h"

int debug = 1;

void *iocfg_manager(void *);
void *io_thread(void *);

int main(int argc, char *argv[])
{
	int	r;
	pthread_t tid;
	struct io_cfg *cfg;
	LIST_INIT(&all_cfg);
	read_config(&all_cfg);

	/* ITERATE OVER EACH CFG IN all_cfg AND 
	 * START CONTROL THREAD.
	*/
	pthread_attr_t dflt_attrs;
        if ((r = pthread_attr_init(&dflt_attrs)) != 0)
            log_die("Error initing thread attrs: %d\n", r);

/*	LIST_FOREACH(cfg, &all_cfg, io_cfgs)
*		show_config(cfg);
*/
	LIST_FOREACH(cfg, &all_cfg, io_cfgs)
		if (pthread_create(&tid, &dflt_attrs, iocfg_manager, (void *)cfg) != 0)
                	printf("error pthread_create: %s", strerror(errno));

	sleep(120);
	printf("Returning from main()\n");
}

void *iocfg_manager(void *arg)
{
	pthread_t		tid;
	struct io_cfg		*icfg;
	struct io_params	*iop;
	pthread_mutexattr_t	mxattrs;
	pthread_attr_t		dflt_attrs;

	icfg = (struct io_cfg *)arg;
	pthread_mutexattr_init(&mxattrs);
	icfg->io_p->listlock = PTHREAD_MUTEX_INITIALIZER;

        if (pthread_attr_init(&dflt_attrs) != 0)
		log_die("Error initing thread attrs\n");

	icfg->io_p->rbuf_p = new_rbuf();  /* MUST BE FREED */

	if (pthread_create(&icfg->io_p->tid, &dflt_attrs, io_thread, (void *)icfg->io_p) != 0)
		printf("pthread_create error: %s\n", strerror(errno));
	
/*	if (!is_netsock(icfg->io_p))
*		validate_path(icfg->io_p);
*/
	LIST_FOREACH(iop, &icfg->io_paths, io_entries)
		iop->rbuf_p = icfg->io_p->rbuf_p;

	LIST_FOREACH(iop, &icfg->io_paths, io_entries) {
		if (pthread_create(&iop->tid, &dflt_attrs, io_thread, (void *)iop) != 0)
                	printf("error pthread_create: %s", strerror(errno));
	}
}

void *io_thread(void *arg)
{
	struct io_params	*iop;
	int			r;

	iop = (struct io_params *)arg;

	for (;;) {
		if (iop->desc_type == FIFO) {
			if ((iop->io_fd = open_fifo(iop)) < 0)
				printf("open_fifo error\n");
		} else if (iop->desc_type == REG_FILE) {
			if ((iop->io_fd = open_file(iop)) < 0)
				printf("open_file error\n");
		} else if (iop->desc_type == UNIX_SOCK) {
			if ((iop->io_fd = open_unixsock(iop)) < 0)
				printf("open unixsock error\n");
		} else if (iop->desc_type == STDIN) {
			iop->io_fd = STDIN_FILENO;
		} else if (iop->desc_type == STDOUT) {
			iop->io_fd = STDOUT_FILENO;
		} else if (iop->desc_type == TCP_SOCK) {
			iop->io_fd = open_tcpsock(iop);
		} else if (iop->desc_type == UDP_SOCK) {
			iop->io_fd = open_udpsock(iop);
		} else {
			printf("Unknown type %d\n", iop->desc_type);
			exit(-1);
		}
	
		if (is_src(iop))
			r = rbuf_writeto(iop);
		else
			r = rbuf_readfrom(iop);

		if (r < 0)
			break;
	}
	free_rbuf(iop->rbuf_p);
	printf("io_thread returning\n");
/*	pthread_exit(void); */
}

int validate_path(struct io_params *iop)
{
	struct stat sb;

	if (valid_path(iop->path, &sb) != 0)
		return 0;

	if (validate_ftype(iop, &sb) != 0) {
		printf("CONFIG ERR: Incorrect file type for %s\n", iop->path);
		return 1;
	}
}

int validate_ftype(struct io_params *iop, struct stat *s)
{
	if ((iop->desc_type == REG_FILE) && (!S_ISREG(s->st_mode))) {
		printf("CONFIG ERR: %s is not a regular file\n", iop->path);
		return -1;
	}

	if ((iop->desc_type == FIFO) && (!S_ISFIFO(s->st_mode))) {
		printf("%s is not a FIFO\n", iop->path);
		return -1;
	}

	if ((iop->desc_type == UNIX_SOCK) && (!S_ISSOCK(s->st_mode))) {
		printf("%s is not a UNIX socket\n", iop->path);
		return -1;
	}
	return 0;
}
