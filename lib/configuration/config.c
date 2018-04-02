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

#include "config.h"
#include "parse_line.h"

const char *tr_fls[] = { "FALSE", "TRUE" };
const char *io_types[] = { "REG_FILE", "FIFO", "STDOUT", "STDIN", "UNIX_SOCK", "TCP_SOCK", "UDP_SOCK", "PIPE", "SSH"};
const char *io_drn[] = { "SRC", "DST" };
const char *cfg_types[] = {"TYPE_1", "TYPE_2", "TYPE_3"};
const char *conn_type[] = { "CLIENT", "SRVR" };
const char *sockio[] = { "DGRAM", "STREAM" };

int read_config(struct all_cfg_list *all, char *cfg_file)
{
        FILE *fp;
        char ln[SIZE];
        char *p;
	struct io_cfg *iocfg;

        if ((fp = fopen(cfg_file, "r")) == NULL)  {
		log_syserr("fopen error: ");
	}

        /* FIND BEGIN OF CONFIG STANZA BY IGNORING STUFF UNTIL "{" IS FOUND */
        while (fgets(ln, SIZE, fp) != NULL) {
                p = ln;
                if (strncmp(p, "{", 1) == 0) {
                        fseek(fp, -(strlen(p) - 1), SEEK_CUR);
                        iocfg = parse_config(fp); 
			set_cfg_type(iocfg);

                        LIST_INSERT_HEAD(all, iocfg, io_cfgs);
		}

                if (feof(fp) != 0)
                        break;
        }
	if (fclose(fp) != 0)
	    log_syserr("fclose failed\n");
}

struct io_cfg *parse_config(FILE *fp)
{
        char ln[SIZE];
        char *p;
	struct io_cfg *iocfg;
	struct io_params *iop;
	struct iop0_params *iop0;
	struct iop1_params *iop1;
	int r;
                
	/* IN CONFIG STANZA */
	iocfg = io_cfg_alloc();

	if ((iop0 = parse_iop0_stanza(fp)) == NULL) {
		log_msg("parse_iop0_stanza error\n");
		return NULL;
	} else {
		LIST_INSERT_HEAD(&iocfg->iop0_paths, iop0, iop0_paths);
	}

	iop0 = LIST_FIRST(&iocfg->iop0_paths);

	for (;;) {				
		if ((iop = parse_io_cfg(fp)) != NULL) {
			iop1 = iop1_alloc();
			iop1->iop = iop;	
 			LIST_INSERT_HEAD(&iop0->io_paths, iop1, io_paths);
		} else {			
			log_msg("parse_io_cfg error");
			return NULL;
		}

		/* read next line until readable line */	

		while (fgets(ln, SIZE, fp) != NULL) {
                	p = clean_line(ln);

	                /* IF COMMENT -> CONTINUE ....*/
        	        if (check_line(p) != 0)
                	        continue;
			else
				break;
		}
		if (strncmp(p, "(", 1) == 0) {
			fseek(fp, -(strlen(p) + 1), SEEK_CUR);
			continue;
		} else if (strncmp(p, "}", 1) == 0) {
			break;
                }
        }

	return iocfg;
}

char * fetch_next_line(FILE *f)
{
	char	*ln, *p;
	int	n_bytes;

        for (;;) {
            ln = NULL;

            n_bytes = (line_byte_cnt(f));
            if (n_bytes == 0) {
		return NULL;	/* EOF */
	    }

            if ((ln = malloc((size_t)(n_bytes + 1))) == NULL)
                log_syserr("malloc error while reading config file", errno);

            if (fgets(ln, n_bytes + 1, f) == NULL) {
                if (feof(f)) {
                    free(ln);
                    return NULL;
                } else {
                    /* FATAL */
		    free(ln);
                    log_die("error calling fgets on config file", errno);
		}
	    }
	    p = clean_line(ln);
	    if (check_line(p) != 0) {
                free(ln);
                continue;
            } else {
		break;
	    }		
	}
	return ln;
}

struct iop0_params * parse_iop0_stanza(FILE *f)
{
	struct iop0_params *iop0;
        char *ln;
        char *p;
        int r;

	iop0 = iop0_alloc();
	iop0->iop = iop_alloc();

        while ((ln = fetch_next_line(f)) != NULL) {
		p = clean_line(ln);
		/* '(' character signals end of stanza */
                if (strncmp(p, "(", 1) == 0) {
                        fseek(f, -(strlen(ln)), SEEK_CUR);
                        break;
                }

		if ((r = parse_line(p, iop0->iop)) < 0) {
			log_msg("Error parsing line\n");
			free(ln);
			return NULL;
		}
	}

	free(ln);
	return iop0;
} 

struct io_params *parse_io_cfg(FILE *f)
{
	char ln[SIZE];
	char *p = ln;
	int r;
	int last = 0;
	struct io_params *iop;

	iop = iop_alloc();

	/* XXX NEED TO SUPPORT ARBITRARY LINE LENGTHS */
	while (fgets(ln, SIZE, f) != NULL) {
                p = clean_line(ln);

		/* IF COMMENT -> CONTINUE ....*/
		if (check_line(p) != 0)
			continue;

                if (strncmp(p, ")", 1) == 0)
                	break;

		if (strncmp(&p[0], "(", 1) == 0 ) /* EAT FIRST '(' */
			p++;

		if (strncmp(&p[ strlen(p) - 1 ], ")", 1) == 0 ) {
			last = 1;
			p[ strlen(p) - 1 ] = '\0';
			p = rm_end_space(p);
		}

                if ((r = parse_line(p, iop)) < 0 ) {
                        log_msg("Error parsing line\n");
                        return NULL;
                } 

		if (last)
			break;			
	}

	return iop;
}

int is_dst(struct io_params *iop)
{
	if (iop->io_drn == DST)
		return 1;
	else
		return 0;
}

int is_src(struct io_params *iop)
{
	if (iop->io_drn == SRC)
		return 1;
	else
		return 0;
}

int is_sock(struct io_params *iop)
{
        if ((iop->io_type == UDP_SOCK) || \
	    (iop->io_type == TCP_SOCK) || \
	    (iop->io_type == UNIX_SOCK) || \
	    (iop->io_type == SSH))
                return 1; 
        else 
                return 0; 
}

int is_netsock(struct io_params *iop)
{
        if ((iop->io_type == UDP_SOCK) || \
	    (iop->io_type == TCP_SOCK))
                return 1; 
        else 
                return 0; 
}

int use_tls(struct io_params *iop)
{

	if (is_sock(iop) && iop->sock_data->tls == TRUE)
	    return 1;
	else
	    return 0;
}

int use_ssh(struct io_params *iop)
{
	if (iop->io_type == SSH)
	    return 1;
	else
	    return 0;
}

int show_config(struct io_cfg *iocfg)
{
	struct iop0_params *iop0;
	struct iop1_params *iop1;

	log_msg("========= START CONFIG ==========\n");
	log_msg("cfg_type\t\t%s\n", cfg_types[iocfg->cfg_type]);

	LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths) {
		log_msg("------- iop0 path -----------\n");
		print_config_params(iop0->iop);

	        LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
			log_msg("-------- iopath -------\n");
			print_config_params(iop1->iop);
		}
        }
}

int show_all_configs(struct all_cfg_list *all)
{
        struct io_cfg *icfg;

        LIST_FOREACH(icfg, all, io_cfgs) { 
                show_config(icfg);

        }
}

void print_config_params(struct io_params *iop)
{
	struct sock_param *sop;
	sop = iop->sock_data;

	printf("cfgtype_p\t\t%s\n", cfg_types[*iop->cfgtype_p]);
	printf("io_drn:\t\t%s\n", io_drn[iop->io_drn]);
	printf("io_type:\t\t%s\n", io_types[iop->io_type]);
	printf("rbuf_p addr: %p\n", iop->rbuf_p);
	printf("io_fd ptr: %p\n", iop->io_fd);
	printf("fd_lock ptr: %p\n", iop->fd_lock);
	printf("buf_sz: %d\n", iop->buf_sz);

	if (iop->pipe_cmd != NULL)
	    printf("pipe_cmd:\t\t%s\n", iop->pipe_cmd);

/*	printf("readable addr: %p\n", iop->readable);
*	printf("listlock addr: %p\n", iop->listlock);
*	printf("listready addr: %p\n", iop->listready);
*/
	printf("nonblock: %d\n", iop->nonblock);
	printf("io_fd: %d\n", iop->io_fd);
	printf("path: %s\n", iop->path != NULL ? iop->path : NULL);

	if (use_ssh(iop)) {
		printf("------------- ssh data ---------------\n");
		if (sop->hostname != NULL)
		    printf("hostname: %s\n", sop->hostname);
		if (sop->ip != NULL)
		    printf("ip: %s\n", sop->ip);
		printf("Command: %s\n", sop->ssh_cmd);
	} else if (is_sock(iop) && iop->io_type != SSH) {
		printf("----- sock_data -----\n");
		printf("\tconn_type: %s\n", 	conn_type[sop->conn_type]);
		printf("\tsockio: %s\n", 		sockio[sop->sockio]);
		printf("\tip: %s\n", 		sop->ip != 0 ? sop->ip : NULL);
		printf("\tport: %d\n", 		sop->port != 0 ? sop->port : 0);
		if (iop->sock_data->hostname != NULL)
			printf("\thostname: %s\n", sop->hostname);
		if (sop->sockpath != NULL)
			printf("\tsockpath: %s\n", sop->sockpath);
		if (sop->tls == TRUE) {
		    printf("\ttls = TRUE\n");
		    printf("\ttls_port: %s\n", sop->tls_port);
		    if (sop->cacert_path != NULL)
			printf("\tcacertpath: %s\n", sop->cacert_path);
		    if (sop->cacert_dirpath != NULL)
			printf("\tcacertdir: %s\n", sop->cacert_dirpath);

		    printf("\tcert_vrfy: %s\n", tr_fls[sop->cert_vrfy]);

		    if (sop->host_cert != NULL)
			printf("\thost_cert: %s\n", sop->host_cert);
		    if (sop->host_key != NULL)
			printf("\thost_key: %s\n", sop->host_key);
		}
	}

}

int validate_path(char *path) 
{
	struct stat     s;

        if (stat(path, &s) != 0) {
	    log_syserr("File error: %s\n", path);
	    return -1;
        } else {
            return 0;
        }
}

int valid_ftype(int n, struct stat *s)
{
        if (n == REG_FILE && S_ISREG(s->st_mode))
                return 0;
        else if (n == FIFO && S_ISFIFO(s->st_mode))
                return 0;
        else if (n == UNIX_SOCK && S_ISSOCK(s->st_mode))
                return 0;
        /* THESE TYPES DON'T MATTER; DON'T ERRONEOUSLY SUGGEST ERROR */
        else if (n == STDIN || n == STDOUT || \
                n == TCP_SOCK || n == UDP_SOCK)
                return 0;
        else {
                log_msg("File type inconsistancy: \
			%s is not a what it's supposed to be", \
                        io_types[n]);
                return(-1);
        }
}

void set_cfg_type(struct io_cfg *iocfg)
{
        int 			n;
	struct iop0_params	*iop0;
	struct iop1_params	*iop1;

	iop0 = LIST_FIRST(&iocfg->iop0_paths);
	n = cnt_secondaries(iop0);

        if (n == 1 && iop0->iop->io_drn == SRC)
                iocfg->cfg_type = TYPE_1;
        if (n == 1 && iop0->iop->io_drn == DST)
                iocfg->cfg_type = TYPE_3;
        else if (n > 1 && iop0->iop->io_drn == SRC)
                iocfg->cfg_type = TYPE_2;
        else if (n > 1 && iop0->iop->io_drn == DST)
                iocfg->cfg_type = TYPE_3;

	iop0->iop->cfgtype_p = &iocfg->cfg_type;
        LIST_FOREACH(iop1, &iop0->io_paths, io_paths)
		iop1->iop->cfgtype_p = &iocfg->cfg_type;
}

T_DATA set_io_dir(char *p)
{               

        if (strncasecmp(p, "dst", 3) == 0) {
                return DST;
	} else if (strncasecmp(p, "src", 3) == 0) {
                return SRC;
	} else {
                log_die("config error: unknow directional %s\n", p);
	}
}

int line_byte_cnt(FILE *f)
{
        int     c;
        int     i = 0;
        long    p;   

        p = ftell(f);

        while ((c = fgetc(f)) != EOF) {
            i++;
            if (c == '\n')
                break; 
        }
                
        if (fseek(f, p, SEEK_SET) != 0)
            log_die("seek error reading config: %s\n", strerror(errno));
                        
        return i;
}

struct io_cfg *io_cfg_alloc(void)
{
	struct io_cfg *iocfg;

	/* IN CONFIG STANZA */
	if ((iocfg = malloc(sizeof(struct io_cfg))) == NULL)
		log_syserr("Failed to malloc io_cfg", errno);

	bzero(iocfg, sizeof(struct io_cfg));
	LIST_INIT(&iocfg->iop0_paths);

	return iocfg;
}

/*int validate_config(struct io_cfg *iocfg) */

struct iop0_params *iop0_alloc(void)
{
	struct iop0_params *iop0;

	if ((iop0 = malloc(sizeof(struct iop0_params))) == NULL)
	    log_syserr("Failed to allocate iop0_param", errno);

	bzero(iop0, sizeof(struct iop0_params));

	LIST_INIT(&iop0->io_paths);

	return iop0;
}

struct iop1_params *iop1_alloc(void)
{
	struct iop1_params *iop1;

	if ((iop1 = malloc(sizeof(struct iop1_params))) == NULL)
	    log_syserr("Failed to allocate iop1_param", errno);

	bzero(iop1, sizeof(struct iop1_params));

	return iop1;
}

struct io_params *iop_alloc(void)
{
	struct io_params *iop;

	if ((iop = malloc(sizeof(struct io_params))) == NULL)
	    log_syserr("Failed to allocate io_param", errno);

	bzero(iop, sizeof(struct io_params));
	iop->path = NULL;
	iop->pipe_cmd = NULL;
	iop->io_fd = -1;
	iop->sock_data = NULL;
	iop->buf_sz = BUFF_SIZE;
	
	return iop;
}

struct sock_param *sock_param_alloc()
{
	struct sock_param *sop;
 
	if ((sop = malloc(sizeof(struct sock_param))) == NULL)
		log_syserr("Failed to malloc sock_param", errno);

	bzero(sop, sizeof(struct sock_param));
	sop->hostname		= NULL;
	sop->sockpath		= NULL;
	sop->ip			= NULL;
	sop->tls_port		= NULL;
	sop->cacert_path	= NULL;
	sop->cacert_dirpath	= NULL;
	sop->host_cert		= NULL;
	sop->host_key		= NULL;
	sop->ssh_cmd		= NULL;
	sop->cert_vrfy		= TRUE;
	sop->listenfd		= -1;

	return sop;
}

void free_iocfg(struct io_cfg *iocfg)
{
	struct iop0_params	*iop0;
	struct iop1_params	*iop1;
	struct io_params	*iop;
	int 	r;

	LIST_FOREACH(iop0, &iocfg->iop0_paths, iop0_paths) {
	    LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
		free_iop(iop1->iop);
	    }
	    free_iop0(iop0);
	}

	while (!LIST_EMPTY(&iocfg->iop0_paths)) {
	    iop0 = LIST_FIRST(&iocfg->iop0_paths);
	    while (!LIST_EMPTY(&iop0->io_paths)) {
		iop1 = LIST_FIRST(&iop0->io_paths);
		LIST_REMOVE(iop1, io_paths);
		free(iop1);
	    }

	    LIST_REMOVE(iop0, iop0_paths);
	    free(iop0);
	}
}

void free_sock_param(struct sock_param *sop)
{
	if (sop->sockpath != NULL)
	    free(sop->sockpath);

	if (sop->hostname != NULL)
	    free(sop->hostname);

	if (sop->ip != NULL)
	    free(sop->ip);

	if (sop->tls_port != NULL)
	    free(sop->tls_port);

	if (sop->cacert_path != NULL)
	    free(sop->cacert_path);

	if (sop->cacert_dirpath != NULL)
	    free(sop->cacert_dirpath);

	if (sop->host_cert != NULL)
	    free(sop->host_cert);

	if (sop->host_key != NULL)
	    free(sop->host_key);

	if (sop->ssh_cmd != NULL)
	    free(sop->ssh_cmd);

	free(sop);
}

void free_iop0(struct iop0_params *iop0)
{
	struct io_params *iop;

	iop = iop0->iop;

        pthread_mutex_destroy(&iop->listlock);
        pthread_cond_destroy(&iop->readable);

	if (*iop0->iop->cfgtype_p == TYPE_3)
	    pthread_mutex_destroy(&iop->fd_lock);

	free_rbuf(iop);  /* XXX WHAT HAPPENS TO OTHER THREADS LOCKED ON RBUFF? */
        free(iop->listready);
        free_iop(iop);
}
	
void free_iop(struct io_params *iop)
{

	if (iop->sock_data != NULL)
		free_sock_param(iop->sock_data);

	if (iop->path != NULL)
	    free(iop->path);

	if (iop->pipe_cmd != NULL)
	    free(iop->pipe_cmd);

	free(iop);
}

int validate_cfg(struct io_cfg *iocfg)
{
	struct iop0_params	*iop0;
	struct iop1_params	*iop1;

	iop0 = LIST_FIRST(&iocfg->iop0_paths);
	validate_iop(iop0->iop);

	LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
	    validate_iop(iop1->iop);
	}
}

void validate_iop(struct io_params *iop)
{
	if (iop->io_type == TCP_SOCK || \
	    iop->io_type == UDP_SOCK || \
	    iop->io_type == UNIX_SOCK) {
	    validate_sockparams(iop);
	}
}

void validate_sockparams(struct io_params *iop)
{
	struct sock_param *sop;
	sop = iop->sock_data;

	if (iop->io_type == TCP_SOCK)
	    sop->sockio == STREAM;
	else if (iop->io_type == UDP_SOCK)
	    sop->sockio == DGRAM;
	else if (iop->io_type == UNIX_SOCK)
	    sop->sockio == STREAM;

	if (sop->conn_type == SRVR) {
	    if (sop->hostname != NULL) {
		log_msg("Config notice: hostnames ignored for server listening sockets\n");
	    }
	    if (is_dst(iop) && iop->io_type == UDP_SOCK) {
		log_die("UDP listening servers can't be destinations\n");
	    }
	} else if (is_netsock(iop) && sop->conn_type == CLIENT) {
	    if (sop->hostname == NULL && sop->ip == NULL)
		log_die("config error: hostname required for sockets\n");
	}

	if (sop->tls == TRUE) {
	    if (sop->conn_type == CLIENT && sop->cacert_path == NULL && sop->cacert_dirpath == NULL)
		log_die("TLS requires a CA cert path CA cert directory\n");

	    if (sop->conn_type == SRVR && sop->host_cert == NULL)
		log_die("Server TLS requires filenames for server's certificate\n");

	    if (sop->conn_type == SRVR && sop->host_key == NULL)
		log_die("Server TLS requires filenames for server's private key\n");

	    if (iop->io_type == UDP_SOCK && sop->tls == TRUE)
		log_die("Config errer: no TLS available for UDP sockets");

	}
}

int compare_io_params(struct io_params *iop1, struct io_params *iop2)
{
	struct sock_param	*sop1, *sop2;

	sop1 = iop1->sock_data;
	sop2 = iop2->sock_data;

	if (iop1->cfgtype_p != iop2->cfgtype_p)
	    return -1;

	if (iop1->io_drn != iop2->io_drn)
	    return -1;

	if (iop1->io_type != iop2->io_type)
	    return -1;

	if (iop1->buf_sz != iop2->buf_sz)
	    return -1;

	if (iop1->nonblock != iop2->nonblock)
	    return -1;

	if (iop1->path != iop2->path)
	    return -1;

	if (iop1->pipe_cmd != iop2->pipe_cmd)
	    return -1;

	/* SOCK DATA. CHECK FOR sock_data DONE BY COMPARING io_types */
	if (sop1->conn_type != sop2->conn_type)
	    return -1;

	if (sop1->sockio != sop2->sockio)
	    return -1;

	if (sop1->hostname != sop2->hostname)
	    return -1;

	if (sop1->ip != sop2->ip)
	    return -1;

	if (sop1->sockpath != sop2->sockpath)
	    return -1;

	if (sop1->port != sop2->port)
	    return -1;

	if (sop1->ssh_cmd != sop2->ssh_cmd)
	    return -1;

	/* TLS options */
	if (sop1->tls == sop2->tls && sop1->tls == TRUE)
	    return -1;

	if (sop1->cacert_path != sop2->cacert_path)
	    return -1;

	if (sop1->cacert_dirpath != sop2->cacert_dirpath)
	    return -1;

	if (sop1->cert_vrfy != sop2->cert_vrfy)
	    return -1;

	if (sop1->host_cert != sop2->host_cert)
	    return -1;

	if (sop1->host_key != sop2->host_key)
	    return -1;

	/* FALL THROUGH */
	return 0;
}

int cnt_secondaries(struct iop0_params *iop0)
{
        int 			n;
	struct iop1_params	*iop1;

	n = 0;
        LIST_FOREACH(iop1, &iop0->io_paths, io_paths) {
	    n++;
	}
	return n;
}

struct iop0_params *compare_iop0(struct io_cfg *iocfg, struct io_cfg *new_iocfg)
{
	struct iop0_params	*iop0, *newiop0;
	struct io_params	*iop, *newiop;

	iop0 = LIST_FIRST(&iocfg->iop0_paths);
	newiop0 = LIST_FIRST(&new_iocfg->iop0_paths);

	if (compare_io_params(iop0->iop, newiop0->iop) != 0)
	    return NULL;

	if (cnt_secondaries(iop0) != cnt_secondaries(newiop0))
	    return NULL;

	/* FALL THROUGH */
	return iop0;
}
