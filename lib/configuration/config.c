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

const char *desc_types[] = { "REG_FILE", "FIFO", "STDOUT", "STDIN", "UNIX_SOCK", "TCP_SOCK", "UDP_SOCK"};
const char *io_drn[] = { "SRC", "DST" };
const char *io_types[] = {"TYPE_1", "TYPE_2", "TYPE_3"};
const char *conn_type[] = { "CONNECT", "LISTEN" };
const char *sockio[] = { "DGRAM", "STREAM" };
const char *cert_strtgy[] = {"DEMAND", "NEVER", "TRY", "ALLOW"};

int read_config(struct all_cfg_list *all)
{
        FILE *fp;
        char ln[SIZE];
        char *p;
	struct io_cfg *iocfg;

        if ((fp = fopen("./ioproxy.conf", "r")) == NULL)  {
		log_syserr("fopen error: ");
	}

        /* FIND BEGIN OF CONFIG STANZA BY IGNORING STUFF UNTIL "{" IS FOUND */
        while (fgets(ln, SIZE, fp) != NULL) {
                p = ln;
                if (strncmp(p, "{", 1) == 0) {
                        fseek(fp, -(strlen(p) - 1), SEEK_CUR);
                        iocfg = parse_config(fp); 
			set_io_type(iocfg);

                        LIST_INSERT_HEAD(all, iocfg, io_cfgs);
		}

                if (feof(fp) != 0)
                        break;
        }
	fclose(fp);
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
			fseek(fp, -(strlen(p)), SEEK_CUR);
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

	if ((ln = fetch_next_line(f)) != NULL) {
		p = clean_line(ln);
	} else {
		log_msg("fetch_next_line() returned NULL\n");
	}

	fseek(f, -strlen(ln), SEEK_CUR);
	free(ln);

        while ((ln = fetch_next_line(f)) != NULL) {
		p = clean_line(ln);
		/* '(' character signals end of stanza */
                if (strncmp(p, "(", 1) == 0) {
                        fseek(f, -(strlen(ln) - 1), SEEK_CUR);
                        break;
                }

		if ((r = parse_line(p, iop0->iop)) < 0) {
			log_msg("Error parsing line\n");
			free(ln);
			return NULL;
		}
	}

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

int is_sock(int n)
{
        if ((n == UDP_SOCK) || \
	    (n == TCP_SOCK) || \
	    (n == UNIX_SOCK)) 
                return 1; 
        else 
                return 0; 
}

int is_netsock(int n)
{
        if ((n == UDP_SOCK) || \
	    (n == TCP_SOCK))
                return 1; 
        else 
                return 0; 
}

int show_config(struct io_cfg *iocfg)
{
	struct iop0_params *iop0;
	struct iop1_params *iop1;

	log_msg("========= START CONFIG ==========\n");
	log_msg("io_type\t\t%s\n", io_types[iocfg->io_type]);

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
	struct sock_param *sp;

	printf("type_p\t\t%s\n", io_types[*iop->type_p]);
	printf("io_drn:\t\t%s\n", io_drn[iop->io_drn]);
	printf("desc_type:\t\t%s\n", desc_types[iop->desc_type]);
	printf("rbuf_p addr: %p\n", iop->rbuf_p);
	printf("io_fd ptr: %p\n", iop->io_fd);
	printf("fd_lock ptr: %p\n", iop->fd_lock);
	printf("buf_sz: %d\n", iop->buf_sz);

/*	printf("readable addr: %p\n", iop->readable);
*	printf("listlock addr: %p\n", iop->listlock);
*	printf("listready addr: %p\n", iop->listready);
*/
	printf("nonblock: %d\n", iop->nonblock);
	printf("io_fd: %d\n", iop->io_fd);

	if (is_sock(iop->desc_type)) {
		sp = iop->sock_data;

		printf("conn_type: %s\n", 	conn_type[sp->conn_type]);
		printf("sockio: %s\n", 		sockio[sp->sockio]);
		printf("ip: %s\n", 		sp->ip != 0 ? sp->ip : NULL);
		printf("port: %s\n", 		sp->port != 0 ? sp->port : 0);
		if (iop->sock_data->hostname != NULL)
			printf("hostname: %s\n", sp->hostname);

		if (sp->sockpath != NULL)
			printf("sockpath: %s\n", sp->sockpath);
		if (sp->tls == TRUE) {
		    printf("tls = TRUE\n");
		    if (sp->cacert_path != NULL)
			printf("cacertpath: %s\n", sp->cacert_path);
		    if (sp->cacert_dirpath != NULL)
			printf("cacertdir: %s\n", sp->cacert_dirpath);
		    printf("cert_strtgy: %s\n", cert_strtgy[sp->cert_strtgy]);
		}
	}

	printf("path: %s\n", iop->path != NULL ? iop->path : NULL);	
}

int valid_path(char *p, struct stat *s) 
{
        int error = 0;

        if (stat(p, s) != 0)
                error = -1; 

        return error;
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
                        desc_types[n]);
                return(-1);
        }
}

void set_io_type(struct io_cfg *iocfg)
{
        int 			n;
	struct iop0_params	*iop0;
	struct iop1_params	*iop1;

	iop0 = LIST_FIRST(&iocfg->iop0_paths);
        LIST_FOREACH(iop1, &iop0->io_paths, io_paths)
                n++;

        if (n == 1 && iop0->iop->io_drn == SRC)
                iocfg->io_type = TYPE_1;
        if (n == 1 && iop0->iop->io_drn == DST)
                iocfg->io_type = TYPE_3;
        else if (n > 1 && iop0->iop->io_drn == SRC)
                iocfg->io_type = TYPE_2;
        else if (n > 1 && iop0->iop->io_drn == DST)
                iocfg->io_type = TYPE_3;

	iop0->iop->type_p = &iocfg->io_type;
        LIST_FOREACH(iop1, &iop0->io_paths, io_paths)
		iop1->iop->type_p = &iocfg->io_type;

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
	iop->io_fd = -1;
	iop->sock_data = NULL;
	iop->buf_sz = BUFF_SIZE;
	
	return iop;
}


struct sock_param *sock_param_alloc()
{
	struct sock_param *sd;
 
	if ((sd = malloc(sizeof(struct sock_param))) == NULL)
		log_syserr("Failed to malloc sock_param", errno);

	bzero(sd, sizeof(struct sock_param));
	sd->hostname	= NULL;
	sd->sockpath	= NULL;
	sd->ip		= NULL;

	return sd;
}

void free_sock_param(struct sock_param *sd)
{
	if (sd->hostname != NULL)
		free(sd->hostname);

	if (sd->sockpath != NULL)
		free(sd->sockpath);

	if (sd->ip != NULL)
		free(sd->ip);

	free(sd);
}


void free_iop0(struct iop0_params *iop0)
{
	struct io_params *iop;

	iop = iop0->iop;
        pthread_mutex_destroy(&iop->listlock);
        pthread_cond_destroy(&iop->readable);
	pthread_mutex_destroy(&iop->fd_lock);

	free_rbuf(iop->rbuf_p);  /* XXX WHAT HAPPENS TO OTHER THREADS LOCKED ON RBUFF? */
        free(iop->listready);  /* XXX WHY IS THIS MALLOC'D? */
        free_iop(iop);
}
	
void free_iop(struct io_params *iop)
{
	struct sock_param 	*s_iop;

	if (iop->sock_data != NULL)
		free_sock_param(iop->sock_data);

	free(iop->path);
	free(iop);
}

int validate_iop(struct io_params *iop)
{

	if (iop->desc_type == UDP_SOCK && iop->sock_data->conn_type == LISTEN)
	   log_die("Config error: No udp listening sockets");

}
