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

#include "config.h"
#include "parse_line.h"

const char *desc_types[] = { "REG_FILE", "FIFO", "STDOUT", "STDIN", "UNIX_SOCK", "TCP_SOCK", "UDP_SOCK"};
const char *io_drn[] = { "SRC", "DST" };
const char *conn_type[] = { "CONNECT", "LISTEN" };
const char *sockio[] = { "DGRAM", "STREAM" };

int read_config(struct all_cfg_list *all)
{
        FILE *fp;
        char ln[SIZE];
        char *p;
        struct io_params *iop_p;
	struct io_cfg *io_cfg_p;

        if ((fp = fopen("./input", "r")) == NULL)  {
		printf("fopen error: %s\n", strerror(errno));
		exit(-1);
	}

        /* FIND BEGIN OF CONFIG STANZA BY IGNORING STUFF UNTIL "{" IS FOUND */
        while (fgets(ln, SIZE, fp) != NULL) {
                p = ln;
                if (strncmp(p, "{", 1) == 0) {
                        p++;

                        fseek(fp, -(strlen(p) - 1), SEEK_CUR);
                        io_cfg_p = parse_config(fp); 

                        LIST_INSERT_HEAD(all, io_cfg_p, io_cfgs);
		}

                if (feof(fp) != 0)
                        break;
        }
}

struct io_cfg * parse_config(FILE *fp)
{
        char ln[SIZE];
        char *p;
	struct io_cfg *io_cfg_p;
	struct io_params *iop, *iop_p;
	int r;
                
	/* IN CONFIG STANZA */
	io_cfg_p = malloc(sizeof(struct io_cfg));
	LIST_INIT(&io_cfg_p->io_paths);

	if ((io_cfg_p->io_p = parse_cfg_stanza(fp)) == NULL) {
		printf("parse_cfg_stanza error\n");
		exit(-1);
	}

	for (;;) {				
		if ((iop_p = parse_io_cfg(fp)) != NULL) {
			iop_p->readable = io_cfg_p->io_p->readable;
			iop_p->listlock = io_cfg_p->io_p->listlock;
			iop_p->listready = io_cfg_p->io_p->listready;
		
			/* PUT iop_p ON LIST */
 			LIST_INSERT_HEAD(&io_cfg_p->io_paths, iop_p, io_entries);

		} else {
			printf("Error\n");
			return NULL;
		}

		/* read next line until readable line */	

		while (fgets(ln, SIZE, fp) != NULL) {
                	p = clean_line(ln);

	                /* IF COMMENT -> CONTINUE ....*/
        	        if (check_line(p) != 0) {
                	        continue;
			} else {
				break;
			}
		}

		if (strncmp(p, "(", 1) == 0) {
			p++;
			fseek(fp, -(strlen(p)), SEEK_CUR);
			continue;
		} else if (strncmp(p, "}", 1) == 0) {
			break;
                }
        }

	return io_cfg_p;
}

struct io_params * parse_cfg_stanza(FILE *f)
{
        char ln[SIZE];
        char *p = ln;
        int r;

	struct io_params *i = malloc(sizeof(struct io_params));
	bzero(i, sizeof(struct io_params));
	pthread_cond_init(&i->readable, NULL);
	pthread_mutex_init(&i->listlock, NULL);
	i->listready = malloc(sizeof(int));
	*i->listready = 0;

        while (fgets(ln, SIZE, f) != NULL) {
                p = rm_space(ln);

		/* '(' character signals end of stanza */
                if (strncmp(p, "(", 1) == 0) {
			p++;
                        fseek(f, -(strlen(p) - 1), SEEK_CUR);
                        break;
                }

		p = clean_line(ln);

                /* IF COMMENT -> CONTINUE ....*/
                if (check_line(p) != 0)
                        continue;

		i->io_drn = set_io_type(p);

		if ((r = parse_line(p, i)) < 0 ) {
			printf("Error parsing line\n");
			return NULL;
		}
	}

	return i;
} 

struct io_params * parse_io_cfg(FILE *f)
{
	char ln[SIZE];
	char *p = ln;
	int r;
	int last = 0;

	struct io_params *i = malloc(sizeof(struct io_params));
	bzero(i, sizeof(struct io_params));

	while (fgets(ln, SIZE, f) != NULL) {
                p = clean_line(ln);
		
		/* IF COMMENT -> CONTINUE ....*/
		if (check_line(p) != 0)
			continue;

                if (strncmp(p, ")", 1) == 0)
                	break;

		i->io_drn = set_io_type(p);

		if (strncmp(&p[ strlen(p) - 1 ], ")", 1) == 0 ) {
			last = 1;
			p[ strlen(p) - 1 ] = '\0';
			p = rm_end_space(p);
		}

                if ((r = parse_line(p, i)) < 0 ) {
                        printf("Error parsing line\n");
                        return NULL;
                } 
			
		if (last)
			break;			
	}	

	return i;
}

int show_config(struct io_cfg *cfg)
{
        struct io_params *iop_p;        

        printf("========= START CONFIG ==========\n");
        print_config_params(cfg->io_p);

        LIST_FOREACH(iop_p, &cfg->io_paths, io_entries) {
                printf("-------- iopath -------\n");
                print_config_params(iop_p);
        }

        printf("\n\n");
}

int show_all_configs(struct all_cfg_list *all)
{
        struct io_cfg *ip;

        LIST_FOREACH(ip, all, io_cfgs) { 
                show_config(ip);

        }
}

int is_dst(struct io_params *ip)
{
	if (ip->io_drn == DST)
		return 1;
	else
		return 0;
}

int is_src(struct io_params *ip)
{
	if (ip->io_drn == SRC)
		return 1;
	else
		return 0;
}

int is_sock(struct io_params *ip)
{
        if ((ip->desc_type == UDP_SOCK) || \
	    (ip->desc_type == TCP_SOCK) || \
	    (ip->desc_type == UNIX_SOCK)) 
                return 1; 
        else 
                return 0; 
}

int is_netsock(struct io_params *ip)
{
        if ((ip->desc_type == UDP_SOCK) || \
	    (ip->desc_type == TCP_SOCK))
                return 1; 
        else 
                return 0; 
}

void print_config_params(struct io_params *i)
{
	printf("io_drn:\t\t%s\n", io_drn[i->io_drn]);
	printf("desc_type:\t\t%s\n", desc_types[i->desc_type]);
	printf("rbuf_p addr: %p\n", i->rbuf_p);
	printf("readable addr: %p\n", i->readable);
	printf("listlock addr: %p\n", i->listlock);
	printf("listready addr: %p\n", i->listready);
	printf("nonblock: %d\n", i->nonblock);

	if (is_sock(i)) {
		printf("conn_type: %s\n", 	conn_type[i->sock_data->conn_type]);
		printf("sockio: %s\n", 		sockio[i->sock_data->sockio]);
		printf("ip: %d\n", 		i->sock_data->ip != 0 ? i->sock_data->ip : 0);
		printf("port: %d\n", 		i->sock_data->port != 0 ? i->sock_data->port : 0);
		printf("hostname: %s\n", 	i->sock_data->hostname != NULL ? i->sock_data->hostname : 0);
		printf("path: %s\n", 		i->sock_data->sockpath != NULL ? i->sock_data->sockpath : 0);
	} else 
		printf("path: %s\n", 		i->path != NULL ? i->path : 0);	
}

int valid_path(char *p, struct stat *s) 
{
        int error = 0;

        if (stat(p, s) != 0) {
/*                log_ret("stat error: %s %s\n", p, strerror(errno)); */
                error = -1; 
        }

        return error;
}

int valid_ftype(struct io_params *iop, struct stat *s)
{
        if (iop->desc_type == REG_FILE && S_ISREG(s->st_mode))
                return 0;
        else if (iop->desc_type == FIFO && S_ISFIFO(s->st_mode))
                return 0;
        else if (iop->desc_type == UNIX_SOCK && S_ISSOCK(s->st_mode))
                return 0;
        /* THESE TYPES DON'T MATTER; DON'T ERRONEOUSLY SUGGEST ERROR */
        else if (iop->desc_type == STDIN || iop->desc_type == STDOUT || \
                iop->desc_type == TCP_SOCK || iop->desc_type == UDP_SOCK)
                return 0;
        else {
                log_msg("File type inconsistancy: %s is not a %s", iop->path, \
                        desc_types[iop->desc_type]);
                return(-1);
        }
}

/*int validate_config(struct io_cfg *iocfg) */
