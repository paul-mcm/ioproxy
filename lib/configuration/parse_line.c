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

#include "parse_line.h"

#define SIZE 256

int type;	/* XXX WHAT'S THIS??? */

int parse_line(char * ln, struct io_params *i)
{
	/* FOUR ERRORS:
	 * 1. LINE ISN'T TERMINATED W/ ';'
	 * 2. LINE DOESN'T CONTAIN FIELD/VAL SEPARATOR ':'
	 * 3. LINE HAS INCONSISTANT DIRECTION (src/dst)
	 * 4. FIELD OR VALUE HAS BLANK SPACE BEFORE 
	 *    TERMINATING ';' or ':' CHAR.
	 */

	char *pr, *field, *val;
	int r;

	/* LINE NOT TERMINATED BY ';' IS A CONFIG ERROR */
	if (strncmp(&ln[strlen(ln) - 1], ";", 1) != 0 ) {
		printf("missing ';' at end of line\n");
		return(-1);
	}

	while ((pr = strsep(&ln, ";")) != NULL) {
  		field = strsep(&pr, ":");
		val = pr;

		/* FAILURE TO FIND ':' MEANS CONFIG ERROR */
		if(val == '\0') {
			printf("config error - missing ':' %s\n", ln);
			return(-1);
		}

		/* CONFIG ERR IF VAL/FIELD END W/ BLANK SPACE */
		if (isblank(val[strlen(val) - 1]) != 0) {
			printf("blankspace error: ->%s<-\n", val);
			return(-1);
		}

		if (isblank(field[strlen(field) - 1]) != 0) {
			printf("blankspace error: ->%s<-\n", field);
			return(-1);
		}

		field = rm_space(field);
		val = rm_space(val);

		if ((r = fill(field, val, i)) < 0)
			log_die("Fill Error: %s %s\n", field, val);

		/* BREAK IF NOTHING LEFT IN LINE */		
		if(ln[0] == '\0')
			break;
	}

	return 0;
}

int fill(char *f, char *v, struct io_params *i)
{
	int err = 0;
	char	*s;

	if ( strcasecmp((f + 4) , "type") == 0 ) {
		/* XXX DOESN'T CHECK FOR ERROR */
 		if (set_desc_t(v, i) != 0) {
			printf("Error setting type\n");
			exit(-1);
		}
		
		if (is_sock(i)) {
			if ((i->sock_data = malloc(sizeof(struct sock_param))) == NULL) {
				printf("Malloc failure: %s\n", strerror(errno));
				exit(-1);
			}
			bzero(i->sock_data, sizeof(struct sock_param));
		}

	} else if (strcasecmp((f + 4), "path") == 0 ) {
		i->path = malloc(256);
		strncpy(i->path, v, 256);

	} else if (strcasecmp((f + 4), "sockpath") == 0 ) {
		i->sock_data->sockpath = malloc(256);
		strncpy(i->sock_data->sockpath, v, 256);
		i->path = malloc(256);
		strncpy(i->path, v, 256);

	} else if (strcasecmp((f + 4), "host") == 0 ) {

		if ((i->sock_data->hostname = malloc(256)) == NULL) {
			printf("malloc failure: %s\n", strerror(errno));
			exit(-1);
		}
		strncpy(i->sock_data->hostname, v, 256);

		/* XXX MUST FIX */
	} else if (strcasecmp((f + 4), "ip") == 0 ) {
		i->sock_data->ip = malloc(256);
		strncpy(i->sock_data->ip, v, 256);

	} else if (strcasecmp((f + 4), "conn") == 0 ) {
		err = set_conn(v, i);
	} else if (strcasecmp((f + 4), "proto") == 0 ) {
		err = set_sockio(v, i);
	} else if (strcasecmp((f + 4), "nonblock") == 0) {
		err = set_nonblock(v, i);
 	} else if (strcasecmp((f + 4), "port") == 0 ) {
		i->sock_data->port = atoi(v);
	} else {
		log_msg("unknown value: %s %s\n", f, v);
		err = -1;
	}

	return(err);
}

int set_nonblock(char *t, struct io_params *iop)
{
	if (strcasecmp(t, "TRUE") == 0)
		iop->nonblock = TRUE;
	else if (strcasecmp(t, "FALSE") == 0)
		iop->nonblock = FALSE;
	else
		return (-1);

	return(0);
}
int set_conn(char *t, struct io_params *p) 
{	
	int err = 0;

        if ( strcasecmp(t, "CONNECT") == 0 ) {
                p->sock_data->conn_type = CONNECT;

        } else if ( strcasecmp(t, "LISTEN") == 0 ) {
		p->sock_data->conn_type = LISTEN;

        } else {
                printf("unknown connection type: %s\n", t);
                err = -1;
        }

	return err;

}

int set_sockio(char *t, struct io_params *p)
{	
	int err = 0;

        if ( strcasecmp(t, "DGRAM") == 0 ) {
         	p->sock_data->sockio = DGRAM;

        } else if ( strcasecmp(t, "STREAM") == 0 ) {
		p->sock_data->sockio = STREAM;

        } else {
                printf("unknown proto: %s\n", t);
                err -1;
        }

	return err; 
}	

int set_desc_t(char * t, struct io_params *p)
{
	int err = 0;

	if ( strcasecmp(t, "FIFO") == 0 ) {
		p->desc_type = FIFO;

	} else if ( strcasecmp(t, "FILE") == 0 ) {
		p->desc_type = REG_FILE;

	} else if ( strcasecmp(t, "STDIN") == 0 ) {
		p->desc_type = STDIN;

        } else if ( strcasecmp(t, "STDOUT") == 0 ) {
		p->desc_type = STDOUT;

        } else if ( strcasecmp(t, "TCP_SOCK") == 0 ) {
		p->desc_type = TCP_SOCK;

        } else if ( strcasecmp(t, "UDP_SOCK") == 0 ) {
		p->desc_type = UDP_SOCK;

	} else if ( strcasecmp(t, "UNIX_SOCK") == 0 ) {
		p->desc_type = UNIX_SOCK;
	} else {
		printf("unknown type: %s\n", t);
		err -1;
	}
	return err;
}

char * clean_line(char *s)
{	 
	s = rm_end_space(s);

	return rm_space(s);
}

char *
rm_end_space(char *l)
{
	while ( strncmp( &l[ strlen(l) - 1 ], "\n", 1) == 0 || \
                isblank( l[ strlen(l) - 1 ]) ) {

                l[ strlen(l) - 1 ] = '\0';
        }
	return l;
}

char *   
rm_space(char *s)
{
        while (isblank(s[0]) != 0)
            s++;
        return s;
}        

T_DATA set_io_type(char *p)
{
	if (strncasecmp(p, "dst", 3) == 0) {
		return DST;
	} else if (strncasecmp(p, "src", 3) == 0) {
		return SRC;
	} else {
		printf("config error: unknow directional\n");
	}
}

int check_line(char * l)
{
        if (strncmp(l, "#", 1) == 0 )
                return 1;

        if (strlen(l) == 0)
                return 1;
        
        return 0;
}
