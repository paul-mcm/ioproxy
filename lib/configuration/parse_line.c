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

#include "parse_line.h"

#define SIZE 256

int parse_line(char * ln, struct io_params *iop)
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
	if (strncmp(&ln[strlen(ln) - 1], ";", 1) != 0 )
		log_die("missing ';' at end of line: %s\n", ln);

	while ((pr = strsep(&ln, ";")) != NULL) {
  		field = strsep(&pr, ":");
		val = pr;

		/* FAILURE TO FIND ':' MEANS CONFIG ERROR */
		if(val == '\0')
			log_die("config error - missing ':' %s\n", ln);

		/* CONFIG ERR IF VAL/FIELD END W/ BLANK SPACE */
		if (isblank(val[strlen(val) - 1]) != 0)
			log_die("blankspace error: ->%s<-\n", val);

		if (isblank(field[strlen(field) - 1]) != 0)
			log_die("blankspace error: ->%s<-\n", field);

		field = rm_space(field);
		val = rm_space(val);

		if ((r = fill(field, val, iop)) < 0)
			log_die("Fill Error: %s %s\n", field, val);

		/* BREAK IF NOTHING LEFT IN LINE */		
		if(ln[0] == '\0')
			break;
	}

	return 0;
}

int fill(char *f, char *v, struct io_params *iop)
{
	int err = 0;
	const char *s;

	if ( strcasecmp((f + 4) , "type") == 0 ) {
	    /* XXX DOESN'T CHECK FOR ERROR */
	    if (set_desc_t(v, iop) != 0)
		log_die("Error setting type\n");
		
	    if (is_sock(iop->desc_type))
		iop->sock_data = sock_param_alloc();

	} else if (strcasecmp((f + 4), "path") == 0 ) {
		iop->path = malloc(256);
		strncpy(iop->path, v, 256);

	} else if (strcasecmp((f + 4), "sockpath") == 0 ) {
		iop->path = malloc(256);
		strncpy(iop->path, v, 256);
		iop->sock_data->sockpath = iop->path;
	} else if (strcasecmp((f + 4), "host") == 0) {
		if ((iop->sock_data->hostname = malloc(256)) == NULL)
			log_syserr("malloc failure: ");

		strncpy(iop->sock_data->hostname, v, 256);
		/* XXX MUST FIX */
	} else if (strcasecmp((f + 4), "ip") == 0) {
		iop->sock_data->ip = malloc(256);
		strncpy(iop->sock_data->ip, v, 256);

	} else if (strcasecmp((f + 4), "conn") == 0)
		err = set_conn(v, iop);
	else if (strcasecmp((f + 4), "proto") == 0)
		err = set_sockio(v, iop);
	else if (strcasecmp((f + 4), "nonblock") == 0)
		err = set_nonblock(v, iop);
 	else if (strcasecmp((f + 4), "port") == 0) {
		iop->sock_data->port = malloc(strlen(v) + 1);
		strncpy(iop->sock_data->port, v, strlen(v) + 1);
	} else if (strcasecmp((f + 4), "tls") == 0)
		iop->sock_data->tls = TRUE;
	else if (strcasecmp((f + 4), "cacert") == 0) {
		iop->sock_data->cacert_path = malloc(strlen(v) + 1);
		strncpy(iop->sock_data->cacert_path, v, strlen(v));
	} else if (strcasecmp((f + 4), "cacertdir") == 0) {
		iop->sock_data->cacert_dirpath = malloc(strlen(v) + 1);
		strncpy(iop->sock_data->cacert_dirpath, v, strlen(v));
	} else if (strcasecmp((f + 4), "reqcrt") == 0) {
		if (strcasecmp(v, "demand") == 0)
		    iop->sock_data->cert_strtgy = DEMAND;
		else if (strcasecmp(v, "never") == 0)
		    iop->sock_data->cert_strtgy = NEVER;
		else if (strcasecmp(v, "try") == 0)
		    iop->sock_data->cert_strtgy = TRY;
		else if (strcasecmp(v, "allow") == 0)
		    iop->sock_data->cert_strtgy = ALLOW;
		else
		    log_die("Bad value for 'reqcrt' param");
	} else if (strcasecmp((f + 4), "bufsz") == 0) {
		iop->buf_sz = strtonum(v, 1, 16384, &s);
		if (s != NULL) {
		    log_die("bufsz value error: %s\n", s);
		}
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

int set_conn(char *t, struct io_params *iop) 
{	
	int err = 0;

        if (strcasecmp(t, "CONNECT") == 0)
		iop->sock_data->conn_type = CONNECT;
        else if (strcasecmp(t, "LISTEN") == 0)
		iop->sock_data->conn_type = LISTEN;
        else {
                log_msg("unknown connection type: %s\n", t);
                err = -1;
        }

	return err;

}

int set_sockio(char *t, struct io_params *iop)
{	
	int err = 0;

        if (strcasecmp(t, "DGRAM") == 0)
         	iop->sock_data->sockio = DGRAM;
        else if (strcasecmp(t, "STREAM") == 0)
		iop->sock_data->sockio = STREAM;
        else {
                log_msg("unknown proto: %s\n", t);
                err -1;
        }

	return err; 
}	

int set_desc_t(char *t, struct io_params *iop)
{
	int err = 0;

	if (strcasecmp(t, "FIFO") == 0)
		iop->desc_type = FIFO;
	else if (strcasecmp(t, "FILE") == 0)
		iop->desc_type = REG_FILE;
	else if (strcasecmp(t, "STDIN") == 0)
		iop->desc_type = STDIN;
        else if (strcasecmp(t, "STDOUT") == 0)
		iop->desc_type = STDOUT;
        else if (strcasecmp(t, "TCP_SOCK") == 0)
		iop->desc_type = TCP_SOCK;
        else if (strcasecmp(t, "UDP_SOCK") == 0)
		iop->desc_type = UDP_SOCK;
	else if (strcasecmp(t, "UNIX_SOCK") == 0)
		iop->desc_type = UNIX_SOCK;
	else {
		log_msg("unknown type: %s\n", t);
		err = -1;
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
                isblank(l[ strlen(l) - 1 ])) {
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

int check_line(char *l)
{
        if (strncmp(l, "#", 1) == 0)
                return 1;

        if (strncmp(l, "\n", 1) == 0)
                return 1;
	
        if (strlen(l) == 0)
                return 1;
        
        return 0;
}
