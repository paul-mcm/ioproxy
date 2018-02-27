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
	struct sock_param	*sop;
	int			vlen, err;
	const char 		*s;

	err = 0;
	vlen = strlen(v);
	sop = iop->sock_data;

	if ( strcasecmp(f, "type") == 0 ) {
	    /* XXX DOESN'T CHECK FOR ERROR */
	    if (set_desc_t(v, iop) != 0) {
		log_die("Error setting type\n");
	    }
	    if (is_sock(iop)) {
		iop->sock_data = sock_param_alloc();
		sop = iop->sock_data;
	    }
	    if (iop->desc_type == TCP_SOCK) {
		sop->sockio = STREAM;
	    } else if (is_sock(iop) && iop->desc_type != TCP_SOCK) {
		sop->sockio = DGRAM;
	    }
	} else if (strcasecmp(f, "dir") == 0) {
	    if (strcasecmp(v, "src") == 0)
		iop->io_drn = SRC;
	    else if (strcasecmp(v, "dst") == 0)
		iop->io_drn = DST;
	    else 
		log_die("Invalid config directive: %s: %s;\n", f, v);
	} else if (strcasecmp(f, "path") == 0 ) {
		iop->path = malloc(vlen + 1);
		strncpy(iop->path, v, vlen + 1);
	} else if (strcasecmp(f, "sockpath") == 0 ) {
		iop->path = malloc(vlen + 1);
		strncpy(iop->path, v, 256);
		sop->sockpath = iop->path;
	} else if (strcasecmp(f, "host") == 0) {
		if ((sop->hostname = malloc(vlen + 1)) == NULL)
			log_syserr("malloc failure: ");
		strlcpy(sop->hostname, v, vlen + 1);
		/* XXX MUST FIX */
	} else if (strcasecmp(f, "ip") == 0) {
		sop->ip = malloc(vlen + 1);
		strncpy(sop->ip, v, vlen + 1);
	} else if (strcasecmp(f, "conn") == 0)
		err = set_conn(v, iop);
	else if (strcasecmp(f, "proto") == 0)
		err = set_sockio(v, iop);
	else if (strcasecmp(f, "nonblock") == 0)
		err = set_nonblock(v, iop);
 	else if (strcasecmp(f, "port") == 0) {
		sop->tls_port = malloc(vlen + 1);
		strncpy(sop->tls_port, v, vlen + 1);
		sop->port = strtonum(v, 1, 65535, &s);
		if (s != NULL)
		    log_syserr("strtonum() error: %s\n", s);
	} else if (strcasecmp(f, "tls") == 0)
		sop->tls = TRUE;
	else if (strcasecmp(f, "cacert") == 0) {
		sop->cacert_path = malloc(vlen + 1);
		strncpy(sop->cacert_path, v, vlen + 1);
	} else if (strcasecmp(f, "cacertdir") == 0) {
		sop->cacert_dirpath = malloc(vlen + 1);
		strncpy(sop->cacert_dirpath, v, vlen);
	} else if (strcasecmp(f, "srvr_cert") == 0) {
		sop->srvr_cert = malloc(vlen + 1);
		strlcpy(sop->srvr_cert, v, vlen + 1);
	} else if (strcasecmp(f, "srvr_key") == 0) {
		sop->srvr_key = malloc(vlen + 1);
		strlcpy(sop->srvr_key, v, vlen + 1);
	} else if (strcasecmp(f, "cmd") == 0) {
		sop->ssh_cmd = malloc(vlen + 1);
		strlcpy(sop->ssh_cmd, v, vlen + 1);
	} else if (strcasecmp(f, "reqcrt") == 0) {
		if (strcasecmp(v, "true") == 0)
		    sop->cert_vrfy = TRUE;
		else if (strcasecmp(v, "false") == 0)
		    sop->cert_vrfy = FALSE;
		else
		    log_die("Bad value for 'reqcrt' param");
	} else if (strcasecmp(f, "bufsz") == 0) {
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

        if (strcasecmp(t, "CLIENT") == 0)
		iop->sock_data->conn_type = CLIENT;
        else if (strcasecmp(t, "SERVER") == 0)
		iop->sock_data->conn_type = SRVR;
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
	else if (strcasecmp(t, "TCP_SOCK") == 0) {
	    iop->desc_type = TCP_SOCK;
	} else if (strcasecmp(t, "UDP_SOCK") == 0) {
	    iop->desc_type = UDP_SOCK;
	} else if (strcasecmp(t, "UNIX_SOCK") == 0) {
	    iop->desc_type = UNIX_SOCK;
	} else if (strcasecmp(t, "SSH") == 0) {
	    iop->desc_type = SSH;
	} else {
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
