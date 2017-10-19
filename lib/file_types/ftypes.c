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

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ftypes.h"

int open_fifo(struct io_params *iop)
{	
	struct stat	s;
	int		fd;
	int		oflags;
	int		perms;

	oflags = set_flags(iop);
	perms = S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH;

	if (stat(iop->path, &s) < 0) {
	    if (errno == ENOENT)
		if (mkfifo(iop->path, perms) < 0)
		    log_syserr("mkfifo(2) error %s.\n", iop->path);
		else
		    log_syserr("stat(2) error: %s", iop->path);
	}

	for (;;) {
	    if ((fd = open(iop->path, oflags)) < 0) {
		if (errno == ENXIO) {
		    log_ret("Destination %s FIFO not writable without reader", iop->path);
		    sleep(10);
		    continue;
		} else
		    log_syserr("open(2) error - %s", iop->path);
	    } else 
		break;
	}
	return fd;
}
		
int open_file(struct io_params *iop)
{	
	struct stat	s;
	int		fd;
	int 		oflags;
	int		perms;

	oflags = set_flags(iop);
	perms =  S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH;

	if (stat(iop->path, &s) < 0) { 
	    if (errno == ENOENT) {
		oflags |= O_CREAT;
		if ((fd = open(iop->path, oflags, perms)) < 0 )
		    log_syserr("oper(2) error for %s", iop->path);
	    } else {
		    log_syserr("stat(2) error for %s", iop->path);
	    }	
	} else {
	    if ((fd = open(iop->path, oflags)) < 0)
		log_syserr("oper(2) error for %s\n", iop->path);
	}

	if (lseek(fd, 0, SEEK_END) < 0)
		printf("lseek error: %s\n", strerror(errno));

	return fd;
}
		
int open_unixsock(char *n)
{	
	return 0;
}

int open_tcpsock(struct io_params *iop)
{
	return 0;
}

int open_udpsock(struct io_params *iop)
{
	return 0;
}

int set_flags(struct io_params *iop)
{
	int f;

	if (is_src(iop))
		f = O_RDONLY;
	else	
		f = O_WRONLY;

	if (iop->nonblock == TRUE)
		f |= O_NONBLOCK;

	return f;
}

		
/*
*int open_local_desc(char *n, int t) {	
*
*	
*	  PASSED A CONFIG PATHNAME AND
*	  TYPE AS ARG. OPEN APPROPRIATE
*	  FILE TYPE
*
*
*	if (t == STDOUT) {
*		return STDOUT_FILENO;
*
*	} else if (t == FIFO) {
*		return open_fifo(n);
*
*	} else if (t == REG_FILE) {
*		return open_file(n);
*			
*	} else if (t == UNIX_SOCK) {
*		printf("is sockct\n");
*	} else { 
*		printf("can't us file type\n");
*		return -1;
*	}	
*}
*/
