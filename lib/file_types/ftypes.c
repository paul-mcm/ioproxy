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

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "ftypes.h"

#define SA struct sockaddr
#define LISTENQ 1

int open_desc(struct io_params *iop)
{
	int fd;

	fd = -1;

	for (;;) {
	    if (iop->desc_type == FIFO) {
		fd = open_fifo(iop);
	    } else if (iop->desc_type == REG_FILE) {
		fd = open_file(iop);
	    } else if (iop->desc_type == UNIX_SOCK) {
		fd = open_sock(iop);
	    } else if (iop->desc_type == STDIN) {
		fd = STDIN_FILENO;
	    } else if (iop->desc_type == STDOUT) {
		fd = STDOUT_FILENO;
	    } else if (iop->desc_type == TCP_SOCK) {
		fd = open_udpsock(iop);
	    } else if (iop->desc_type == UDP_SOCK) {
		fd = open_sock(iop);
	    } else {
		printf("Unknown type %d\n", iop->desc_type);
		return -1;
	    }
	
	    if (fd >= 0)
		break;		
	}
	return fd;
}

int open_fifo(struct io_params *iop)
{	
	struct stat	s;
	int		fd;
	int		oflags;
	int		perms;
	int		r;

	oflags = set_flags(iop);
	perms = S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH;

	if (stat(iop->path, &s) < 0) {
	    if (errno == ENOENT) {
		if ((r = mkfifo(iop->path, perms)) > 0) {
		    log_syserr("mkfifo(2) error %s.\n", iop->path);
		}
	    } else {
		log_syserr("stat error for %s: %s", iop->path, errno);
	    }
	}

	oflags |= O_NONBLOCK;

	for (;;) {
	    if ((fd = open(iop->path, oflags)) < 0) {
		if (errno == ENXIO) {
		    log_ret("Destination %s FIFO not writable without reader", iop->path);
		    sleep(5);
		    continue;
		} else {
		    printf("error here\n");
		    log_syserr("open(2) error - %s", iop->path);
		}
	    } else {
		break;
	    }
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

		if ((fd = open(iop->path, oflags, perms)) < 0 ) {
		    log_syserr("oper(2) error for %s", iop->path);
		}

	    } else {
		    log_syserr("stat(2) error for %s", iop->path);
	    }	

	} else {
	    if ((fd = open(iop->path, oflags)) < 0)
		log_syserr("open(2) error for %s\n", iop->path);
	}

	if (lseek(fd, 0, SEEK_END) < 0)
		log_syserr("lseek(2) failed\n", errno);
	
	return fd;
}

int open_sock(struct io_params *iop)
{
	/* LOCAL? NETWORK? */
	/* LISTEN? CONNECT? */
        /* RETURN INT FOR io_fd */
	int fd;
	
	if (iop->desc_type == UNIX_SOCK) {
	    if (iop->sock_data->conn_type == LISTEN) {
		if ((iop->sock_data->listenfd = call_bind(iop)) < 0)
		    log_msg("error binding socket");

		return call_accept(iop);
	    } else {
		return call_connect(iop);
	    }
	}
}



int call_bind(struct io_params *iop)
{
	int len, fd, r;
	struct sockaddr_un      servaddr;
	mode_t                  old_umask;

        memset(&servaddr, 0, sizeof(servaddr));

	if (iop->desc_type == UNIX_SOCK) {

	    servaddr.sun_family = AF_LOCAL;
	    strcpy(servaddr.sun_path, iop->sock_data->sockpath);
	    len = offsetof(struct sockaddr_un, sun_path) + strlen(iop->sock_data->sockpath);

	    if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
		log_syserr("Failed to create listening socket:", errno);

/*	    if ((r = connect(fd, (SA *) &servaddr, (socklen_t)sizeof(servaddr))) == 0) {
*		log_die("Error: listing socket already listening");
*	    } else if (r == -1 && errno != ENOENT) {
*		if (unlink(iop->path) != 0)
*			log_syserr("Failed to unlink unix socket: %s %s", iop->path, strerror(errno));
*	    }
*/
	    old_umask = umask(S_IXUSR|S_IXGRP|S_IXOTH);

	    if (bind(fd, (SA *) &servaddr, len) < 0) {
		(void)umask(old_umask);
		log_syserr("Error binding to socket:", errno);
	    }

	    (void)umask(old_umask);

	    if (chmod(iop->path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) == -1) {
		(void)umask(old_umask);
		log_syserr("chmod error: %d %s", errno, strerror(errno));
	    }

	    if (listen(fd, LISTENQ) < 0)
		log_syserr("Call to listen call failed:", errno);
	}

	return fd;
}


int call_accept(struct io_params *iop)
{
	int			sd;
	struct sockaddr_un 	cliaddr;
	int			clilen;


	printf("HERE\n");

	if (iop->desc_type == UNIX_SOCK) {	
	    clilen = offsetof(struct sockaddr_un, sun_path) + \
		strlen(iop->sock_data->sockpath);
	}

	if ((sd = accept(iop->sock_data->listenfd, (SA *) &cliaddr, &clilen)) < 0) {
	    if (errno == ECONNABORTED) {
		log_ret("accept() error: %s", strerror(errno));
		return -1;
	    } else {
		log_syserr("fatal accept() error: %s", strerror(errno));
		return -1;
            }
        }
	return sd;
}

int call_connect(struct io_params *iop)
{
	struct sockaddr_un	unix_saddr;
	struct sockaddr		net_saddr;
	int			len;
	int			fd;	

	if (iop->desc_type == UNIX_SOCK) {
	    fd = socket(AF_UNIX, SOCK_STREAM, 0);
	    bzero(&unix_saddr, sizeof(unix_saddr));
	    unix_saddr.sun_family = AF_UNIX;
	    strlcpy(unix_saddr.sun_path, iop->path, sizeof(unix_saddr.sun_path));
	    len = offsetof(struct sockaddr_un, sun_path) + strlen(iop->path);
	}

	if (connect(fd, (SA *) &unix_saddr, (socklen_t)sizeof(unix_saddr)) != 0) {
	    log_syserr("connect() failed: %s %d", iop->path, errno);
	}

	return fd;
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
		f = O_WRONLY|O_APPEND;

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
*		return STDOUT_REG_FILENO;
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
