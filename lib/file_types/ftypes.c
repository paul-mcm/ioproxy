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
		fd = open_sock(iop);
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
	} else if (iop->desc_type == TCP_SOCK) {
	    if (iop->sock_data->conn_type == LISTEN) {
		if ((iop->sock_data->listenfd = call_bind(iop)) < 0)
		    log_msg("error binding socket");

		return call_accept(iop);
	    } else {
		return call_connect(iop);
	    }
	} else if (iop->desc_type == UDP_SOCK) {	
		printf("IS UDP\n");
	}
}	

int call_bind(struct io_params *iop)
{
	int len, fd, r;
	struct sockaddr_un      unix_saddr;
	struct sockaddr_in      net_saddr;
	mode_t                  old_umask;

        memset(&unix_saddr, 0, sizeof(struct sockaddr_un));
        memset(&net_saddr, 0, sizeof(struct sockaddr_in));

	if (iop->desc_type == UNIX_SOCK) {

	    unix_saddr.sun_family = AF_LOCAL;
	    strcpy(unix_saddr.sun_path, iop->path);
	    len = offsetof(struct sockaddr_un, sun_path) + strlen(iop->path);

	    if (iop->sock_data->sockio == STREAM) 
		if ((fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
		    log_syserr("Failed to create listening socket:", errno);
	    else
		if ((fd = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		    log_syserr("Failed to create listening socket:", errno);

	    if ((r = connect(fd, (SA *) &unix_saddr, (socklen_t)sizeof(unix_saddr))) == 0) {
		log_die("Error: listing socket already listening");
	    } else if (r == -1 && errno != ENOENT) {
		if (unlink(iop->path) != 0)
			log_syserr("Failed to unlink unix socket: %s %s", iop->path, strerror(errno));
	    }

	    old_umask = umask(S_IXUSR|S_IXGRP|S_IXOTH);

	    if (bind(fd, (SA *) &unix_saddr, len) < 0) {
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

	} else if (iop->desc_type == TCP_SOCK) {
	    bzero(&net_saddr, sizeof(net_saddr));
	    net_saddr.sin_family = AF_INET;
	    net_saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	    net_saddr.sin_port = htons(iop->sock_data->port);

	    fd = socket(AF_INET, SOCK_STREAM, 0);

	    if (bind(fd, (SA *) &net_saddr, sizeof(net_saddr)) < 0)
		log_syserr("bind() error: %s", errno);

	    if (listen(fd, 1) != 0)
		log_syserr("listen() error: %s", errno);

	} else if (iop->desc_type == UDP_SOCK) {
	    bzero(&net_saddr, sizeof(net_saddr));
	    net_saddr.sin_family = AF_INET;
	    net_saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	    net_saddr.sin_port = htons(iop->sock_data->port);

	    fd = socket(AF_INET, SOCK_DGRAM, 0);

	    if (bind(fd, (SA *) &net_saddr, sizeof(net_saddr)) < 0)
		log_syserr("bind() error: %s", errno);

	    if (listen(fd, 1) != 0)
		log_syserr("listen() error: %s", errno);

	}

	return fd;
}


int call_accept(struct io_params *iop)
{
	int			sd;
	struct sockaddr_un 	cliaddr;
	int			clilen;

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
	struct sockaddr_in	net_saddr;
	int			len;
	int			fd;	

	if (iop->desc_type == UNIX_SOCK) {
	    fd = socket(AF_UNIX, SOCK_STREAM, 0);
	    bzero(&unix_saddr, sizeof(unix_saddr));
	    unix_saddr.sun_family = AF_UNIX;
	    strlcpy(unix_saddr.sun_path, iop->path, sizeof(unix_saddr.sun_path));
	    len = offsetof(struct sockaddr_un, sun_path) + strlen(iop->path);

	    for (;;) {
		if (connect(fd, (SA *)&unix_saddr, (socklen_t)sizeof(unix_saddr)) != 0) {
		    if (errno == ENOENT || errno == ECONNREFUSED) {
			log_ret("connect() failed for %s", iop->path);
			sleep(2);
			continue;
		    } else {
			log_syserr("connect() error for %s", iop->path);
		    }
		} else {
		    break;
		}
	    }
	} else if (iop->desc_type == TCP_SOCK) {
	    fd = socket(AF_INET, SOCK_STREAM, 0);
	    bzero(&net_saddr, sizeof(net_saddr));
	    net_saddr.sin_family = AF_INET;
	    net_saddr.sin_port = htons(iop->sock_data->port);

	    if (iop->sock_data->ip != NULL)
		inet_pton(AF_INET, iop->sock_data->ip, &net_saddr.sin_addr);

	    for (;;) {
		if (connect(fd, (SA *) &net_saddr, sizeof(net_saddr)) != 0) {
		    if (errno == ENOENT) {
			log_ret("connect() failed - no listeng socket");
			sleep(2);
			continue;
		    } else {
			log_syserr("connect error: %s", errno);
		    }
		} else {
                   break;
		}
	    }
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
