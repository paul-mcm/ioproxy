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
	    } else if (is_netsock(iop)) {
		fd = open_sock(iop);
	    } else {
		log_msg("Unknown type %d", iop->desc_type);
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
	int 			r;
	struct sock_param	*sop;

	sop = iop->sock_data;

	if (sop->conn_type == CLIENT) {
	    return call_connect(iop);
	} else {
	    if (sop->listenfd < 0) {
		if ((sop->listenfd = call_bind(iop)) < 0)
		    log_msg("error binding socket");
	    }

	    if ((r = call_accept(iop)) < 0)
		return r;
	    else
		iop->io_fd = r;

	    if (use_tls(iop) && do_tlsaccept(iop) < 0) {
		log_msg("do_tlsaccept() failed\n");
		close(r);
		iop->io_fd = -1;
		return -1;
	    } else {
		return r;
	    }
	}
}	

int call_bind(struct io_params *iop)
{
	int			lfd, r, sopt;
	struct sockaddr_un      u_saddr;
	struct sockaddr_in      net_saddr;
	mode_t                  old_umask;
	socklen_t		len;

	if (iop->desc_type == UNIX_SOCK) {
	    memset(&u_saddr, 0, sizeof(struct sockaddr_un));
	    u_saddr.sun_family = AF_LOCAL;

	    if (strlcpy(u_saddr.sun_path, iop->path,
		sizeof(u_saddr.sun_path)) >= sizeof(u_saddr.sun_path))
		    log_die("error: %s - name too long\n", iop->path);

	    len = offsetof(struct sockaddr_un, sun_path) + strlen(iop->path);

	    if ((lfd = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		log_syserr("Failed to create listening socket:", errno);

	    if ((r = connect(lfd, (SA *)&u_saddr, sizeof(u_saddr))) == 0) {
		log_die("Error: listing socket already listening");
	    } else if (r == -1 && errno != ENOENT) {
		if (unlink(iop->path) != 0)
			log_syserr("Failed to unlink unix socket: %s %s", iop->path, strerror(errno));
	    }

	    old_umask = umask(S_IXUSR|S_IXGRP|S_IXOTH);

	    if (bind(lfd, (SA *)&u_saddr, len) < 0) {
		(void)umask(old_umask);
		log_syserr("Error binding to socket:", errno);
	    }

	    (void)umask(old_umask);

	    if (chmod(iop->path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) == -1) {
		(void)umask(old_umask);
		log_syserr("chmod error: %d %s", errno, strerror(errno));
	    }

	    if (listen(lfd, LISTENQ) < 0)
		log_syserr("Call to listen call failed:", errno);

	} else if (is_netsock(iop)) {
	    sopt = 1;

	    bzero(&net_saddr, sizeof(net_saddr));
	    net_saddr.sin_family = AF_INET;
	    net_saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	    net_saddr.sin_port = htons(iop->sock_data->port);

	    if (iop->desc_type == UDP_SOCK) {
		if ((lfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		    log_syserr("socket() error: ");
	    } else if (iop->desc_type == TCP_SOCK) {
		if ((lfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		    log_syserr("socket() error: ");
	    }

	    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &sopt, sizeof(sopt)) == -1)
		log_syserr("setsockopt failure");

	    if (bind(lfd, (SA *) &net_saddr, sizeof(net_saddr)) < 0)
		log_syserr("bind() error");

	    if (listen(lfd, 1) != 0)
		log_syserr("listen() error");

	}
	return lfd;
}

int do_tlsaccept(struct io_params *iop)
{
	struct tls_config	*tls_cfg;
	struct tls		*tls;
	struct sock_param	*sop;

	sop = iop->sock_data;

	if ((tls_cfg = tls_config_new()) == NULL)
            log_die("tls_config_new error\n");

        tls_config_set_keypair_file(tls_cfg, sop->srvr_cert, sop->srvr_key);

        if ((tls = tls_server()) == NULL)
	    log_die("tls_server() error\n");

        if (tls_configure(tls, tls_cfg) != 0)
	    log_die("tls_configure() error: %s\n", tls_config_error(tls_cfg));

	if (tls_accept_socket(tls, &sop->tls_ctx, iop->io_fd) < 0) {
	    log_msg("tls_accept_socket() error %s\n", tls_error(tls));
	    return -1;
	} else {
	    log_msg("tls_accept_socket() success!\n");
	    return 0;
	}
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

	if (iop->desc_type == UNIX_SOCK)
	    return do_localconnect(iop);
	else if (use_tls(iop)) {
	    return do_tlsconnect(iop);
	} else {
	    return do_netconnect(iop);
	}
}

int do_localconnect(struct io_params *iop)
{
	struct sockaddr_un	uaddr;
	int			len, fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	bzero(&uaddr, sizeof(uaddr));
	uaddr.sun_family = AF_UNIX;
	strlcpy(uaddr.sun_path, iop->path, sizeof(uaddr.sun_path));
	len = offsetof(struct sockaddr_un, sun_path) + strlen(iop->path);

	for (;;) {
	    if (connect(fd, (SA *)&uaddr, len) != 0) {
		if (errno == ENOENT || errno == ENETDOWN || errno == ETIMEDOUT || \
		    errno == ECONNREFUSED) {
		    log_ret("connect() failed - no listeng socket");
		    sleep(2);
		    continue;
		} else {
		   log_syserr("connect error: %s", errno);
		}
	    } else {
		return fd;
		break;
	    }
	}
}

int do_tlsconnect(struct io_params *iop)
{
	int			fd, r;
	struct sock_param	*sop;
	struct tls_config	*tls_cfg;
	char			*host;

	sop = iop->sock_data;

	if (sop->hostname != NULL)
	    host = sop->hostname;
	else if (sop->ip != NULL)
	    host = sop->ip;

	if ((tls_cfg = tls_config_new()) == NULL)
	    log_die("tls_config_new error: %s\n", tls_config_error(tls_cfg));

	if (sop->cacert_path != NULL)
	    if (tls_config_set_ca_file(tls_cfg, sop->cacert_path) != 0)
		log_die("tls_config_set_ca_file() error: %s\n", tls_config_error(tls_cfg));

	if (sop->cacert_dirpath != NULL)
	    if (tls_config_set_ca_path(tls_cfg, sop->cacert_dirpath) != 0)
		log_die("tls_config_set_ca_path() error: %s\n", tls_config_error(tls_cfg));

	if (sop->cert_vrfy == FALSE)
	    tls_config_insecure_noverifyname(tls_cfg); 

	for (;;) {
	    sop->tls_ctx = tls_client();

	    if (tls_configure(sop->tls_ctx, tls_cfg) != 0)
		log_die("tls_configure() error: %s\n", tls_config_error(tls_cfg));

	    if (tls_connect(sop->tls_ctx, host, sop->tls_port) != 0) {
		log_msg("tls_connect() error\n", tls_error(sop->tls_ctx));
		tls_close(sop->tls_ctx);
		tls_free(sop->tls_ctx);
		sleep(3);
		continue;
	    } else {
		log_msg("tls_connect() success!\n");
		if (tls_handshake(sop->tls_ctx) != 0) {
		    log_msg("tls_handshake() failed: %s\n", tls_error(sop->tls_ctx));
		    tls_close(sop->tls_ctx);
		    tls_free(sop->tls_ctx);
		    sleep(2);
		    continue;
		} else {
		    return 0;
		}
	    }
	}
}

int do_netconnect(struct io_params *iop)
{
	int			fd, r;
	struct addrinfo		hints, *res, *ressave;
	struct sockaddr_in	servaddr;
	struct sock_param	*sop;
	int			s_type;

	sop = iop->sock_data;	
	s_type = iop->desc_type == TCP_SOCK ? SOCK_STREAM : SOCK_DGRAM;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = s_type;

	if (sop->hostname != NULL) {
	    for (;;) {
		if ((r = getaddrinfo(sop->hostname, NULL, &hints, &res)) != 0) { 
		    log_msg("getaddrinfo() error: %s", gai_strerror(r));
		    exit(-1); /* XXX REALLY */
		} else {
		    ressave = res;
		}
	        do {
		    if ((fd = socket(res->ai_family, res->ai_socktype, \
			res->ai_protocol)) < 0) {
			log_ret("socket() error");
			continue;
			}

		    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
			log_ret("connect() error");
			continue;
		    } else {
			break;
		    }
		} while ((res = res->ai_next) != NULL);

		if (res == NULL) {
		    sleep(2);
		    freeaddrinfo(ressave);
		    continue;
		} else {
		    freeaddrinfo(ressave);
		    return fd;
		}

            }

	} else if (sop->ip != NULL) {
	    bzero(&servaddr, sizeof(servaddr));
	    servaddr.sin_family = AF_INET;
	    servaddr.sin_port = htons(sop->port);
	    inet_pton(AF_INET, sop->ip, &servaddr.sin_addr);

	    for (;;) {
		if ((fd = socket(AF_INET, s_type, 0)) < 0) {
		    log_ret("socket() error");
		    return -1;
		}

		if (connect(fd, (SA *)&servaddr, sizeof(servaddr)) != 0) {
		    log_ret("connect() error");
		    sleep(3);
		    continue;
		} else {
		    return fd;
		}
	    }
	}
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
