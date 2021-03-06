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

#ifndef CONFIG_H
#define CONFIG_H

#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include <libssh/libssh.h>

#define FALSE		0
#define TRUE		1

typedef enum {
	TYPE_1,		/* 1-to-1    */
	TYPE_2,		/* 1-to-many */
	TYPE_3,		/* many-to-1 */
} T_CFG;

typedef enum {
	SRC,
	DST
} T_DATA;

typedef enum { 	
	REG_FILE,
	FIFO,
	STDOUT,
	STDIN,
	UNIX_SOCK,
	TCP_SOCK,
	UDP_SOCK,
	PIPE,
	SSH,
} T_IO;

typedef enum {
	CLIENT,
	SRVR,
} T_SOCK;

typedef enum {
	DGRAM,
	STREAM,
} T_SOCKIO;

struct sock_param {
        T_SOCK		conn_type;
        T_SOCKIO	sockio;
	int		tls;
        char		*ip;
	int		listenfd;
        char	     	*tls_port;
	uint32_t	port;
        char    	*hostname;
	char		*sockpath;
	char		*cacert_path;
	char		*cacert_dirpath;
	char		*host_cert;
	char		*host_key;
	struct tls	*tls_ctx;
	int		cert_vrfy;
	char		*ssh_cmd;
	ssh_session	ssh_s;
	ssh_channel	ssh_chan;
	struct sockaddr *host_addr;
};

/* s - shared
 * c - constant (does not change)
 */

struct io_params {
        T_DATA			io_drn;
        T_IO			io_type;
	T_CFG			*cfgtype_p;

	struct rbuf_entry	*rbuf_p;
	struct rbuf_entry	*w_ptr;
	struct rbuf_entry	*r_ptr;
	void *(*io_thread)(void *);

	pthread_t		tid;
	pthread_mutex_t		listlock;	/* s */
	pthread_cond_t		readable;	/* s */
	pthread_mutex_t		fd_lock;	/* s */
	pthread_mutex_t		*fdlock_p;
	pthread_barrier_t	thrd_b;		/* s */
	int			buf_sz;
	int			io_fd;
	int			*iofd_p;	/* TYPE 3 ONLY */
        char			*path;
	char			*pipe_cmd;
	pid_t			pipe_cmd_pid;
	int			nonblock;
	int			*listready;	/* s */
	unsigned long		bytes;
	unsigned long		io_cnt;
        struct sock_param	*sock_data;	/* MAY BE NULL */
	struct iop1_paths	*iop1_p;
#ifdef BSD
	int			kqd;
#endif
};

struct iop0_params {
	struct io_params			*iop;
	LIST_HEAD(iop1_paths, iop1_params)	io_paths;
	LIST_ENTRY(iop0_params)			iop0_paths;
};

struct iop1_params {
	struct io_params	*iop;
	LIST_ENTRY(iop1_params)	io_paths;
};

struct io_cfg {
	T_CFG			    cfg_type;
	LIST_HEAD(, iop0_params)    iop0_paths;
	LIST_ENTRY(io_cfg)	    io_cfgs;
};

LIST_HEAD(all_cfg_list, io_cfg) all_cfg;
struct all_cfg_list *all_cfgs;

LIST_HEAD(new_cfg_list, io_cfg) new_cfg;
struct new_cfg_list *new_cfgs;

struct io_cfg * parse_config(FILE *);
int read_config(struct all_cfg_list *, char *);
int init_cfg(struct io_cfg *);
int show_config(struct io_cfg *);
int show_all_configs(struct all_cfg_list *);

struct io_params * parse_io_cfg(FILE *);
struct iop0_params * parse_iop0_stanza(FILE *);

int is_sock(struct io_params *);
int is_netsock(struct io_params *);
int is_src(struct io_params *);
int is_dst(struct io_params *);
int use_tls(struct io_params *);
int use_ssh(struct io_params *);
void report_close_error(struct io_params *);

int validate_path(char *);  /* VALIDATE PATH */
int valid_ftype(int, struct stat *); /* VALIDATE FILE TYPE */

void print_config_params(struct io_params *);

void set_cfg_type(struct io_cfg *);
T_DATA set_io_dir(char *);

int line_byte_cnt(FILE *);

struct io_cfg		*io_cfg_alloc(void);
struct iop0_params	*iop0_alloc(void);
struct iop1_params	*iop1_alloc(void);
struct io_params	*iop_alloc(void);
struct sock_param	*sock_param_alloc(void);
struct rbuf_entry 	*set_rbuf_lock(struct io_params *);

void free_iocfg(struct io_cfg *);
void free_iop0(struct iop0_params *);
void free_iop1(struct iop1_params *);
void free_iop(struct io_params *);
void free_sock_param(struct sock_param *);

int validate_cfg(struct io_cfg *);
void validate_iop(struct io_params *);
void validate_sockparams(struct io_params *);

int compare_io_params(struct io_params *, struct io_params *);
int cnt_secondaries(struct iop0_params *);
struct iop0_params *compare_iop0(struct io_cfg *, struct io_cfg *);

char *fetch_next_line(FILE *, int *);
int check_endcfg(char *);

#endif
