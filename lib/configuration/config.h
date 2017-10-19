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
#include <syslog.h>
#include <unistd.h>

/* #include "../buff_management/rbuf.h" */

#define FALSE 0
#define TRUE  1
#define BUFF_SIZE	2048
#define SIZE	256

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
	UDP_SOCK
} T_IO;

typedef enum {
	CONNECT,
	LISTEN,
} T_SOCK;

typedef enum {
	DGRAM = 3,
	STREAM = 4,
} T_SOCKIO;

struct io_params {
	pthread_t		tid;
        T_DATA			io_drn;
        T_IO			desc_type;
	int			io_fd;
	pthread_mutex_t		listlock;
	pthread_cond_t		readable;
	int			*listready;
	int			nonblock;
	struct rbuf_entry	*rbuf_p;
        char			*path;
        struct	sock_param	*sock_data;	/* MAY BE NULL */
        LIST_ENTRY(io_params)	io_entries;
};

struct sock_param {
        T_SOCK		conn_type;
        T_SOCKIO	sockio;
        char		*ip;
        int     	port;
        char    	*hostname;
	char		*sockpath;
};

struct io_cfg {
	struct io_params *io_p;
	LIST_HEAD(, io_params) io_paths;
	LIST_ENTRY(io_params) io_entries;
	LIST_ENTRY(io_cfg) io_cfgs;
};

LIST_HEAD(all_cfg_list, io_cfg) all_cfg;
struct all_cfg_list all_configs;

struct io_cfg * parse_config(FILE *);
int read_config(struct all_cfg_list *);
int init_cfg(struct io_cfg *);
int show_config(struct io_cfg *);
int show_all_configs(struct all_cfg_list *);

struct io_params * parse_io_cfg(FILE *);
struct io_params * parse_cfg_stanza(FILE *);
void set_derived_params(struct io_params *);
void print_params(struct io_params *);
int fill(char *, char *, struct io_params *);

int set_conn(char *, struct io_params *);
int set_sockio(char *, struct io_params *);
int set_desc_t(char *, struct io_params *);
int set_ioblock(char *, struct io_params *);

int parse_tuple(char *, char *);
int is_sock(struct io_params *);
int is_netsock(struct io_params *);
int is_src(struct io_params *);
int is_dst(struct io_params *);

int valid_path(char *, struct stat *);  /* VALIDATE PATH */
int valid_ftype(struct io_params *, struct stat *); /* VALIDATE FILE TYPE */

void print_config_params(struct io_params *);


#endif
