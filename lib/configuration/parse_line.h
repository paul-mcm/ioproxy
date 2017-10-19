#ifndef PARSE_LINE_H
#define PARSE_LINE_H

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

#include "config.h"

#define BUFF_SIZE	2048
#define SIZE	256

struct io_cfg * parse_config(FILE *);
int init_cfg(struct io_cfg *);

int parse_line(char *, struct io_params *q);

void set_derived_params(struct io_params *);
int fill(char *, char *, struct io_params *);

int set_conn(char *, struct io_params *);
int set_sockio(char *, struct io_params *);
int set_desc_t(char *, struct io_params *);
int set_nonblock(char *, struct io_params *iop);
int parse_tuple(char *, char *);

char * rm_space(char *);
char * clean_line(char *);
char * rm_end_space(char *);

T_DATA set_io_type(char *);

#endif
