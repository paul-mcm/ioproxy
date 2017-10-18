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

#include "../configuration/config.h"
int open_fifo(struct io_params *);
int open_file(struct io_params *);
int open_tcpsock(struct io_params *);
int open_udpsock(struct io_params *);
int set_flags(struct io_params *);


int open_local_desc(char *, int);
