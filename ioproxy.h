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

#include "lib/configuration/config.h"
#include "lib/buff_management/rbuf.h"
#include "lib/file_types/ftypes.h"

struct t_args {
	struct rbuf_entry *rbuf;
	struct io_params  *iop;
};

int validate_path(struct io_params *);
int validate_ftype(struct io_params *, struct stat *);




