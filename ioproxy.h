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

#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/resource.h>

#include <libssh/libssh.h>
#include <libssh/callbacks.h>

#include "lib/configuration/config.h"
#include "lib/buff_management/rbuf.h"
#include "lib/file_types/ftypes.h"

#ifdef LINUX
#include <bsd/string.h>
#endif

#define FALSE 0
#define TRUE 1

void * iocfg_manager(void *);
void * io_thread(void *);
void * io_t3_thread(void *);

int validate_ftype(struct io_params *, struct stat *);
void ioparam_list_kill(struct io_cfg *);
int cancel_ioparam(struct io_params *);

void set_thrd_sigmask(void);
void *sigterm_thrd(void *);
void *sighup_thrd(void *);

void iop_setup(struct io_cfg *);
void *iop0_thrd(void *);

void copy_io_params(struct io_params *, struct io_params *);

int cancel_threads(struct iop0_params *);
int sigrecvd(void);
int load_command(struct all_cfg_list *, char *, char *, char *);
void init_io_shutdown(void);
