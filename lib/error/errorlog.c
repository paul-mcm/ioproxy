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

#include "errorlog.h"

/* Initialize syslog(), if running as daemon. */

void log_open(const char *id, int opt, int facility)
{
	if (debug == 0)
	    openlog(id, opt, facility);
}

/* LOG SYSCALL RELATED ERROR AND RETURN */
void log_ret(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	log_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	return;
}

/* FATAL SYSCALL ERROR */
void log_syserr(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	log_doit(1, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(-1);
}

/* LOG MISC MSG ERROR AND RETURN */

void log_msg(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	log_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	return;
}

/* FATAL ERROR/NO ERRNO */

void log_die(const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	log_doit(0, LOG_ERR, fmt, ap);
	va_end(ap);
	exit(-1);
}

/* LOG THE ERROR */
static void log_doit(int errnoflag, int priority, const char *fmt, va_list ap)
{
	int	errno_save;
	char	buf[MAXLINE];
	size_t	strerr_len;

	errno_save = errno;		/* value caller might want printed */
	vsnprintf(buf, MAXLINE - 1, fmt, ap);
	if (errnoflag) {
	    strerr_len = strlen(strerror(errno_save)) + 1;
	    snprintf(buf+strlen(buf), MAXLINE - strlen(buf) - 1, ": %s\n", strerror(errno_save));
	}

#ifdef BSD
	strlcat(buf, "\n", MAXLINE);
#elif LINUX
	strcat(buf, "\n");
#endif
	if (debug) {
	    fflush(stdout);
	    fputs(buf, stderr);
	    fflush(stderr);
	} else
	    syslog(priority, buf);

	return;
}
