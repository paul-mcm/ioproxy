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
