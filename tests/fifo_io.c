#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

int main(int argc, char *arg[])
{
	char buff[512];
	int fd;
	int nr, nw, r;
	struct pollfd	pfd[1];
	char buff1[] = "A TEST BUFFER";

	if ((fd = open("/tmp/TESTFIFO", O_RDONLY)) < 0) {
		printf("open() error: %d %s\n", errno, strerror(errno));
		exit(-1);
	}

	pfd[0].fd = fd;
	pfd[0].events = POLLRDNORM;

	for (;;) {
	    if ((r = poll(pfd, 1, INFTIM)) == -1) {
		dprintf(2, "fifo_io: poll() error: %s\n", strerror(errno));
		exit(-1);
	    }
	    if ((pfd[0].revents & (POLLERR|POLLNVAL|POLLHUP))) {
		dprintf(2, "revents error\n");
		exit(-1);
	    }

	    if ((nr = read(fd, buff, 512)) > 0) {
		nw = write(STDOUT_FILENO, buff, nr);
		exit(0);
	    } else if (nr = EOF || nr == 0) {
		dprintf(2, "EOF: %d\n", nr);
	    } else {
		dprintf(2, "unknown: %d\n");
	    }	
	}
}
