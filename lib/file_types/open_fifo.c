#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int open_fifo(char *n)
{	
	struct stat s;
	int fd;

	if (stat(n, &s) < 0) {
		if (errno == ENOENT) {
			if (mkfifo(n, S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH) < 0 )
				printf("openerror: %d, %s\n", errno, strerror(errno));
		}
	}
	
	if ( (fd = open(n, O_WRONLY|O_NONBLOCK)) < 0 ) {
		printf("opern error %s\n", strerror(errno));
		return -1;
	}

	return fd;
}
		
