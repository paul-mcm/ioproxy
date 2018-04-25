#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/un.h>

#define SA struct sockaddr

void test_unixsock(void);

int nread;
int nwritten;
char wbuff[] = "Some test data; should be looooooooooooooooooong enough";

int main(int argc, char *argv[])
{
	test_unixsock();
}

void test_unixsock()
{
	int                     sockfd;
        char                    sock[] = "/tmp/usock_test";
	struct sockaddr_un      servaddr;
	int			flags, i;

	sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sun_family = AF_UNIX;

	strlcpy(servaddr.sun_path, sock, sizeof(servaddr.sun_path));

	if ((flags = fcntl(sockfd, F_GETFL, 0)) < 0)
	    printf("fcntl error: %s\n", strerror(errno));
	if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0)
	    printf("fcntl error: %s\n", strerror(errno));

	if (connect(sockfd, (SA *) &servaddr, sizeof(servaddr)) < 0) {
		printf("Error connecting to socket %s: %s(%d)\n", sock, strerror(errno), errno);
		exit(-1);
	} else {
	    printf("Connect succes\n");
	}

        for (i = 0; i < 12; i++) {
	        if ((nwritten = write(sockfd, wbuff, sizeof(wbuff))) < 0)
        	    printf("Error %d writing to %s: %s\n", errno, sock, strerror(errno));

		printf("nwritten: %d\n", nwritten);
		sleep(1);
	}
}

