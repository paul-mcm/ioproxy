#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>
#include <sys/socket.h>

#define SA struct sockaddr
/* #define SERV_PORT 2345 */
#define LISTENQ	10

int main(int argc, char *argv[])
{
	int			listenfd, connfd;
	socklen_t 		clilen;
	struct sockaddr_in 	cliaddr, servaddr;
  	int			nw;
	char			buff[512];
	struct tls_config	*tls_cfg;
	struct tls		*tls, *ctxt;
	int			port = 2345;
	int			opt;
	opt = 1;

	if (tls_init() < 0)
	    printf("tls init error\n");

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(port);

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) == -1) {
	    printf("setsockopt() error: %s\n", strerror(errno));
	    exit(-1);
	}

	bind(listenfd, (SA *) &servaddr, sizeof(servaddr));
	listen(listenfd, 1);
	clilen = sizeof(cliaddr);

	for (;;) {
	    connfd = accept(listenfd, (SA *) &cliaddr, &clilen);
	    if ((tls_cfg = tls_config_new()) == NULL) {
		printf("tls_config_new error\n");
		exit(-1);
	    }

	    tls_config_set_keypair_file(tls_cfg, host_cert, host_key);

	    tls = tls_server();
	    tls_configure(tls, tls_cfg);

	    if (tls_accept_socket(tls, &ctxt, connfd) < 0)
		printf("tls_accept_socket() error\n");
	    else
		printf("tls_accept_socket() success!\n");
	
	    if (S_TYPE == 0)
		read_data(ctxt);
	    else
		write_data(ctxt);

	    tls_close(ctxt);
	    tls_free(ctxt);
	    close(connfd);
	}
}

int read_data(struct tls *t)
{
  	int	nr;
	char	buff[512];

	for (;;) {
	    if ((nr = tls_read(t, buff, 512)) < 0) {
		printf("tls_read() error: %s\n", tls_error(t));
		break;
	    } else if (nr == 0) {
		printf("tls_read() returned %d\n", nr);
		sleep(2);
		continue;
	    } else {
		write(STDOUT_FILENO, buff, nr);
		continue;
	    }
	}

}

int write_data(struct tls *t)
{
  	int	nw;
	char	buff[] = "A string may be no more than but a thought: misguided, confuzzed, reppqr .... ai";

	for (;;) {
	    if ((nw = tls_write(t, buff, strlen(buff))) < 0) {
		printf("tls_write() error: %s\n", tls_error(t));
		break;
	    } else if (nw == 0) {
		printf("tls_write() returned %d\n", nw);
		sleep(2);
		continue;
	    }
	    sleep(2);
	}

}
