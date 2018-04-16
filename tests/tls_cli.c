#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <unistd.h>
#include <sys/socket.h>

#include "private.h"

#define SA struct sockaddr
#define SERV_PORT 2345
#define LISTENQ	10

int main(int argc, char *argv[])
{
	socklen_t 		servlen;
	struct sockaddr_in 	servaddr;
	char			buff[] = "A Test of Some Data....\n";
	const char		*port = "2345";
	struct tls_config       *tls_cfg;
        struct tls              *tls;
	int			r, i;

	if (tls_init() < 0)
            printf("tls init error\n");

        if ((tls_cfg = tls_config_new()) == NULL)
            printf("tls_config_new error\n");

	tls_config_set_ca_file(tls_cfg, ca_cert);
	tls_config_insecure_noverifyname(tls_cfg);
        tls = tls_client(); 
        tls_configure(tls, tls_cfg);

	if (tls_connect(tls, host, port) != 0) {
		printf("tls_connect() error: %s\n", tls_error(tls));
		exit(-1);	
	} else {
		printf("connect success!\n");
	}

	printf("CALLING HANDSHAKE\n");
	if (tls_handshake(tls) != 0) {
	    printf("tls_handshake() failed: %s\n", tls_error(tls));
	    exit(-1);
	} else {
	    printf("tls_handshake() success!!\n");
	}

	for (i = 0; i < 10; i++) {
	    if ((r = tls_write(tls, buff, strlen(buff))) < 0) {
		printf("tls_write() error: %s\n", tls_error(tls));
		exit(-1);
	    }
	    sleep(1);
	}
}
