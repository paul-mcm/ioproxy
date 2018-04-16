CC = gcc
UNAME := $(shell uname)

ifeq ($(shell echo $(UNAME) | sed -E 's/(Net|Free|Open)//'), BSD)

	BSD_TYPE = $(UNAME)
        OS = BSD
        CCFLAGS = -D ${OS} -D ${BSD_TYPE}

	ifeq ($(BSD_TYPE), FreeBSD)
		LIBS = /usr/local/lib
		INCLUDES = /usr/local/include
	endif

	ifeq ($(BSD_TYPE), NetBSD)
		LIBS = /usr/pkg/lib
		INCLUDES = /usr/pkg/include
	endif

	ifeq ($(UNAME), OpenBSD)
		LIBS = /usr/local/lib
		INCLUDES = /usr/local/include
	endif
endif

ifeq ($(UNAME), Linux)
	LIBS = /usr/lib64
	INCLUDES = /usr/include
	OS = LINUX
	CCFLAGS = -D ${OS} -lbsd -ltls -I/opt/include -L/opt/lib 
endif

all: 
	@$(CC) $(CCFLAGS) -g -I${INCLUDES} -o fifo_io fifo_io.c
	@$(CC) $(CCFLAGS) -g -I${INCLUDES} -ltls -o tls_cli tls_cli.c
#	@$(CC) $(CCFLAGS) -g -I${INCLUDES} -ltls -o tls_serv tls_serv.c

clean: 
	@rm -f fifo_io tls_cli tls_serv
