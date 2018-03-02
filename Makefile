CC = gcc
UNAME := $(shell uname)
SERVER := ioproxyd
CLIENT := ioproxy
INSTALL_DIR := /usr/local/sbin

ifeq ($(shell echo $(UNAME) | sed -E 's/(Net|Free|Open)//'), BSD)

	BSD_TYPE = $(UNAME)
        OS = BSD
        MANPATH = /usr/local/man
        CCFLAGS = -D ${OS} -D ${BSD_TYPE}

	ifeq ($(BSD_TYPE), FreeBSD)
		MANOWNER = root:wheel
		LIBS = /usr/local/lib
		INCLUDES = /usr/local/include
		BINOWNER = root:wheel
	endif

	ifeq ($(BSD_TYPE), NetBSD)
		MANOWNER = root:wheel
		LIBS = /usr/pkg/lib
		INCLUDES = /usr/pkg/include
		BINOWNER = root:wheel
	endif

	ifeq ($(UNAME), OpenBSD)
		LIBS = /usr/local/lib
		INCLUDES = /usr/local/include
		MANOWNER = root:bin
		BINOWNER = root:bin
	endif
endif

ifeq ($(UNAME), Linux)
	LIBS = /usr/lib64
	INCLUDES = /usr/include
	OS = LINUX
	MANPATH = /usr/local/share/man
	MANOWNER = root:root
	BINOWNER = root:root
	CCFLAGS = -D ${OS}
endif

objects = rbuf.o config.o parse_line.o ftypes.o error.o

all: $(objects)
	@$(CC) $(CCFLAGS) -g -ltls -lssh_threads -I/usr/local/include -L/usr/local/lib -pthread -o ioproxyd main.c $(objects) 
	@rm -f $(objects)
	@ln -s ./ioproxyd ./ioproxy

rbuf.o: lib/buff_management/rbuf.h
	@$(CC) $(CCFLAGS) -g -I/usr/local/include -pthread -c -o rbuf.o lib/buff_management/rbuf.c

config.o: lib/configuration/config.h
	@$(CC) $(CCFLAGS) -g -I/usr/local/include -c -o config.o lib/configuration/config.c

parse_line.o: lib/configuration/parse_line.h
	@$(CC) $(CCFLAGS) -g -I/usr/local/include -c -o parse_line.o lib/configuration/parse_line.c

ftypes.o: lib/file_types/ftypes.h
	@$(CC) $(CCFLAGS) -g -I/usr/local/include -c -o ftypes.o lib/file_types/ftypes.c

error.o: lib/error/errorlog.h
	@$(CC) $(CCFLAGS) -g -c -o error.o lib/error/errorlog.c

clean: 
	@rm -f $(objects) ioproxyd ioproxy

