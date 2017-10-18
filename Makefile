objects = rbuf.o config.o parse_line.o ftypes.o error.o

all: $(objects)
	@gcc -g -pthread -o ioproxy main.c $(objects) 

rbuf.o: lib/buff_management/rbuf.h
	@gcc -g -pthread -c -o rbuf.o lib/buff_management/rbuf.c

config.o: lib/configuration/config.h
	@gcc -g -c -o config.o lib/configuration/config.c

parse_line.o: lib/configuration/parse_line.h
	@gcc -g -c -o parse_line.o lib/configuration/parse_line.c

ftypes.o: lib/file_types/ftypes.h
	@gcc -g -c -o ftypes.o lib/file_types/ftypes.c

error.o: lib/error/errorlog.h
	@gcc -g -c -o error.o lib/error/errorlog.c

clean: rm -f $(objects) main

