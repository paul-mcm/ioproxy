objects = rbuf.o

all: $(objects)
	@gcc -g -o rbuf.o $(objects)

rbuf.o: rbuf.h
	@gcc -g -c rbuf.c

.PHONY : clean
clean:
	rm $(objects)

