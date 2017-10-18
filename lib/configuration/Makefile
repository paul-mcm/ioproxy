objects = parse_line.o config.o

all: $(objects)
        @gcc -g -o config.o $(objects) 

parse_line.o:  config.h
        @gcc -g -c parse_line.c

config.o:  config.h
        @gcc -g -c config.c

.PHONY : clean
clean:
        rm $(objects)

