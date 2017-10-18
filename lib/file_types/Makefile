objects = open_fifo.o open_file.o open_local_desc.o

file_management.o:   $(objects)
	@gcc -g -o $(objects)

$(objects) : myheader.h

.PHONY : clean
clean:
	rm $(objects)
