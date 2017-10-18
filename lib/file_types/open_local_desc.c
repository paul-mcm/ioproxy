#include "ftypes.h"

int open_local_desc(char *n, int t) {	

	/*
	*  PASSED A CONFIG PATHNAME AND
	*  TYPE AS ARG. OPEN APPROPRIATE
	*  FILE TYPE
	*/

	if (t == STDOUT) {
		return STDOUT_FILENO;

	} else if (t == FIFO) {
		return open_fifo(n);

	} else if (t == REG_FILE) {
		return open_file(n);
			
	} else if (t == UNIX_SOCK) {
		printf("is sockct\n");

	} else { 
		printf("can't us file type\n");
		return -1;
	}	
}

