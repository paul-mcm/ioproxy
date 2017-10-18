#include "ftypes.h"
#include <sys/stat.h>

int valid_path(char *p, struct stat *s) 
{
        int error = 0;

        if (stat(p, s) != 0) {
                printf("stat error for %s: %s\n", p, strerror(errno));
                error = -1; 
        }
        return error;
}

