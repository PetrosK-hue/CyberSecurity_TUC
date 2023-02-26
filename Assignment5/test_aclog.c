#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc,char* argv[]) 
{
	int i;
	size_t bytes;
	FILE *file;	
	char *a = argv[1];
  	int number_files = atoi(a);
	char filenames[number_files][16];

	/* example source code */

	for (i = 0; i < number_files; i++) {	

		sprintf(filenames[i],"file_%d.txt",i);
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			char buf[128];
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}
}
