#include <stdio.h>

int main(int argc, char** argv)
{
	FILE* fd = fopen(argv[1], "r");
	char buf[256];
	fgets(buf, 2014, fd);
	fclose(fd);
	printf("%s\n", buf);
	return 0;
}
