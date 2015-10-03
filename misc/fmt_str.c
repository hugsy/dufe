#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char** argv){
	int fd = open(argv[1], O_RDONLY);
	char buf[256];
	read(fd, buf, 255);
	close(fd);
	printf(buf);
	return 0;
}
