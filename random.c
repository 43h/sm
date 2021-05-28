#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "random.h"

int vli_get_random(u8 *data, u32 len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	int ret = -1;

	if(fd > 0)
	{
		ret = read(fd, data, len);
		close(fd);
		ret = 0;
	}
	else
	{
		memset(data, 0x33, len);
	}

	return ret;
}
