#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include<time.h>

void printHex(char *name, unsigned char *c, int n)
{
	int i;

	printf("\n[%s ,len = %d, start ]\n", name, n);
	for(i = 0; i < n; i++)
	{
		printf("0x%02X, ", c[i]);
		if((i % 4) == 3)
			printf(" ");

		if((i % 4) == 3)
			printf("\n");
	}
	if((i % 4) != 0)
		printf("\n");
	printf("[%s       end        ]\n", name);
}

void speed_test(char *name, int len)
{
	static volatile unsigned long long byte = 0;
	static volatile unsigned long long count = 0;
	static time_t t1, t2;
	static int flag = 0;

	if(!flag)
	{
		flag = 3;
		time(&t1);
	}

	byte += len;
	count++;

	time(&t2);
	if((t2 - t1) >= flag)
	{

		unsigned long long byte_temp = byte;
		unsigned long long count_temp = count;

		if(byte_temp)
			byte_temp = byte_temp * 8 / flag / 1024 / 1024;

		if(count_temp)
			count_temp = count_temp / flag;

		printf(" %s speed = %lld Mb, %lld Hz \n", name, byte_temp, count_temp);
		t1 = t2;
		byte = 0;
		count = 0;
	}
}

int debug_cmp(void *s1, void *s2, int len)
{
	if(s1 == NULL || s2 == NULL || len <= 0)
	{
		printf("please check u param\n");
		exit(0);
	}

	unsigned char *p = (unsigned char *)s1;
	unsigned char *q = (unsigned char *)s2;

	for(int i = 0; i < len; i++)
	{
		if(p[i] != q[i])
		{
			printf("the %d byte is different\n", i);
			return -1;
		}
	}
	return 0;
}

void show(unsigned char *data)
{
	printf("%s", data);
}