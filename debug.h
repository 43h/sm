#ifndef __DEBUG_H_
#define __DEBUG_H_

//#define TEST_MODE
#define DEBUG

void printHex(char *name, unsigned char *c, int n);
void speed_test(char *name, int len);
int debug_cmp(void *s1, void *s2, int len);


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <libgen.h>


#ifndef DEBUG
#define LOGF(fmt,...) ((void)0)
#define LOGE(fmt,...) ((void)0)
#define LOGW(fmt,...) ((void)0)
#define LOGI(fmt,...) ((void)0)
#define LOGD(fmt,...) ((void)0)
#else

#define LOG_SIZE 64

#define LOGM(fmt,...) do{\
	char log[LOG_SIZE] = {0};\
	sprintf(log ,fmt "\n", ##__VA_ARGS__);\
	show(,log);\
}while(0)


#define LOGF(fmt,...)   do{\
		char log[LOG_SIZE] = {0};\
		sprintf(log,"[FATAL]" fmt "\n", ##__VA_ARGS__);\
		show(log);\
	}while(0)

#define LOGE(fmt,...)  do{\
		char log[LOG_SIZE] = {0};\
		sprintf(log,"[ERROR]" fmt "\n", ##__VA_ARGS__);\
		show(log);\
	}while(0).

#define LOGW(fmt,...)  do{\
		char log[LOG_SIZE] = {0};\
		sprintf(log, "[WARN]" fmt "\n", ##__VA_ARGS__);\
		show(log);\
	}while(0)

#define LOGI(fmt,...)  do{\
		char log[LOG_SIZE] = {0};\
		sprintf(log, "[INFO]" fmt "\n", ##__VA_ARGS__);\
		show(log);\
	}while(0)

#define LOGD(fmt,...)  do{\
		char log[LOG_SIZE] = {0};\
		sprintf(log, "[DEBUG]"fmt "\n", ##__VA_ARGS__);\
		show(log);\
	}while(0)
#endif


void show(unsigned char *data);

#endif
