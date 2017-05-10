#ifndef __UTIL_H
#define __UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <string.h>


static char* StrTrim(char *str)
{
	char *p, *pt;

	p = str;
	while(*p && isspace(*p))	p++;
	pt = p;

	p += strlen(pt) - 1;
	while(isspace(*p))	p--;
	*(++p) = '\0';

	return pt;
}



#endif








