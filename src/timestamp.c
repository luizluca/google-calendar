#define _XOPEN_SOURCE /* man page say: glibc2 needs this */
#include <time.h>
#include <sys/time.h>

char *timestamp2tm(const char *s, const char *format, struct tm *tm)
{
	return strptime(s, format, tm);
}

