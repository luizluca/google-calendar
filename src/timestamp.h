#ifndef __GCAL_TIMESTAMP_H__
#define __GCAL_TIMESTAMP_H__

struct tm;
char *timestamp2tm(const char *s, const char *format, struct tm *tm);

#endif

