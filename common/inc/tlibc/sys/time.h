// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SYS_TIME_H_
#define _SYS_TIME_H_

#include <sys/types.h>

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_REALTIME_COARSE 5
#define CLOCK_MONOTONIC_COARSE 6
#define CLOCK_BOOTTIME 7
#define CLOCK_REALTIME_ALARM 8
#define CLOCK_BOOTTIME_ALARM 9

typedef long time_t;
typedef long suseconds_t;
struct timezone;
#ifndef __timespec_defined
#define __timespec_defined 1
struct timespec
{
    time_t tv_sec;
    long tv_nsec;
};
#endif
struct timeval
{
    time_t tv_sec;       /* seconds */
    suseconds_t tv_usec; /* microseconds */
};
typedef int clockid_t;

#ifdef __cplusplus
extern "C" {
#endif

time_t time(time_t *t);

/* 
 * localtime
 * return value - outside enclave
 */
struct tm *localtime(const time_t *t);

int utimes (const char *path, const struct timeval times[2]);

/*
 * gettimeofday
 * tz - must be NULL
 */
int gettimeofday (struct timeval *tv, struct timezone *tz);

int clock_gettime(clockid_t clk_id, struct timespec *tp);

#ifdef __cplusplus
}
#endif

#endif /* _TIME_H_ */
