#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <assert.h>
#include <unistd.h>
#include <time.h>
#include <mach/mach_time.h>

#include "lib/compiler.h"
#include "lib/errno.h"
#include "lib/misc.h"

#include "hosal/timer.h"

static mach_timebase_info_data_t time_base_info;

/*
* Must be called in the main thread, before everything else
*/
void subsys_timer_init(void)
{
	mach_timebase_info(&time_base_info); /* Determines the time scale */
}

void subsys_timer_exit(void)
{
}

/* misc */
int sys_time_get(struct sys_time *out)
{
	struct timeval tv;
	struct tm timenow;
	struct tm *ret;

	gettimeofday(&tv, NULL);

	ret = localtime_r(&tv.tv_sec, &timenow);
	if (unlikely(!ret))
		return ERR_UNKNOWN;

	out->day = timenow.tm_mday;
	out->month = timenow.tm_mon + 1;
	out->year = timenow.tm_year + 1900;
	out->hour = timenow.tm_hour;
	out->min = timenow.tm_min;
	out->sec = timenow.tm_sec;
	out->msec = tv.tv_usec / 1000;
	if (timenow.tm_zone)
		strncpy(out->time_zone, timenow.tm_zone, sizeof(out->time_zone));
	else
		memset(out->time_zone, 0, sizeof(out->time_zone));
	out->utc_hour_offset = timenow.tm_gmtoff / 3600;
	out->utc_min_offset = (timenow.tm_gmtoff % 3600) / 60;

	return ERR_OK;
}

unsigned long sys_get_jiffies(void)
{
	time_t now;

	time(&now);

	return ((unsigned long)now);
}

void sys_get_timestamp(void *timestamp)
{
       uint64_t now;

       now = mach_absolute_time();
       memcpy(timestamp, &now, sizeof(now));
}

unsigned long sys_get_timestamp_specific(int type)
{
	uint64_t ticks;
	unsigned long ret;

	ticks = mach_absolute_time();

	/* to ms */
	ret = (ticks * time_base_info.numer) / (time_base_info.denom * 1000);
	if (type == SYS_JIFFY_T_IN_MS) {
		ret = ret / 1000;
	} else if (type == SYS_JIFFY_T_IN_SEC) {
		ret = ret / 1000000;
	}
	return ret;
}

uint64_t sys_time_elapsed(const void *timestamp1, const void *timestamp2)
{
       uint64_t stamp1;
       uint64_t stamp2;
       uint64_t elapsed_nano;

       memcpy(&stamp1, timestamp1, sizeof(stamp1));
       memcpy(&stamp2, timestamp2, sizeof(stamp2));

       assert(stamp2 >= stamp1);

       elapsed_nano = (stamp2 - stamp1) * time_base_info.numer / time_base_info.denom;

       return (elapsed_nano / 1000000);
}
