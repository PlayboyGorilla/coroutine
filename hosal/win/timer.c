#include <windows.h>
#include <sysinfoapi.h>
#include <time.h>

#include "lib/compiler.h"
#include "lib/errno.h"

#include "hosal/timer.h"

WINBASEAPI ULONGLONG WINAPI GetTickCount64 (VOID);

/*
* Must be called in the main thread, before everything else
*/
void subsys_timer_init(void)
{
}

void subsys_timer_exit(void)
{
}

/* misc */
int sys_time_get(struct sys_time *out)
{
	SYSTEMTIME time;

	GetLocalTime(&time);

	out->day = time.wDay;
	out->month = time.wMonth;
	out->year = time.wYear;
	out->hour = time.wHour;
	out->min = time.wMinute;
	out->sec = time.wSecond;
	out->msec = time.wMilliseconds;

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
	ULONGLONG ret;

	ret = GetTickCount64();
	memcpy(timestamp, &ret, sizeof(ret));
}

unsigned long sys_get_timestamp_specific(int type)
{
	ULONGLONG ret;

	ret = GetTickCount64();

	if (type == SYS_JIFFY_T_IN_SEC) {
		ret = ret / 1000;
	}
	return ret;
}

uint64_t sys_time_elapsed(const void *timestamp1, const void *timestamp2)
{
	ULONGLONG stamp1;
	ULONGLONG stamp2;

	memcpy(&stamp1, timestamp1, sizeof(stamp1));
	memcpy(&stamp2, timestamp2, sizeof(stamp2));

	return stamp2 - stamp1;
}
