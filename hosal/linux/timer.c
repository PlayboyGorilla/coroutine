#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "lib/compiler.h"
#include "lib/errno.h"
#include "lib/misc.h"

#include "hosal/timer.h"

struct sys_uptime_obtainer {
	unsigned int ts_len;	/* object length to store a timestamp */
	clockid_t clkid;
	int (*detect)(struct sys_uptime_obtainer *ob);	/* detect whether its applicable to the current system */
	void (*get)(struct sys_uptime_obtainer *ob, void *timestamp);
	uint64_t (*elapsed)(const void *timestamp1, const void *timestamp2); /* return timestamp2 - timestamp1, in ms */
};

static int clk_common_detect(struct sys_uptime_obtainer *ob)
{
	struct timespec spec;
	int ret;

	ret = clock_getres(ob->clkid, &spec);
	if (ret < 0)
		return 0;

	if (spec.tv_sec != 0 || spec.tv_nsec > 1000000)
		return 0;

	return 1;
}

static void clk_common_get(struct sys_uptime_obtainer *ob, void *timestamp)
{
	struct timespec *spec = (struct timespec *)timestamp;
	int ret;

	ret = clock_gettime(ob->clkid, spec);
	assert(ret == 0);
}

static uint64_t clk_common_elapsed(const void *timestamp1, const void *timestamp2)
{
	const struct timespec *spec1 = timestamp1;
	const struct timespec *spec2 = timestamp2;
	uint64_t sec_diff;
	uint64_t nsec_diff;

	if (unlikely(spec2->tv_sec < spec1->tv_sec)) {
		assert(0);
	} else if (spec2->tv_sec == spec1->tv_sec) {
		assert(spec2->tv_nsec >= spec1->tv_nsec);
	}

        sec_diff = spec2->tv_sec - spec1->tv_sec;
        if (spec2->tv_nsec < spec1->tv_nsec) {
                nsec_diff = spec2->tv_nsec + 1000000000 - spec1->tv_nsec;
                sec_diff--;
        } else {
                nsec_diff = spec2->tv_nsec - spec1->tv_nsec;
        }

        return (sec_diff * 1000 + nsec_diff / 1000000);
}

static struct sys_uptime_obtainer sys_boottime = {
	.ts_len = sizeof(struct timespec),
	.clkid = CLOCK_BOOTTIME,
	.detect = clk_common_detect,
	.get = clk_common_get,
	.elapsed = clk_common_elapsed
};

static struct sys_uptime_obtainer sys_monotonic_raw = {
	.ts_len = sizeof(struct timespec),
	.clkid = CLOCK_MONOTONIC_RAW,
	.detect = clk_common_detect,
	.get = clk_common_get,
	.elapsed = clk_common_elapsed
};

static struct sys_uptime_obtainer sys_monotonic = {
	.ts_len = sizeof(struct timespec),
	.clkid = CLOCK_MONOTONIC,
	.detect = clk_common_detect,
	.get = clk_common_get,
	.elapsed = clk_common_elapsed
};

static struct sys_uptime_obtainer sys_monotonic_coarse = {
	.ts_len = sizeof(struct timespec),
	.clkid = CLOCK_MONOTONIC_COARSE,
	.detect = clk_common_detect,
	.get = clk_common_get,
	.elapsed = clk_common_elapsed
};

static int gettimeofday_detect(struct sys_uptime_obtainer *ob)
{
	return 1;
}

static void gettimeofday_get(struct sys_uptime_obtainer *ob, void *timestamp)
{
	struct timeval *val = timestamp;

	gettimeofday(val, NULL);
}

static uint64_t gettimeofday_elapsed(const void *timestamp1, const void *timestamp2)
{
	const struct timeval *val1 = timestamp1;
	const struct timeval *val2 = timestamp2;
	uint64_t sec_diff;
	uint64_t usec_diff;

	if (unlikely(val2->tv_sec < val1->tv_sec)) {
		assert(0);
	} else if (val2->tv_sec == val1->tv_sec) {
		assert(val2->tv_usec >= val1->tv_usec);
	}

	sec_diff = val2->tv_sec - val1->tv_sec;
	if (val2->tv_usec < val1->tv_usec) {
		usec_diff = val2->tv_usec + 1000000 - val1->tv_usec;
		sec_diff--;
	} else {
		usec_diff = val2->tv_usec - val1->tv_usec;
	}

	return (sec_diff * 1000 + usec_diff / 1000);
}

static struct sys_uptime_obtainer sys_gettimeofday = {
	.ts_len = sizeof(struct timeval),
	.clkid = 0,
	.detect = gettimeofday_detect,
	.get = gettimeofday_get,
	.elapsed = gettimeofday_elapsed
};

static struct sys_uptime_obtainer *obtainers[] = {
	&sys_monotonic_raw,
	&sys_boottime,
	&sys_monotonic,
	&sys_monotonic_coarse,
	&sys_gettimeofday
};

static struct sys_uptime_obtainer *uptime_obtainer = NULL;

static void subsys_find_uptime_obtainer(void)
{
	unsigned int i;
	struct sys_uptime_obtainer *ob;

	for (i = 0; i < ARRAY_SIZE(obtainers); i++) {
		ob = obtainers[i];
		if (ob->detect(ob)) {
			uptime_obtainer = ob;
			break;
		}
	}

	assert(uptime_obtainer != NULL);
}

/*
* Must be called in the main thread, before everything else
*/
void subsys_timer_init(void)
{
	compile_time_assert(sizeof(struct sys_timestamp_stub) >= sizeof(struct timeval));
	compile_time_assert(sizeof(struct sys_timestamp_stub) >= sizeof(struct timespec));

	subsys_find_uptime_obtainer();
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
	uptime_obtainer->get(uptime_obtainer, timestamp);
}

unsigned long sys_get_timestamp_specific(int type)
{
	struct sys_timestamp_stub curr_time;
	struct sys_timestamp_stub zero_time;
	unsigned long ret;

	memset(&zero_time, 0, sizeof(zero_time));
	sys_get_timestamp(&curr_time);
	ret = uptime_obtainer->elapsed(&zero_time, &curr_time);

	if (type == SYS_JIFFY_T_IN_SEC)
		return ret / 1000;
	else
		return ret;
}

uint64_t sys_time_elapsed(const void *timestamp1, const void *timestamp2)
{
	return uptime_obtainer->elapsed(timestamp1, timestamp2);
}
