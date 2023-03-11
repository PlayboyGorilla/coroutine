#ifndef __HOSAL_TIMER_H__
#define __HOSAL_TIMER_H__

#include "lib/list.h"
#include "lib/types.h"
#include "lib/errno.h"

extern void subsys_timer_init(void);
extern void subsys_timer_exit(void);

/* misc */
struct sys_time {
	uint8_t		day;
	uint8_t		month;
	uint16_t	year;
	uint8_t		hour;
	uint8_t		min;
	uint8_t		sec;
	uint16_t	msec;
	int8_t		utc_hour_offset;
	int8_t		utc_min_offset;
	char		time_zone[8];
};

struct sys_timestamp_stub {
	uint64_t	_u64[4];
};

extern int sys_time_get(struct sys_time *);
extern unsigned long sys_get_jiffies(void);
extern void sys_get_timestamp(void *timestamp);
#define SYS_JIFFY_T_IN_SEC	0
#define SYS_JIFFY_T_IN_MS	1
#define SYS_JIFFY_T_IN_US	2
#define SYS_JIFFY_T_MAX		3
extern unsigned long sys_get_timestamp_specific(int type);
extern uint64_t sys_time_elapsed(const void *timestamp1, const void *timestamp2);

/* platform-dependent */
#ifdef __linux__
#include "hosal/linux/timer.h"
#elif defined WIN32
#include "hosal/win/timer.h"
#elif defined __APPLE__
#include "hosal/osx/timer.h"
#else
#error "Non-supported OS model"
#endif

#endif
