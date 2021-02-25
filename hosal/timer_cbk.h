#ifndef __HOSAL_TIMER_CBK_H__
#define __HOSAL_TIMER_CBK_H__

struct sys_timer;
typedef void (*sys_timeout_func) (struct sys_timer *, unsigned long data);

#endif
