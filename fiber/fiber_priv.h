#ifndef __FIBER_FIBER_PRIV_H__
#define __FIBER_FIBER_PRIV_H__

struct fiber_task;
typedef int     (*fiber_callback)(struct fiber_task *, void *arg);

#endif
