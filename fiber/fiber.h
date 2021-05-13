#ifndef __FIBER_FIBER_H__
#define __FIBER_FIBER_H__

#include <stdint.h>
#include <assert.h>

#include "hosal/thread.h"

#include "fiber/fiber_priv.h"

#include "lib/list.h"
#include "lib/skiplist.h"
#include "lib/errno.h"
#include "lib/compiler.h"

struct fiber_loop;
extern struct fiber_loop *fiber_loop_create(void);
extern void fiber_loop_destroy(struct fiber_loop *floop);
extern struct fiber_loop *fiber_loop_current(void);

static inline int fiber_loop_is_current(struct fiber_loop *floop)
{
	return (fiber_loop_current() == floop);
}

#define FIBER_MSLEEP_MAX	(7 * 24 * 3600 * 1000)
#define FIBER_WAIT4_INFINITE	((unsigned long)(~0))
struct fiber_event {
	uint64_t		data;
	uint64_t		data2;
#define FIBER_EVENT_T_SUBMIT	0
#define FIBER_EVENT_T_CANCEL	1
#define FIBER_EVENT_T_EXIT	2	/* fiber loop to exit */
#define FIBER_EVENT_T_READ	3
#define FIBER_EVENT_T_WRITE	4
#define FIBER_EVENT_T_ERROR	5
#define FIBER_EVENT_T_TIMEOUT	6
#define FIBER_EVENT_T_USER	7
#define FIBER_EVENT_T_MAX	8
	uint8_t			type;
	uint8_t			user_data[15];
	struct list_node	node;
};

struct fiber_timer {
	struct skiplist_node	snode;
	unsigned long		expire;
	struct fiber_loop	*floop;
	void			(*timer_func)(struct fiber_timer *, void *data);
	void			*data;
};

struct fiber_task;

typedef unsigned int	fiber_task_id;
typedef void	(*fiber_destructor)(struct fiber_task *);

#include "fiber/socket.h"

#define FIBER_TASK_MAX_TIER	8
struct fiber_task {
	struct fiber_loop	*floop;
	struct fiber_task	*parent;
	void			*labels[FIBER_TASK_MAX_TIER];
	uint16_t		tier;	/* current tier */
#define FIBER_TASK_S_INIT	0
#define FIBER_TASK_S_SUSPEND	1	/* suspended */
#define FIBER_TASK_S_SCHED	2	/* ready to be scheduled */
#define FIBER_TASK_S_RUNNING	3
#define FIBER_TASK_S_DONE	4
	unsigned int		state;
#define FIBER_YIELD_R_NONE		0
#define FIBER_YIELD_R_MSLEEP		1
#define FIBER_YIELD_R_WAIT4_READ	2
#define FIBER_YIELD_R_WAIT4_WRITE	3
#define FIBER_YIELD_R_WAIT4_UEVENT	4
	unsigned int		yield_reason;
	struct socket		*yield_sock;
	unsigned int		last_yield_reason;
	struct socket		*last_yield_sock;
	struct sys_lock		lock;
	struct sys_cond		cond;
	struct list_node	hash_node;
	struct list_node	node2;
	struct list_node	cond_node;	/* ftask is waiting on a cond */
	struct list_head	user_event;
	fiber_task_id		id;
	int			last_ret;	/* last return value */
	int			result;		/* result of execution */
	struct fiber_timer	timer;		/* multiplexed */
	void			*local_var;
	fiber_callback		task_cbk;
	fiber_destructor	destructor;
};

extern struct fiber_task *fiber_alloc(unsigned int local_var_size,
	fiber_callback task_cbk,
	fiber_destructor destructor);
extern void fiber_free(struct fiber_task *ftask);
extern void *fiber_local(struct fiber_task *ftask);
extern void fiber_init(struct fiber_task *ftask, fiber_callback task_cbk,
	fiber_destructor destructor, void *local);
extern int fiber_submit(struct fiber_loop *, struct fiber_task *, fiber_task_id *id);
extern void fiber_cancel(struct fiber_loop *, fiber_task_id id);
typedef void (*fiber_finish_cb)(void *msg_data, int result);
extern int fiber_notify(struct fiber_loop *, fiber_task_id id, void *msg_data,
	fiber_finish_cb finish_cb);
extern void fiber_wait(struct fiber_task *);
extern void fiber_schedule(struct fiber_task *ftask, int last_ret);

/* fiber primitive -- invoked by fiber taslkets */
extern void fiber_timeout(struct fiber_timer *ftimer, void *data);
#define FIBER_YIELD(_ftask, _sock, _reason, _timeout_ms)						\
	do {												\
		ret = ERR_INPROGRESS;									\
		FIBER_CONCAT(FIBER_LABEL, __LINE__):							\
		if (ret == ERR_INPROGRESS) {								\
			(_ftask)->labels[(_ftask)->tier] = &&FIBER_CONCAT(FIBER_LABEL, __LINE__);	\
			(_ftask)->yield_reason = (_reason);						\
			(_ftask)->yield_sock = (_sock);							\
			if ((_timeout_ms) <= FIBER_MSLEEP_MAX) {					\
				fiber_timer_mod(&(_ftask)->timer, (_timeout_ms),			\
					fiber_timeout, NULL);						\
			}										\
			return ret;									\
		} else {										\
			fiber_timer_del(&(_ftask)->timer);						\
			(_ftask)->yield_reason = FIBER_YIELD_R_NONE;					\
			(_ftask)->yield_sock = NULL;							\
                        (_ftask)->last_ret = ERR_OK;							\
		}											\
	} while(0)

#define FIBER_YIELD_ERR_RETURN(_ftask, _sock, _reason, _timeout_ms)					\
	do {												\
		ret = ERR_INPROGRESS;									\
		FIBER_CONCAT(FIBER_LABEL, __LINE__):							\
		if (ret == ERR_INPROGRESS) {								\
			(_ftask)->labels[(_ftask)->tier] = &&FIBER_CONCAT(FIBER_LABEL, __LINE__);	\
			(_ftask)->yield_reason = (_reason);						\
			(_ftask)->yield_sock = (_sock);							\
			if ((_timeout_ms) <= FIBER_MSLEEP_MAX) {					\
				fiber_timer_mod(&(_ftask)->timer, (_timeout_ms),			\
					fiber_timeout, NULL);						\
			}										\
			return ret;									\
		} else {										\
                        fiber_timer_del(&(_ftask)->timer);						\
			(_ftask)->yield_reason = FIBER_YIELD_R_NONE;					\
			(_ftask)->yield_sock = NULL;							\
                        (_ftask)->last_ret = ERR_OK;							\
			if (ret != ERR_OK) {								\
				return ret;								\
			}										\
		}											\
	} while(0)

#define FIBER_CONCAT2(s1, s2)	s1##s2
#define FIBER_CONCAT(s1, s2)	FIBER_CONCAT2(s1, s2)

#define FIBER_BEGIN(_ftask, _type, _local)				\
	volatile int ret = (_ftask)->last_ret;				\
	_type *_local = fiber_local(_ftask);				\
	(void)ret;							\
	(void)_local;							\
	assert((_ftask)->tier < FIBER_TASK_MAX_TIER);			\
	if ((_ftask)->labels[(_ftask)->tier] != NULL) {			\
		void *__goto_p = (_ftask)->labels[(_ftask)->tier];	\
		(_ftask)->labels[(_ftask)->tier] = NULL;		\
		goto *__goto_p;						\
	}

#define FIBER_END(_ftask, _result)	return (_result)

#define FIBER_ARG_BEGIN(_ftask, _arg, _arg_type, _task_arg)		\
	volatile int ret = (_ftask)->last_ret;				\
	_arg_type *_task_arg = (_arg_type *)(_arg);			\
	(void)ret;							\
	(void)_task_arg;						\
	assert((_ftask)->tier < FIBER_TASK_MAX_TIER);			\
	if ((_ftask)->labels[(_ftask)->tier] != NULL) {			\
		void *__goto_p = (_ftask)->labels[(_ftask)->tier];	\
		(_ftask)->labels[(_ftask)->tier] = NULL;		\
		goto *__goto_p;						\
	}

#define FIBER_ARG_END(_ftask, _result)		return (_result)


/* fiber timer */
static inline void fiber_timer_init(struct fiber_timer *ftimer)
{
	ftimer->floop = NULL;
}

static inline int fiber_timer_is_sched(const struct fiber_timer *ftimer)
{
	return (ftimer->floop != NULL);
}

extern void fiber_timer_mod(struct fiber_timer *ftimer, unsigned long expire_in_ms,
	void (*timer_func)(struct fiber_timer *, void *), void *data);
extern void fiber_timer_del(struct fiber_timer *ftimer);
extern unsigned long fiber_timer_tte(struct fiber_timer *ftimer);

extern int fiber_msleep(struct fiber_task *, unsigned long ms);
#define FIBER_MSLEEP(_ftask, _ms)									\
	do {												\
		ret = fiber_msleep(_ftask, _ms);							\
		FIBER_CONCAT(FIBER_LABEL, __LINE__):							\
		if (ret == ERR_INPROGRESS) {								\
			(_ftask)->labels[(_ftask)->tier] = &&FIBER_CONCAT(FIBER_LABEL, __LINE__);	\
			(_ftask)->yield_reason = FIBER_YIELD_R_MSLEEP;					\
			(_ftask)->yield_sock = NULL;							\
			return ret;									\
		} else if (ret != ERR_TIMEOUT) {							\
			assert(ret != ERR_OK);								\
			return ret;									\
		}											\
	} while (0)

#define FIBER_SUBCO(_ftask, _subco, _arg)								\
	do {												\
		FIBER_CONCAT(FIBER_LABEL, __LINE__):							\
		(_ftask)->tier++;									\
		ret = (_subco)(_ftask, _arg);								\
		(_ftask)->tier--;									\
		if (ret == ERR_INPROGRESS) {								\
			(_ftask)->labels[(_ftask)->tier] = &&FIBER_CONCAT(FIBER_LABEL, __LINE__);	\
			return ret;									\
		}											\
		(_ftask)->last_ret = ERR_OK;								\
	} while (0)

struct fiber_user_event {
	void			*msg_data;
	fiber_finish_cb		finish_cb;
	struct list_node	node;
};

extern void fiber_return_user_event(struct fiber_user_event *uevent, int result);
extern int fiber_get_user_event(struct fiber_task *, struct fiber_user_event **uevent);
#define FIBER_GET_USER_EVENT(_ftask, _uevent)								\
	do {												\
		FIBER_CONCAT(FIBER_LABEL, __LINE__):							\
		ret = fiber_get_user_event(_ftask, &(_uevent));						\
		if (ret == ERR_INPROGRESS) {								\
			(_ftask)->labels[(_ftask)->tier] = &&FIBER_CONCAT(FIBER_LABEL, __LINE__);	\
			(_ftask)->yield_reason = FIBER_YIELD_R_WAIT4_UEVENT;				\
			(_ftask)->yield_sock = NULL;							\
			return ret;									\
		}											\
	} while (0)

/* fiber cond */
struct fiber_cond {
	struct list_head	ftask_list;	/* list of ftasks that are waiting on the cond */
	int			is_set;
};

static inline void fiber_cond_init(struct fiber_cond *fcond)
{
	fcond->is_set = 0;
	init_list_head(&fcond->ftask_list);
}

static inline int fiber_cond_is_set(const struct fiber_cond *fcond)
{
	return fcond->is_set;
}

extern void fiber_cond_set(struct fiber_cond *fcond);
extern void fiber_cond_reset(struct fiber_cond *fcond);

#define FIBER_COND_WAIT(_ftask, _fcond)										\
	do {													\
		if (!(_fcond)->is_set) {									\
			ret = ERR_INPROGRESS;									\
			FIBER_CONCAT(FIBER_LABEL, __LINE__):							\
			if (ret == ERR_INPROGRESS) {								\
				(_ftask)->labels[(_ftask)->tier] = &&FIBER_CONCAT(FIBER_LABEL, __LINE__);	\
				(_ftask)->yield_reason = FIBER_YIELD_R_COND;					\
				(_ftask)->yield_sock = NULL;							\
				list_add_tail(&(_fcond)->ftask_list, &(_ftask)->cond_node);			\
				return ret;									\
			} else {										\
				(_ftask)->yield_reason = FIBER_YIELD_R_NONE;					\
				(_ftask)->yield_sock = NULL;							\
                        	(_ftask)->last_ret = ERR_OK;							\
			}											\
		}												\
	} while (0)

#endif
