#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "hosal/thread.h"
#include "hosal/timer.h"
#include "hosal/byteorder.h"
#include "hosal/atomic.h"
#include "hosal/fiber.h"

#include "lib/list.h"
#include "lib/skiplist.h"
#include "lib/hash.h"
#include "lib/errno.h"
#include "lib/misc.h"
#include "lib/compiler.h"

#include "log/allocator.h"

#include "fiber/fiber.h"
#include "fiber/socket.h"

struct fiber_loop {
	struct sys_thread	thread;
	struct sys_lock		lock;
	struct sys_cond		cond;
	struct list_head	task_suspend;
	struct list_head	task_ready;
	struct skiplist		timers;
	struct hash		*task_table;
	atomic_t		task_id;
	unsigned long		timer_origin;
	unsigned int		task_nr;
	int			exit_sched;
	int			ret;
	struct sys_fiber_loop	plat_data;
};

/* event handlers */
static void fiber_event_submit(struct fiber_loop *floop,
	const struct fiber_event *fevent);
static void fiber_event_cancel(struct fiber_loop *floop,
	const struct fiber_event *fevent);

/*
 * task state changes - run in fiber_loop context
 */
static void fiber_task_done(struct fiber_task *ftask, int ret);
static void fiber_task_resume(struct fiber_task *ftask, int last_ret);
static void fiber_task_suspend(struct fiber_task *ftask);

static int fiber_timer_cmp(const struct skiplist_node *snode1,
	const struct skiplist_node *snode2)
{
	const struct fiber_timer *timer1 = container_of(snode1, struct fiber_timer, snode);
	const struct fiber_timer *timer2 = container_of(snode2, struct fiber_timer, snode);

	if (timer1->expire < timer2->expire)
		return SL_CMP_LT;
	else if (timer1->expire > timer2->expire)
		return SL_CMP_GT;
	else
		return SL_CMP_EQ;
}

#define FIBER_TASK_HTABLE_MAX		128
#define FIBER_TASK_HTABLE_MASK		(FIBER_TASK_HTABLE_MAX - 1)

static unsigned int fiber_task_hash(const void *obj)
{
	const struct fiber_task *ftask = obj;

	return (ftask->id & FIBER_TASK_HTABLE_MASK);
}

static int fiber_task_equal(const void *obj1, const void *obj2)
{
	const struct fiber_task *ftask1 = obj1;
	const struct fiber_task *ftask2 = obj2;

	return (ftask1->id == ftask2->id);
}

static void *fiber_loop_main(void *arg);
struct fiber_loop *fiber_loop_create(void)
{
	struct fiber_loop *floop;
	int ret;

	floop = malloc(sizeof(struct fiber_loop));
	if (!floop)
		return NULL;
	floop->ret = ERR_OK + 1;

	floop->task_table = hash_alloc(FIBER_TASK_HTABLE_MAX, offset_of(struct fiber_task, hash_node),
		fiber_task_hash, fiber_task_equal);
	if (!floop->task_table)
		goto free_out;

	ret = sys_lock_init(&floop->lock);
	if (ret != ERR_OK)
		goto free_hash_out;

	ret = sys_cond_init(&floop->cond, &floop->lock);
	if (ret != ERR_OK)
		goto free_lock_out;

	/* MUST be initialized before thread is created */
	floop->task_id = 0;
	floop->exit_sched = 0;
	floop->task_nr = 0;
	skiplist_init(&floop->timers, fiber_timer_cmp);
	init_list_head(&floop->task_suspend);
	init_list_head(&floop->task_ready);

	sys_thread_init(&floop->thread, fiber_loop_main, floop);
	ret = sys_thread_create(&floop->thread);
	if (ret != ERR_OK)
		goto free_cond_out;

	/* wait for fiber loop to finish its own initialization */
	sys_locking(&floop->lock);
	if (floop->ret == ERR_OK + 1)
		sys_cond_wait(&floop->cond);
	sys_unlocking(&floop->lock);

	if (floop->ret != ERR_OK)
		goto wait4_thread_out;

	ret = sys_fiber_creator_init(&floop->plat_data);
	if (ret != ERR_OK) {
		sys_thread_kill(&floop->thread);
		goto wait4_thread_out;
	}

	return floop;
wait4_thread_out:
	sys_thread_wait(&floop->thread);
	sys_thread_destroy(&floop->thread);
free_cond_out:
	sys_cond_finit(&floop->cond);
free_lock_out:
	sys_lock_finit(&floop->lock);
free_hash_out:
	hash_free(floop->task_table);
free_out:
	free(floop);
	return NULL;
}

void fiber_loop_destroy(struct fiber_loop *floop)
{
	/* notify the main loop */
	sys_fiber_send_cmd(&floop->plat_data, FIBER_EVENT_T_EXIT, 0, 0, NULL);

	sys_thread_wait(&floop->thread);
	sys_thread_destroy(&floop->thread);
	sys_fiber_creator_exit(&floop->plat_data);
	sys_cond_finit(&floop->cond);
	sys_lock_finit(&floop->lock);
	hash_free(floop->task_table);
	free(floop);
}

struct fiber_loop *fiber_loop_current(void)
{
	return (struct fiber_loop *)sys_get_tls();
}

void fiber_init(struct fiber_task *ftask, fiber_callback task_cbk,
	fiber_destructor destructor, void *local)
{
	ftask->floop = NULL;
	ftask->parent = NULL;
	memset(ftask->labels, 0, sizeof(ftask->labels));
	ftask->state = FIBER_TASK_S_INIT;
	ftask->yield_reason = FIBER_YIELD_R_NONE;
	ftask->yield_sock = NULL;
	ftask->last_yield_reason = FIBER_YIELD_R_NONE;
	ftask->last_yield_sock = NULL;
	ftask->last_ret = ERR_OK;
	ftask->local_var = local;
	ftask->task_cbk = task_cbk;
	ftask->destructor = destructor;
	init_list_head(&ftask->user_event);
}

struct fiber_task *fiber_alloc(unsigned int local_var_size,
	fiber_callback task_cbk,
	fiber_destructor destructor)
{
	struct fiber_task *ftask;
	unsigned int obj_size = ALIGN_UP(sizeof(struct fiber_task), 8);
	int ret;

	ftask = malloc(obj_size + local_var_size);
	if (!ftask)
		return NULL;

	fiber_init(ftask, task_cbk, destructor, ((uint8_t *)ftask) + obj_size);

	if (!destructor) {
		ret = sys_lock_init(&ftask->lock);
		if (ret != ERR_OK) {
			free(ftask);
			return NULL;
		}
		ret = sys_cond_init(&ftask->cond, &ftask->lock);
		if (ret != ERR_OK) {
			sys_lock_finit(&ftask->lock);
			free(ftask);
			return NULL;
		}
	}

	return ftask;
}

void fiber_free(struct fiber_task *ftask)
{
	if (!ftask->destructor) {
		sys_lock_finit(&ftask->lock);
		sys_cond_finit(&ftask->cond);
	}
	free(ftask);
}

void *fiber_local(struct fiber_task *ftask)
{
	return ftask->local_var;
}

int fiber_submit(struct fiber_loop *floop, struct fiber_task *ftask, fiber_task_id *id)
{
	ftask->floop = floop;
	ftask->state = FIBER_TASK_S_INIT;
	ftask->last_ret = ERR_OK;
	ftask->tier = 0;
	ftask->id = (fiber_task_id)sys_atomic_inc_return(&floop->task_id);

	*id = ftask->id;

	if (!fiber_loop_is_current(floop)) {
		return sys_fiber_send_cmd(&floop->plat_data, FIBER_EVENT_T_SUBMIT,
			(uint64_t)ftask, 0, NULL);
	} else {
		struct fiber_event fevent;

		assert(ftask->destructor != NULL);

		fevent.type = FIBER_EVENT_T_SUBMIT;
		fevent.data = (uint64_t)ftask;
		fiber_event_submit(floop, &fevent);
		return ERR_OK;
	}
}

void fiber_cancel(struct fiber_loop *floop, fiber_task_id id)
{
	if (!fiber_loop_is_current(floop)) {
		sys_fiber_send_cmd(&floop->plat_data, FIBER_EVENT_T_CANCEL, (uint64_t)id, 0, NULL);
	} else {
		struct fiber_event fevent;

		fevent.type = FIBER_EVENT_T_CANCEL;
		fevent.data = (uint64_t)id;

		fiber_event_cancel(floop, &fevent);
	}
}

static int __fiber_event_notify(struct fiber_loop *floop, fiber_task_id id,
	void *msg_data, fiber_finish_cb finish_cb)
{
	struct fiber_task tmp;
	struct fiber_task *ftask;
	struct fiber_user_event *user_event;

	tmp.id = id;
	ftask = hash_find(floop->task_table, &tmp);
	if (!ftask) {
		return ERR_NOT_FOUND;
	}

	user_event = mem_logged_alloc(sizeof(struct fiber_user_event), MEM_FIBER_UEVENT);
	if (!user_event) {
		return ERR_NOMEM;
	}

	user_event->msg_data = msg_data;
	user_event->finish_cb = finish_cb;

	list_add_tail(&ftask->user_event, &user_event->node);

	if (ftask->yield_reason == FIBER_YIELD_R_WAIT4_UEVENT) {
		fiber_schedule(ftask, ERR_OK);
	}

	return ERR_OK;
}

int fiber_notify(struct fiber_loop *floop, fiber_task_id id, void *msg_data,
	fiber_finish_cb finish_cb)
{
	if (!fiber_loop_is_current(floop)) {
		return sys_fiber_send_cmd(&floop->plat_data, FIBER_EVENT_T_USER,
			(uint64_t)id, (uint64_t)finish_cb, msg_data);
	} else {
		return __fiber_event_notify(floop, id, msg_data, finish_cb);
	}
}

void fiber_wait(struct fiber_task *ftask)
{
	assert(ftask->destructor == NULL);

	sys_locking(&ftask->lock);
	if (ftask->state != FIBER_TASK_S_DONE)
		sys_cond_wait(&ftask->cond);
	sys_unlocking(&ftask->lock);
}

void fiber_schedule(struct fiber_task *ftask, int last_ret)
{
	struct fiber_loop *floop = ftask->floop;

	if (ftask->state != FIBER_TASK_S_SUSPEND) {
		return;
	}

	ftask->state = FIBER_TASK_S_SCHED;
	ftask->last_ret = last_ret;

	list_del_node(&floop->task_suspend, &ftask->node);
	list_add_tail(&floop->task_ready, &ftask->node);
}

void fiber_timeout(struct fiber_timer *ftimer, void *data)
{
	struct fiber_task *ftask;

	ftask = container_of(ftimer, struct fiber_task, timer);
	fiber_schedule(ftask, ERR_TIMEOUT);
}

static void fiber_timer_sched(struct fiber_loop *floop, struct fiber_timer *ftimer,
	unsigned long ms, void (*timer_func)(struct fiber_timer *, void *), void *data)
{
	unsigned long current;

	current = sys_get_timestamp_specific(SYS_JIFFY_T_IN_MS);
	if (skiplist_empty(&floop->timers)) {
		floop->timer_origin = current;
	}

	ftimer->expire = current - floop->timer_origin + ms;
	ftimer->floop = floop;
	ftimer->timer_func = timer_func;
	ftimer->data = data;

	skiplist_insert(&floop->timers, &ftimer->snode);
}

static inline void fiber_timer_unsched(struct fiber_loop *floop, struct fiber_timer *ftimer)
{
	/*
	 * fiber_timer deletion MUST take place in the same fiber_loop
	 * as the one it is scheduled on
	 */
	assert(floop == ftimer->floop);

	skiplist_delete(&floop->timers, &ftimer->snode);
	ftimer->floop = NULL;
	ftimer->data = NULL;
}

/*
 * timer mod and del MUST be called in the same fiber_loop as it is scheduled on
 */
void fiber_timer_mod(struct fiber_timer *ftimer, unsigned long expire_in_ms,
	void (*timer_func)(struct fiber_timer *, void *), void *data)
{
	struct fiber_loop *floop;

	/* a timer MUST be scheduled in an floop context */
	floop = sys_get_tls();
	assert(floop);

	if (fiber_timer_is_sched(ftimer)) {
		fiber_timer_unsched(floop, ftimer);
	}
	fiber_timer_sched(floop, ftimer, expire_in_ms, timer_func, data);
}

void fiber_timer_del(struct fiber_timer *ftimer)
{
	struct fiber_loop *floop;

	if (!fiber_timer_is_sched(ftimer)) {
		return;
	}

	floop = sys_get_tls();
	assert(floop);

	fiber_timer_unsched(floop, ftimer);
}

unsigned long fiber_timer_tte(struct fiber_timer *ftimer)
{
	struct fiber_loop *floop;
	unsigned long current;

	if (!fiber_timer_is_sched(ftimer)) {
		return 0;
	}

	floop = ftimer->floop;
	/* only allowed to be called by the same fiber loop */
	assert(fiber_loop_is_current(floop));

	current = sys_get_timestamp_specific(SYS_JIFFY_T_IN_MS)
		- floop->timer_origin;
	if (current < ftimer->expire) {
		return 0;
	} else {
		return current - ftimer->expire;
	}
}

/* in conjunction with FIBER_MSLEEP */
static void fiber_msleep_timeout(struct fiber_timer *ftimer, void *data)
{
	struct fiber_task *ftask;

	ftask = container_of(ftimer, struct fiber_task, timer);
	fiber_schedule(ftask, ERR_TIMEOUT);
}

int fiber_msleep(struct fiber_task *ftask, unsigned long ms)
{
	struct fiber_timer *ftimer = &ftask->timer;

	if (ms == 0)
		return ERR_TIMEOUT;

	if (ms > FIBER_MSLEEP_MAX)
		return ERR_INVAL;

	fiber_timer_mod(ftimer, ms, fiber_msleep_timeout, NULL);
	return ERR_INPROGRESS;
}

/* in conjunction with FIBER_GET_USER_EVENT */
int fiber_get_user_event(struct fiber_task *ftask, struct fiber_user_event **uevent)
{
	struct list_node *node;
	struct fiber_user_event *_uevent;

	if (is_list_empty(&ftask->user_event))
		return ERR_INPROGRESS;

	node = list_first_node(&ftask->user_event);
	list_del_node(&ftask->user_event, node);
	_uevent = container_of(node, struct fiber_user_event, node);
	*uevent = _uevent;

	return ERR_OK;
}

/* in conjunction with FIBER_WAIT_COND */
void fiber_cond_set(struct fiber_cond *fcond)
{
	struct list_node *node;
	struct list_node *temp;
	struct fiber_task *ftask;

	fcond->is_set = 1;
	list_for_head2tail_safe(&fcond->ftask_list, node, temp) {
		ftask = container_of(node, struct fiber_task, cond_node);
		fiber_schedule(ftask, ERR_OK);
	}
	init_list_head(&fcond->ftask_list);
}

void fiber_cond_reset(struct fiber_cond *fcond)
{
	fcond->is_set = 0;
}

/*
 * Called by fiber tasklets -- free a user event
 * when a fiber tasklet is done with it
 */
void fiber_return_user_event(struct fiber_user_event *uevent, int result)
{
	if (uevent->finish_cb) {
		uevent->finish_cb(uevent->msg_data, result);
	}
	mem_logged_free(uevent, MEM_FIBER_UEVENT);
}

static void fiber_loop_exit(struct fiber_loop *floop)
{
	sys_fiber_thread_exit(&floop->plat_data);
	sys_thread_exit();
}

static void fiber_may_del_old_monitor(struct fiber_task *ftask);
/*
 * NOTE: @ftask becomes invalid. NO access to @ftask after below call
 */
static void fiber_task_done(struct fiber_task *ftask, int ret)
{
	struct fiber_loop *floop = ftask->floop;
	struct list_node *node;
	struct list_node *temp;
	struct fiber_user_event *uevent;

	fiber_may_del_old_monitor(ftask);
	ftask->last_yield_sock = NULL;
	ftask->last_yield_reason = FIBER_YIELD_R_NONE;

	ftask->result = ret;
	hash_del(floop->task_table, ftask);

	list_for_head2tail_safe(&ftask->user_event, node, temp) {
		uevent = container_of(node, struct fiber_user_event, node);
		fiber_return_user_event(uevent, ERR_ABORTED);
	}

	if (!ftask->destructor) {
		sys_locking(&ftask->lock);
		ftask->state = FIBER_TASK_S_DONE;
		sys_cond_signal(&ftask->cond);
		sys_unlocking(&ftask->lock);
	} else {
		ftask->state = FIBER_TASK_S_DONE;
		ftask->destructor(ftask);
	}

	assert(floop->task_nr > 0);
	if (--floop->task_nr == 0 && floop->exit_sched) {
		fiber_loop_exit(floop);
	}
}

static void fiber_may_del_old_monitor(struct fiber_task *ftask)
{
	if (!ftask->last_yield_sock) {
		return;
	}

	if (ftask->last_yield_reason == FIBER_YIELD_R_WAIT4_READ) {
		sys_fiber_read_monitor(ftask, &ftask->floop->plat_data, ftask->last_yield_sock,
			0);
	} else if (ftask->last_yield_reason == FIBER_YIELD_R_WAIT4_WRITE) {
		sys_fiber_write_monitor(ftask, &ftask->floop->plat_data, ftask->last_yield_sock,
 			0);
	} else {
		assert(ftask->last_yield_reason == FIBER_YIELD_R_NONE);
	}
}

static void fiber_task_suspend(struct fiber_task *ftask)
{
	ftask->state = FIBER_TASK_S_SUSPEND;
	list_add_tail(&ftask->floop->task_suspend, &ftask->node);

	if (ftask->yield_reason == ftask->last_yield_reason &&
			ftask->yield_sock == ftask->last_yield_sock) {
		return;
	}

	fiber_may_del_old_monitor(ftask);

	if (ftask->yield_reason == FIBER_YIELD_R_WAIT4_READ) {
		sys_fiber_read_monitor(ftask, &ftask->floop->plat_data, ftask->yield_sock,
			1);
	} else if (ftask->yield_reason == FIBER_YIELD_R_WAIT4_WRITE) {
		sys_fiber_write_monitor(ftask, &ftask->floop->plat_data, ftask->yield_sock,
 			1);
	}

	/* Get ready for next suspend */
	ftask->last_yield_reason = ftask->yield_reason;
	ftask->last_yield_sock = ftask->yield_sock;
}

static void fiber_task_resume(struct fiber_task *ftask, int last_ret)
{
	struct fiber_task *parent = ftask->parent;
	int ret;

	ftask->tier = 0;
	ftask->last_ret = last_ret;
	ret = ftask->task_cbk(ftask, NULL);
	if (ret != ERR_INPROGRESS) {
		fiber_task_done(ftask, ret);
		if (parent)
			fiber_task_resume(parent, ret);
	} else {
		fiber_task_suspend(ftask);
	}
}

/* main event loop facilitators */
static void fiber_event_submit(struct fiber_loop *floop,
	const struct fiber_event *fevent)
{
	struct fiber_task *ftask = (struct fiber_task *)(fevent->data);

	/* initialize task timer in the context of floop */
	fiber_timer_init(&ftask->timer);

	floop->task_nr++;
	hash_insert(floop->task_table, ftask);

	ftask->state = FIBER_TASK_S_SUSPEND;
	list_add_tail(&floop->task_suspend, &ftask->node);

	fiber_schedule(ftask, ERR_OK);
}

static void fiber_event_cancel(struct fiber_loop *floop,
	const struct fiber_event *fevent)
{
	fiber_task_id id = (fiber_task_id)(fevent->data);
	struct fiber_task tmp;
	struct fiber_task *ftask;

	tmp.id = id;
	ftask = hash_find(floop->task_table, &tmp);
	if (!ftask)
		return;

	//TODO
	(void)ftask;
}

static void fiber_event_exit(struct fiber_loop *floop,
	const struct fiber_event *fevent)
{
	floop->exit_sched = 1;

	if (floop->task_nr == 0)
		fiber_loop_exit(floop);
}

static void fiber_event_read(struct fiber_loop *floop,
	const struct fiber_event *fevent)
{
	struct socket *s = (struct socket *)(fevent->data);
	struct fiber_task *read_ftask[SYS_FIBER_FTASK_MAX];
	unsigned int nr = 0;
	unsigned int i;

	sys_fiber_read_ftask(s, read_ftask);

	for (i = 0; i < ARRAY_SIZE(read_ftask); i++) {
		if (read_ftask[i]) {
			nr++;
			fiber_schedule(read_ftask[i], ERR_OK);
		}
	}

	/* fiber tasks waiting on READ event must be present */
	assert(nr > 0);
}

static void fiber_event_write(struct fiber_loop *floop,
	const struct fiber_event *fevent)
{
	struct socket *s = (struct socket *)(fevent->data);
	struct fiber_task *write_ftask[SYS_FIBER_FTASK_MAX];
	unsigned int nr = 0;
	unsigned int i;

	sys_fiber_write_ftask(s, write_ftask);

	for (i = 0; i < ARRAY_SIZE(write_ftask); i++) {
		if (write_ftask[i]) {
			nr++;
			fiber_schedule(write_ftask[i], ERR_OK);
		}
	}

	/* fiber tasks waiting on WRITE event must be present */
	assert(nr > 0);
}

static void fiber_event_error(struct fiber_loop *floop,
	const struct fiber_event *fevent)
{
	struct socket *s = (struct socket *)(fevent->data);
	struct fiber_task *read_ftask[SYS_FIBER_FTASK_MAX];
	struct fiber_task *write_ftask[SYS_FIBER_FTASK_MAX];
	unsigned int i;

	sys_fiber_read_ftask(s, read_ftask);
	sys_fiber_write_ftask(s, write_ftask);

	for (i = 0; i < ARRAY_SIZE(read_ftask); i++) {
		if (read_ftask[i]) {
			fiber_schedule(read_ftask[i], ERR_OK);
		}
	}

	for (i = 0; i < ARRAY_SIZE(write_ftask); i++) {
		if (write_ftask[i]) {
			fiber_schedule(write_ftask[i], ERR_OK);
		}
	}
}

static void fiber_handle_timeout_chain(struct fiber_loop *floop, struct skiplist_node *snode)
{
	struct fiber_timer *ftimer;
	struct skiplist_node *snode_tmp;
	void *data;

	skiplist_eradicate(&floop->timers, snode);

	while (snode) {
		snode_tmp = snode->buddy_next;
		ftimer = container_of(snode, struct fiber_timer, snode);
		data = ftimer->data;
		ftimer->floop = NULL;
		ftimer->data = NULL;
		ftimer->timer_func(ftimer, data);
		snode = snode_tmp;
	}
}

static void fiber_event_timeout(struct fiber_loop *floop,
	const struct fiber_event *fevent)
{
	struct skiplist_node *snode = skiplist_first(&floop->timers);

	assert(snode != NULL);
	fiber_handle_timeout_chain(floop, snode);
}

static void fiber_event_notify(struct fiber_loop *floop,
	const struct fiber_event *fevent)
{
	fiber_task_id id = (fiber_task_id)(fevent->data);
	fiber_finish_cb finish_cb;
	uint64_t tmp_be64;
	void *msg_data;
	int ret;

	finish_cb = (fiber_finish_cb)(fevent->data2);

	memcpy(&tmp_be64, fevent->user_data, sizeof(tmp_be64));
	tmp_be64 = sys_betoh64(tmp_be64);
	msg_data = (void *)tmp_be64;

	ret = __fiber_event_notify(floop, id, msg_data, finish_cb);
	if (ret != ERR_OK && finish_cb) {
		finish_cb(msg_data, ret);
	}
}

static void fiber_event_handler(struct fiber_loop *floop, struct fiber_event *fevent)
{
	typedef void (*event_handler_cbk)(struct fiber_loop *, const struct fiber_event *fevent);
	static const event_handler_cbk cbks[FIBER_EVENT_T_MAX] = {
		[FIBER_EVENT_T_SUBMIT] = fiber_event_submit,
		[FIBER_EVENT_T_CANCEL] = fiber_event_cancel,
		[FIBER_EVENT_T_EXIT] = fiber_event_exit,
		[FIBER_EVENT_T_READ] = fiber_event_read,
		[FIBER_EVENT_T_WRITE] = fiber_event_write,
		[FIBER_EVENT_T_ERROR] = fiber_event_error,
		[FIBER_EVENT_T_TIMEOUT] = fiber_event_timeout,
		[FIBER_EVENT_T_USER] = fiber_event_notify,
	};

	if (unlikely(fevent->type >= FIBER_EVENT_T_MAX))
		return;

	cbks[fevent->type](floop, fevent);
}

static unsigned long fiber_check_timers(struct fiber_loop *floop)
{
	struct skiplist_node *snode = skiplist_first(&floop->timers);
	struct fiber_timer *ftimer;
	unsigned long current;

	if (!snode)
		return 0;	/* return value does not matter */

	while (snode) {
		current = sys_get_timestamp_specific(SYS_JIFFY_T_IN_MS) - floop->timer_origin;

		ftimer = container_of(snode, struct fiber_timer, snode);

		if (current < ftimer->expire)
			break;

		fiber_handle_timeout_chain(floop, snode);

		snode = skiplist_first(&floop->timers);
	}

	return current;
}

void fiber_may_resume_tasks(struct fiber_loop *floop)
{
	struct fiber_task *ftask;
	struct list_node *node;
	struct list_node *temp;
	DEFINE_LIST_HEAD(ftask_head);

	/* move all available tasks to @ftask_head */
	while (!is_list_empty(&floop->task_ready)) {
		list_for_head2tail_safe(&floop->task_ready, node, temp) {
			ftask = container_of(node, struct fiber_task, node);
			list_add_tail(&ftask_head, &ftask->node2);
		}
		init_list_head(&floop->task_ready);

		list_for_head2tail_safe(&ftask_head, node, temp) {
			ftask = container_of(node, struct fiber_task, node2);

			ftask->state = FIBER_TASK_S_RUNNING;
			fiber_task_resume(ftask, ftask->last_ret);
		}
		init_list_head(&ftask_head);
	}
}

static void *fiber_loop_main(void *arg)
{
	struct fiber_loop *floop = arg;
	struct fiber_timer *ftimer;
	struct skiplist_node *snode;
	int ret;
	unsigned long current;
	unsigned long wait_ms;

	ret = sys_fiber_thread_init(&floop->plat_data);
	if (ret == ERR_OK) {
		ret = sys_set_tls(floop);
	}

	sys_locking(&floop->lock);
	floop->ret = ret;
	sys_cond_signal(&floop->cond);
	sys_unlocking(&floop->lock);

	if (ret != ERR_OK)
		return NULL;

	while (1) {
		current = fiber_check_timers(floop);
		snode = skiplist_first(&floop->timers);
		if (snode) {
			ftimer = container_of(snode, struct fiber_timer, snode);
			wait_ms = ftimer->expire - current;

			assert(wait_ms != 0);
		} else {
			wait_ms = FIBER_WAIT4_INFINITE;
		}
		fiber_may_resume_tasks(floop);

		sys_fiber_wait4_event(&floop->plat_data, floop, wait_ms, fiber_event_handler);
		fiber_may_resume_tasks(floop);
	}

	/*
	 * Never here as aio_loop_destroy() sends an event to trigger
	 * sys_thread_exit() call
	 */
	assert(0);
	return NULL;
}
