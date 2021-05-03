#ifndef __HOSAL_FIBER_H__
#define __HOSAL_FIBER_H__

#include <stdint.h>

struct sys_fiber_loop;
struct fiber_loop;
struct fiber_event;
extern int sys_fiber_thread_init(struct sys_fiber_loop *fbl);
extern void sys_fiber_thread_exit(struct sys_fiber_loop *fbl);
extern int sys_fiber_send_cmd(struct sys_fiber_loop *fbl, uint8_t event_type,
	uint64_t pointer_data, uint64_t pointer_data2, void *user_data);
extern int sys_fiber_creator_init(struct sys_fiber_loop *fbl);
extern void sys_fiber_creator_exit(struct sys_fiber_loop *fbl);
extern void sys_fiber_wait4_event(struct sys_fiber_loop *fbl, struct fiber_loop *floop,
	unsigned long wait_ms,
	void (*event_cbk)(struct fiber_loop *, struct fiber_event *));

struct socket;
struct fiber_task;
extern int sys_fiber_read_monitor(struct fiber_task *ftask,
	struct sys_fiber_loop *fbl, struct socket *s, int is_set);
extern int sys_fiber_write_monitor(struct fiber_task *ftask,
	struct sys_fiber_loop *fbl, struct socket *s, int is_set);

#define SYS_FIBER_FTASK_MAX	2
extern void sys_fiber_read_ftask(struct socket *s, struct fiber_task *array[SYS_FIBER_FTASK_MAX]);
extern void sys_fiber_write_ftask(struct socket *s, struct fiber_task *array[SYS_FIBER_FTASK_MAX]);

struct sys_fiber_event {
        uint64_t	pointer;
        uint64_t	pointer2;
	uint8_t		type;
        uint8_t		user_data[15];
}__attribute__ ((packed));

#ifdef __linux__
#include "hosal/linux/fiber.h"
#elif defined WIN32
#include "hosal/windows/fiber.h"
#elif defined __APPLE__
#include "hosal/osx/fiber.h"
#else
#error "Non-supported OS model"
#endif

#endif
