#ifndef __LIB_HASH_H__
#define __LIB_HASH_H__

#include "lib/list.h"

struct hash {
	unsigned int		entry_nr;
	unsigned int		node_offset;
	unsigned int		(*cb_hash)(const void *obj);
	int			(*cb_equal)(const void *obj1, const void *obj2);
	struct list_head	hash_tbl[0];
};

#define DEFINE_HASH_TABLE_STRUCT(_size)								\
	struct hash_##_size {									\
		unsigned int		entry_nr;						\
		unsigned int		node_offset;						\
		unsigned int		(*cb_hash)(const void *obj);				\
		int			(*cb_equal)(const void *obj1, const void *obj2);	\
		struct list_head	hash_tbl[_size];					\
	}

#define HASH_TABLE_STRUCT(_size, _name)			\
	struct hash_##_size _name

#define HASH_TABLE(_size, _node_offset, _cb_hash, _cb_equal, _name)			\
	struct hash_##_size _name = {							\
		.entry_nr = _size,							\
		.node_offset = (_node_offset),						\
		.cb_hash = _cb_hash,							\
		.cb_equal = _cb_equal,							\
		.hash_tbl = {{0}},							\
	}

extern void hash_init(struct hash *, unsigned int entry_nr,
	unsigned long node_offset,
	unsigned int (*cb_hash)(const void *obj),
	int (*cb_equal)(const void *obj1, const void *obj2));
extern struct hash *hash_alloc(unsigned int entry_nr,
	unsigned long node_offset,
	unsigned int (*cb_hash)(const void *obj),
	int (*cb_equal)(const void *obj1, const void *obj2));
extern void hash_free(struct hash *);
extern void hash_insert(struct hash *, void *obj);
extern void hash_insert_fast(struct hash *, void *obj, unsigned int hash_val);
extern void hash_del(struct hash *, void *obj);
extern void hash_del_fast(struct hash *, void *obj, unsigned int hash_val);
extern void *hash_find(struct hash *, const void *obj_temp);
extern void hash_iterate(struct hash *, void (*callback)(void *obj, void *data),
	void *data);
extern void hash_clear(struct hash *);

#endif
