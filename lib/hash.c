#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "list.h"
#include "hash.h"

struct hash {
	unsigned int		entry_nr;
	unsigned int		node_offset;
	unsigned int		(*cb_hash)(const void *obj);
	int			(*cb_equal)(const void *obj1, const void *obj2);
	struct list_head	hash_tbl[0];
};

static inline struct list_node *hash_obj_to_node(struct hash *htable, void *obj)
{
	return (struct list_node *)(((uint8_t *)obj) + htable->node_offset);
}

static inline void *hash_node_to_obj(struct hash *htable, struct list_node *node)
{
	return (((uint8_t *)node) - htable->node_offset);
}

struct hash *hash_alloc(unsigned int entry_nr,
	unsigned long node_offset,
	unsigned int (*cb_hash)(const void *obj),
	int (*cb_equal)(const void *obj1, const void *obj2))
{
	struct hash *htable;
	unsigned int i;

	htable = malloc(sizeof(struct hash) + entry_nr * sizeof(struct list_head));
	if (!htable)
		return NULL;

	htable->entry_nr = entry_nr;
	htable->node_offset = node_offset;
	htable->cb_hash = cb_hash;
	htable->cb_equal = cb_equal;

	for (i = 0; i < entry_nr; i++)
		init_list_head(&htable->hash_tbl[i]);

	return htable;
}

void hash_free(struct hash *htable)
{
	free(htable);
}

void hash_insert(struct hash *htable, void *obj)
{
	unsigned int hash_val;
	struct list_node *node;

	hash_val = htable->cb_hash(obj);
	assert(hash_val < htable->entry_nr);

	node = hash_obj_to_node(htable, obj);
	list_add_tail(&htable->hash_tbl[hash_val], node);
}

void hash_insert_fast(struct hash *htable, void *obj, unsigned int hash_val)
{
	struct list_node *node;

	assert(hash_val < htable->entry_nr);

	node = hash_obj_to_node(htable, obj);
	list_add_tail(&htable->hash_tbl[hash_val], node);
}

void hash_del(struct hash *htable, void *obj)
{
	unsigned int hash_val;
	struct list_node *node;

	hash_val = htable->cb_hash(obj);
	assert(hash_val < htable->entry_nr);

	node = hash_obj_to_node(htable, obj);
	list_del_node(&htable->hash_tbl[hash_val], node);
}

void hash_del_fast(struct hash *htable, void *obj, unsigned int hash_val)
{
	struct list_node *node;

	assert(hash_val < htable->entry_nr);

	node = hash_obj_to_node(htable, obj);
	list_del_node(&htable->hash_tbl[hash_val], node);
}

void *hash_find(struct hash *htable, const void *obj_temp)
{
	struct list_node *node;
	void *obj;
	unsigned int hash_val;

	hash_val = htable->cb_hash(obj_temp);
	list_for_head2tail(&htable->hash_tbl[hash_val], node) {
		obj = hash_node_to_obj(htable, node);

		if (htable->cb_equal(obj_temp, obj))
			return obj;
	}

	return NULL;
}
