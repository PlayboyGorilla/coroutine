#ifndef __LIB_HASH_H__
#define __LIB_HASH_H__

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

#endif
