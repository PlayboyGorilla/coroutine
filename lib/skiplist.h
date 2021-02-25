#ifndef __LIB_SKIPLIST_H__
#define __LIB_SKIPLIST_H__

#define SL_CMP_GT	1	/* > */
#define SL_CMP_LT	2	/* < */
#define SL_CMP_EQ	3	/* == */

#define SKIPLIST_MAX_LEVEL 8

struct skiplist_node {
	unsigned int level;
	struct skiplist_node *buddy_prev;
	struct skiplist_node *buddy_next;
	struct skiplist_node *prev[SKIPLIST_MAX_LEVEL + 1];
	struct skiplist_node *next[SKIPLIST_MAX_LEVEL + 1];
};

typedef int (*skiplist_compare)(const struct skiplist_node *snode1,
	const struct skiplist_node *snode2);
struct skiplist {
	struct skiplist_node	header;
	skiplist_compare	cmp_cbk;
};

extern void skiplist_init(struct skiplist *list, skiplist_compare cmp_cbk);
extern int skiplist_insert(struct skiplist *list, struct skiplist_node *snode);
extern struct skiplist_node *skiplist_search(struct skiplist *list, struct skiplist_node *temp);
extern struct skiplist_node *skiplist_search_neighbor(struct skiplist *list, struct skiplist_node *temp,
	struct skiplist_node **prev, struct skiplist_node **next);
extern struct skiplist_node *skiplist_find_or_insert(struct skiplist *list, struct skiplist_node *newnode,
	struct skiplist_node **prev, struct skiplist_node **next);
extern void skiplist_eradicate(struct skiplist *list, struct skiplist_node *snode);
extern void skiplist_delete(struct skiplist *list, struct skiplist_node *snode);
extern void skiplist_iterate(struct skiplist *list, void (*cbk)(struct skiplist_node *, void *), void *data);
extern struct skiplist_node *skiplist_first(struct skiplist *list);
extern int skiplist_empty(struct skiplist *list);

#endif
