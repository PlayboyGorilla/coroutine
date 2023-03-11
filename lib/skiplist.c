/* Skip Lists: A Probabilistic Alternative to Balanced Trees */
 
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <assert.h>

#include "skiplist.h"
#include "compiler.h"
#include "errno.h"

void skiplist_init(struct skiplist *list, skiplist_compare cmp_cbk)
{
	unsigned int i;

	list->header.level = 1;
	list->header.buddy_next = NULL;
	list->header.buddy_prev = NULL;
	list->cmp_cbk = cmp_cbk;

	for (i = 0; i <= SKIPLIST_MAX_LEVEL; i++) {
		list->header.next[i] = &list->header;
		list->header.prev[i] = &list->header;
	}
}
 
static unsigned int rand_level() {
	unsigned int level = 1;

	while (rand() < RAND_MAX / 2 && level < SKIPLIST_MAX_LEVEL)
		level++;

	return level;
}

static inline int __skiplist_compare(struct skiplist *list,
	struct skiplist_node *node1, struct skiplist_node *node2)
{
	if (unlikely(node1 == &list->header))
		return SL_CMP_GT;

	if (unlikely(node2 == &list->header))
		return SL_CMP_LT;

	return list->cmp_cbk(node1, node2);
}

static void skiplist_insert_head(struct skiplist *list, struct skiplist_node **update,
	struct skiplist_node *newnode)
{
	struct skiplist_node *p, *q;
	unsigned int i, level;

	level = rand_level();
	if (level > list->header.level) {
		for (i = list->header.level + 1; i <= level; i++) {
			update[i] = &list->header;
		}
		list->header.level = level;
	}

	newnode->level = level;
	newnode->buddy_prev = NULL;
	newnode->buddy_next = NULL;

	for (i = 1; i <= newnode->level; i++) {
		p = update[i];
		q = p->next[i];
		newnode->next[i] = q;
		p->next[i] = newnode;
		newnode->prev[i] = p;
		q->prev[i] = newnode;
	}
}

static void skiplist_insert_buddy(struct skiplist_node *equal, struct skiplist_node *new)
{
	struct skiplist_node *last = equal;

	while (last->buddy_next)
		last = last->buddy_next;

	last->buddy_next = new;
	new->buddy_next = NULL;
	new->buddy_prev = last;
}

int skiplist_insert(struct skiplist *list, struct skiplist_node *snode)
{
	struct skiplist_node *update[SKIPLIST_MAX_LEVEL + 1];
	struct skiplist_node *x = &list->header;
	unsigned int i;

	for (i = list->header.level; i >= 1; i--) {
		while (__skiplist_compare(list, x->next[i], snode) == SL_CMP_LT)
			x = x->next[i];
		update[i] = x;
	}
	x = x->next[1];

	if (list->cmp_cbk(snode, x) == SL_CMP_EQ) {
		skiplist_insert_buddy(x, snode);
		return ERR_EXISTED;
	} else {
		skiplist_insert_head(list, update, snode);
	}

	return ERR_OK;
}

struct skiplist_node *skiplist_search(struct skiplist *list, struct skiplist_node *temp)
{
	struct skiplist_node *x = &list->header;
	unsigned int i;

	for (i = list->header.level; i >= 1; i--) {
		while (__skiplist_compare(list, x->next[i], temp) == SL_CMP_LT)
			x = x->next[i];
	}

	if (list->cmp_cbk(x->next[1], temp) == SL_CMP_EQ)
		return x->next[1];

	return NULL;
}

struct skiplist_node *skiplist_search_neighbor(struct skiplist *list, struct skiplist_node *temp,
	struct skiplist_node **prev, struct skiplist_node **next)
{
	struct skiplist_node *x = &list->header;
	unsigned int i;

	for (i = list->header.level; i >= 1; i--) {
		while (__skiplist_compare(list, x->next[i], temp) == SL_CMP_LT)
			x = x->next[i];
	}

	if (list->cmp_cbk(x->next[1], temp) == SL_CMP_EQ) {
		*prev = NULL;
		*next = NULL;
		return x->next[1];
	}

	/* prev == x && next == x->next[1] */
	*prev = (x == &list->header ? NULL : x);
	*next = (x->next[1] == &list->header ? NULL : x->next[1]);

	return NULL;
} 

/*
 * Try finding the node that matches the key of @newnode:
 *	1. If a match is found, return the match and do nothing more
 *	2. If not, insert @newnode into list and return its neighbors
 */
struct skiplist_node *skiplist_find_or_insert(struct skiplist *list, struct skiplist_node *newnode,
	struct skiplist_node **prev, struct skiplist_node **next)
{
	struct skiplist_node *update[SKIPLIST_MAX_LEVEL + 1];
	struct skiplist_node *x = &list->header;
	unsigned int i;

	for (i = list->header.level; i >= 1; i--) {
		while (__skiplist_compare(list, x->next[i], newnode) == SL_CMP_LT)
			x = x->next[i];
		update[i] = x;
	}

	if (list->cmp_cbk(x->next[1], newnode) == SL_CMP_EQ) {
		*prev = NULL;
		*next = NULL;
		return x->next[1];
	}

	/* prev == x && next == x->next[1] */
	*prev = (x == &list->header ? NULL : x);
	*next = (x->next[1] == &list->header ? NULL : x->next[1]);

	skiplist_insert_head(list, update, newnode);

	return NULL;
}

void skiplist_eradicate(struct skiplist *list, struct skiplist_node *snode)
{
	struct skiplist_node *head = &list->header;
	unsigned int l, m = snode->level;

	for (l = 1; l <= m; l++) {
		snode->prev[l]->next[l] = snode->next[l];
		snode->next[l]->prev[l] = snode->prev[l];
	}

	if (m == head->level && m > 1) {
		while (head->next[m] == head && m > 1) {
			m--;
		}
		head->level = m;
	}
}

static inline int skiplist_is_node_header(struct skiplist_node *snode)
{
	return (snode->buddy_prev == NULL);
}

void skiplist_delete(struct skiplist *list, struct skiplist_node *snode)
{
	struct skiplist_node *next = snode->buddy_next;
	struct skiplist_node *next_next;
	int ret;

	if (skiplist_is_node_header(snode)) {
		skiplist_eradicate(list, snode);
		if (next) {
			next_next = next->buddy_next;
			ret = skiplist_insert(list, next);
			assert(ret == ERR_OK);
			next->buddy_next = next_next;
		}
	} else {
		/* old good regular list node deletion */
		snode->buddy_prev->buddy_next = next;
		if (next)
			next->buddy_prev = snode->buddy_prev;
	}
}

void skiplist_iterate(struct skiplist *list, void (*cbk)(struct skiplist_node *, void *), void *data)
{
	struct skiplist_node *x = &list->header;

	while (x && x->next[1] != &list->header) {
		cbk(x->next[1], data);
		x = x->next[1];
	}
}

struct skiplist_node *skiplist_first(struct skiplist *list)
{
	struct skiplist_node *x = &list->header;

	if (x && x->next[1] != &list->header)
		return x->next[1];

	return NULL;
}

int skiplist_empty(struct skiplist *list)
{
	return !skiplist_first(list);
}
