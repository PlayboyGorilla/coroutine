#ifndef __LIB_LIST_H
#define __LIB_LIST_H

#include <stdio.h>
#include <stdint.h>

/*It should be noted that this list is not protected by any locks*/
struct list_node {
	struct list_node *prev;
	struct list_node *next;
};

/*
* separate list_head and list_node would be worthwhile
*/
struct list_head {
	struct list_node head;
#ifdef CONFIG_LIST_NR_CNT
	unsigned int cnt;
#endif
};

#ifdef CONFIG_LIST_NR_CNT
#define DEFINE_LIST_HEAD(x)		\
	struct list_head x = {		\
		{&(x.head), NULL},	\
		0			\
	}
#else
#define DEFINE_LIST_HEAD(x)  		\
	struct list_head x = {		\
		{&(x.head), NULL},	\
	}
#endif

#ifdef CONFIG_LIST_NR_CNT
#define INIT_EMBEDDED_LIST_HEAD(x)	\
	{ {&(x.head), NULL}, 0 }
#else
#define INIT_EMBEDDED_LIST_HEAD(x)	\
	{ {&(x.head), NULL} }
#endif

#define LIST_2_STRUCT(ptr,type,member)	\
	 ( (type*)( (unsigned char *)ptr - (unsigned long)&(((type*)0)->member) ) )

#define LIST_HEAD_INIT(lhead) { &(lhead.head), NULL }

void init_list_head(struct list_head *head);
void list_add_tail(struct list_head *head, struct list_node *tail);
void list_del_node(struct list_head *head, struct list_node *node);
void list_insert_node(struct list_head *head, struct list_node *tail_node,struct list_node *new_node);
void list_swap_node(struct list_head *head, struct list_node *node1, struct list_node *node2);

void list_add_tail_sub(struct list_head *head, struct list_node *sub);
struct list_node *list_del_sub(struct list_head *head, struct list_node *from, struct list_node *to);

static inline struct list_node *list_del_sub_2_end(struct list_head *head, struct list_node *sub)
{
	return list_del_sub(head, sub, head->head.prev);
}

static inline int is_list_empty(const struct list_head *lhead)
{
        return (lhead->head.next == NULL);
}

static inline struct list_node *list_first_node(struct list_head *head)
{
	return head->head.next;
}

static inline struct list_node *list_last_node(struct list_head *head)
{
	if (is_list_empty(head))
		return NULL;

	return head->head.prev;
}

static inline struct list_node *list_next_node(struct list_head *head, struct list_node *node)
{
	return node->next;
}

static inline struct list_node *list_prev_node(struct list_head *head, struct list_node *node)
{
	struct list_node *n = node->prev;

	if (n == &head->head)
		return NULL;

	return n;
}

static inline void *list_first_entry(struct list_head *head, unsigned long offset)
{
	struct list_node *node = list_first_node(head);

	if (!node)
		return NULL;

	return (((uint8_t *)node) - offset);
}

static inline void *list_last_entry(struct list_head *head, unsigned long offset)
{
	struct list_node *node = list_last_node(head);

	if (!node)
		return NULL;

	return (((uint8_t *)node) - offset);
}

static inline void *list_next_entry(struct list_head *head, struct list_node *n, unsigned long offset)
{
	struct list_node *node = list_next_node(head, n);

	if (!node)
		return NULL;

	return (((uint8_t *)node) - offset);
}

static inline void *list_prev_entry(struct list_head *head, struct list_node *n, unsigned long offset)
{
	struct list_node *node = list_prev_node(head, n);

	if (!node)
		return NULL;

	return (((uint8_t *)node) - offset);
}

/* 'const' version of list_XXX getters */
static inline const struct list_node *list_first_node_const(const struct list_head *head)
{
	return head->head.next;
}

static inline const struct list_node *list_last_node_const(const struct list_head *head)
{
	if (is_list_empty(head))
		return NULL;

	return head->head.prev;
}

static inline const struct list_node *list_next_node_const(const struct list_head *head,
		const struct list_node *node)
{
	return node->next;
}

static inline const struct list_node *list_prev_node_const(const struct list_head *head,
		const struct list_node *node)
{
	const struct list_node *n = node->prev;

	if (n == &head->head)
		return NULL;

	return n;
}

static inline const void *list_first_entry_const(const struct list_head *head, unsigned long offset)
{
	const struct list_node *node = list_first_node_const(head);

	if (!node)
		return NULL;

	return (((uint8_t *)node) - offset);
}

static inline const void *list_last_entry_const(const struct list_head *head, unsigned long offset)
{
	const struct list_node *node = list_last_node_const(head);

	if (!node)
		return NULL;

	return (((uint8_t *)node) - offset);
}

static inline const void *list_next_entry_const(const struct list_head *head,
		const struct list_node *n, unsigned long offset)
{
	const struct list_node *node = list_next_node_const(head, n);

	if (!node)
		return NULL;

	return (((uint8_t *)node) - offset);
}

static inline const void *list_prev_entry_const(const struct list_head *head,
		const struct list_node *n, unsigned long offset)
{
	const struct list_node *node = list_prev_node_const(head, n);

	if (!node)
		return NULL;

	return (((uint8_t *)node) - offset);
}

#define is_list_first(lhead, node)		(list_first_node_const(lhead) == (node))
#define is_list_last(lhead, node)		(list_last_node_const(lhead) == (node))

#define list_for_head2tail(head, node)	\
	for (node = list_first_node(head); node != NULL; node = list_next_node(head, node))
#define list_for_tail2head(head, node)	\
	for (node = list_last_node(head); node != NULL; node = list_prev_node(head, node))
#define list_for_head2tail_safe(head, node, temp)	\
	for (node = list_first_node(head), (temp = (node ? list_next_node(head, node) : NULL));	\
		node != NULL;		\
		node = temp, (temp = (node ? list_next_node(head, node) : NULL)))
#define list_for_tail2head_safe(head, node, temp)	\
	for (node = list_last_node(head), (temp = (node ? list_prev_node(head, node) : NULL));	\
		node != NULL;	\
		node = temp, (temp = (node ? list_prev_node(head, node) : NULL)))

/* 'const' versions */
#define list_for_head2tail_const(head, node)	\
	for (node = list_first_node_const(head); node != NULL; node = list_next_node_const(head, node))
#define list_for_tail2head_const(head, node)	\
	for (node = list_last_node_const(head); node != NULL; node = list_prev_node_const(head, node))

#endif
