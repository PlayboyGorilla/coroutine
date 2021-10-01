#ifndef __LIB_LIST_H
#define __LIB_LIST_H

#include <stdio.h>
#include <stdint.h>

#include "hosal/type.h"

/*It should be noted that this list is not protected by any locks*/
struct list_node {
	struct list_node *prev;
	struct list_node *next;
};

/*
* separate list_head and list_node would be worthwhile
*/
struct list_head {
	struct list_node *head;
	struct list_node *tail;
};

#define DEFINE_LIST_HEAD(x)  		\
	struct list_head x = {		\
		NULL, NULL }

#define LIST_HEAD_INIT(lhead) { NULL, NULL }

static inline void init_list_head(struct list_head *head)
{
	head->head = NULL;
	head->tail = NULL;
}

extern void list_add_tail(struct list_head *head, struct list_node *tail);
extern void list_del_node(struct list_head *head, struct list_node *node);
extern void list_insert_node(struct list_head *head, struct list_node *tail_node,struct list_node *new_node);

static inline int is_list_empty(const struct list_head *head)
{
        return (head->head == NULL);
}

static inline struct list_node *list_first_node(struct list_head *head)
{
	return head->head;
}

static inline struct list_node *list_last_node(struct list_head *head)
{
	return head->tail;
}

static inline struct list_node *list_next_node(struct list_head *head, struct list_node *node)
{
	return node->next;
}

static inline struct list_node *list_prev_node(struct list_head *head, struct list_node *node)
{
	return node->prev;
}

static inline void *list_first_entry(struct list_head *head, uint_pointer offset)
{
	struct list_node *node = list_first_node(head);

	if (!node) {
		return NULL;
	}

	return (((uint8_t *)node) - offset);
}

static inline void *list_last_entry(struct list_head *head, uint_pointer offset)
{
	struct list_node *node = list_last_node(head);

	if (!node) {
		return NULL;
	}

	return (((uint8_t *)node) - offset);
}

static inline void *list_next_entry(struct list_head *head, struct list_node *n, uint_pointer offset)
{
	struct list_node *node = list_next_node(head, n);

	if (!node) {
		return NULL;
	}

	return (((uint8_t *)node) - offset);
}

static inline void *list_prev_entry(struct list_head *head, struct list_node *n, uint_pointer offset)
{
	struct list_node *node = list_prev_node(head, n);

	if (!node) {
		return NULL;
	}

	return (((uint8_t *)node) - offset);
}

/* 'const' version of list_XXX getters */
static inline const struct list_node *list_first_node_const(const struct list_head *head)
{
	return head->head;
}

static inline const struct list_node *list_last_node_const(const struct list_head *head)
{
	return head->tail;
}

static inline const struct list_node *list_next_node_const(const struct list_head *head,
		const struct list_node *node)
{
	return node->next;
}

static inline const struct list_node *list_prev_node_const(const struct list_head *head,
		const struct list_node *node)
{
	return node->prev;
}

static inline const void *list_first_entry_const(const struct list_head *head, uint_pointer offset)
{
	const struct list_node *node = list_first_node_const(head);

	if (!node) {
		return NULL;
	}

	return (((const uint8_t *)node) - offset);
}

static inline const void *list_last_entry_const(const struct list_head *head, uint_pointer offset)
{
	const struct list_node *node = list_last_node_const(head);

	if (!node) {
		return NULL;
	}

	return (((const uint8_t *)node) - offset);
}

static inline const void *list_next_entry_const(const struct list_head *head,
		const struct list_node *n, uint_pointer offset)
{
	const struct list_node *node = list_next_node_const(head, n);

	if (!node) {
		return NULL;
	}

	return (((const uint8_t *)node) - offset);
}

static inline const void *list_prev_entry_const(const struct list_head *head,
		const struct list_node *n, uint_pointer offset)
{
	const struct list_node *node = list_prev_node_const(head, n);

	if (!node) {
		return NULL;
	}

	return (((const uint8_t *)node) - offset);
}

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
