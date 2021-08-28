#ifndef __LIB_SLIST_H__
#define __LIB_SLIST_H__

#include <stdio.h>
#include <stdint.h>

/*It should be noted that this list is not protected by any locks*/
struct slist_node {
	struct slist_node *next;
};

/*
* separate list_head and list_node would be worthwhile
*/
struct slist_head {
	struct slist_node *head;
	struct slist_node *tail;
};

static inline void slist_init(struct slist_head *slh)
{
	slh->head = NULL;
	slh->tail = NULL;
}

static inline int slist_is_empty(const struct slist_head *slh)
{
	return (slh->head == NULL);
}

extern void slist_add_tail(struct slist_head *head, struct slist_node *node);
extern void slist_del_node(struct slist_head *head, struct slist_node *prev, struct slist_node *node);
extern void slist_insert_node(struct slist_head *head, struct slist_node *prev,struct slist_node *new_node);

static inline struct slist_node *slist_first(struct slist_head *head)
{
	return head->head;
}

static inline struct slist_node *slist_last(struct slist_head *head)
{
	return head->tail;
}

static inline struct slist_node *slist_next(struct slist_node *node)
{
	return node->next;
}

static inline void *slist_first_entry(struct slist_head *head, unsigned long offset)
{
	struct slist_node *node = slist_first(head);

	if (!node) {
		return NULL;
	}

	return (((uint8_t *)node) - offset);
}

static inline void *slist_last_entry(struct slist_head *head, unsigned long offset)
{
	struct slist_node *node = slist_last(head);

	if (!node) {
		return NULL;
	}

	return (((uint8_t *)node) - offset);
}

static inline void *slist_next_entry(struct slist_node *node, unsigned long offset)
{
	struct slist_node *next = slist_next(node);

	if (!next) {
		return NULL;
	}

	return (((uint8_t *)next) - offset);
}

/* 'const' version of list_XXX getters */
static inline const struct slist_node *slist_first_const(const struct slist_head *head)
{
	return head->head;
}

static inline const struct slist_node *slist_last_const(const struct slist_head *head)
{
	return head->tail;
}

static inline const struct slist_node *slist_next_const(const struct slist_node *node)
{
	return node->next;
}

static inline const void *slist_first_entry_const(const struct slist_head *head, unsigned long offset)
{
	const struct slist_node *node = slist_first_const(head);

	if (!node) {
		return NULL;
	}

	return (((uint8_t *)node) - offset);
}

static inline const void *slist_last_entry_const(const struct slist_head *head, unsigned long offset)
{
	const struct slist_node *node = slist_last_const(head);

	if (!node) {
		return NULL;
	}

	return (((const uint8_t *)node) - offset);
}

static inline const void *slist_next_entry_const(const struct slist_node *node, unsigned long offset)
{
	const struct slist_node *next = slist_next_const(node);

	if (!next) {
		return NULL;
	}

	return (((const uint8_t *)next) - offset);
}

#define slist_for_head2tail(head, node)	\
	for (node = slist_first(head); node != NULL; node = slist_next(node))
#define slist_for_head2tail_safe(head, node, temp)	\
	for (node = slist_first(head), (temp = (node ? slist_next(node) : NULL));	\
		node != NULL;		\
		node = temp, (temp = (node ? slist_next(node) : NULL)))

/* 'const' versions */
#define slist_for_head2tail_const(head, node)	\
	for (node = slist_first_const(head); node != NULL; node = list_next_const(node))

#endif
