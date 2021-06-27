#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "lib/list.h"

void list_add_tail(struct list_head *lhead, struct list_node *node)
{
	if (!lhead->head) {
		node->prev = NULL;
		lhead->head = node;
	} else {
		node->prev = lhead->tail;
		lhead->tail->next = node;
	}

	node->next = NULL;
	lhead->tail = node;
}

void list_del_node(struct list_head *lhead, struct list_node *node)
{
	if (node->next) {
		node->next->prev = node->prev;
	}
	if (node->prev) {
		node->prev->next = node->next;
	}

	if (node == lhead->head) {
		lhead->head = node->next;
	}
	if (node == lhead->tail) {
		lhead->tail = node->prev;
	}
}

/*insert 'new_node' right after 'tail_node'*/
void list_insert_node(struct list_head *lhead, struct list_node *prev, struct list_node *node)
{
	struct list_node **old_next;

	if (prev) {
		old_next = &prev->next;
	} else {
		old_next = &lhead->head;
	}
	if (*old_next) {
		(*old_next)->prev = node;
	}
	node->next = *old_next;
	*old_next = node;
	node->prev = prev;

	if (lhead->tail == prev) {
		lhead->tail = node;
	}
}
