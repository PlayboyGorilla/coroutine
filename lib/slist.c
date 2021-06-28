#include <assert.h>
#include "lib/slist.h"

void slist_add_tail(struct slist_head *head, struct slist_node *node)
{
	if (head->tail) {
		head->tail->next = node;
	} else {
		assert(head->head == NULL);
		head->head = node;
	}

	node->next = NULL;
	head->tail = node;
}

void slist_del_node(struct slist_head *head, struct slist_node *prev, struct slist_node *node)
{
	if (!prev) {
		assert(head->head == node);
		head->head = node->next;
	} else {
		assert(prev->next == node);
		prev->next = node->next;
	}
	if (node == head->tail) {
		head->tail = prev;
	}
}

void slist_insert_node(struct slist_head *head, struct slist_node *prev,struct slist_node *node)
{
	if (!prev) {
		node->next = head->head;
		head->head = node;
	} else {
		node->next = prev->next;
		prev->next = node;
	}

	if (head->tail == prev) {
		head->tail = node;
	}
}


