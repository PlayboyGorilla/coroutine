#include "list.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void init_list_head(struct list_head * lhead)
{
	struct list_node *head = &lhead->head;

	head->prev = head;
	head->next = NULL;
#ifdef CONFIG_LIST_NR_CNT
	lhead->cnt = 0;
#endif
}

void list_add_tail(struct list_head *lhead, struct list_node *node)
{
	struct list_node *head = &lhead->head;
	struct list_node *tail = head->prev;
	
	tail->next = node;
	node->prev = tail;
	node->next = NULL;
	head->prev = node;
#ifdef CONFIG_LIST_NR_CNT
	lhead->cnt++;
#endif
}

void list_del_node(struct list_head *lhead, struct list_node *node)
{
	struct list_node *head = &lhead->head;
	struct list_node *new_next = node->next;

	node->prev->next = new_next;
	if(new_next) //!is_tail
		new_next->prev = node->prev;
	else //is_tail == TRUE; A new tail;
		head->prev = node->prev;
#ifdef CONFIG_LIST_NR_CNT
	lhead->cnt--;
#endif
}

/*insert 'new_node' right after 'tail_node'*/
void list_insert_node(struct list_head *lhead, struct list_node *tail_node, struct list_node *new_node)
{
	struct list_node *head = &lhead->head;
	struct list_node *next_node = tail_node->next;
	
	tail_node->next = new_node;

	new_node->prev = tail_node;
	new_node->next = next_node;

	if(next_node) {
		/*node is not the tail of the 'head'*/
		next_node->prev = new_node;
	}else {
		/*we've got a new tail*/
		head->prev = new_node;
	}
#ifdef CONFIG_LIST_NR_CNT
	lhead->cnt++;
#endif
}

void list_swap_node(struct list_head *lhead, struct list_node *node1, struct list_node *node2)
{
	struct list_node *head = &lhead->head;
	struct list_node *before1;
	struct list_node *before2;

	assert(node1 != head && node2 != head);

	/*node1 & node2 stand next to each other*/
	if(node1->next == node2) {
		before1 = node1->prev;

		list_del_node(lhead, node1);
		list_del_node(lhead, node2);

		list_insert_node(lhead, before1, node2);
		list_insert_node(lhead, node2, node1);
	}else if(node2->next == node1) {
		before2 = node2->prev;

		list_del_node(lhead, node1);
		list_del_node(lhead, node2);
		
		list_insert_node(lhead, before2, node1);
		list_insert_node(lhead, node1, node2);
	}else {
		before1 = node1->prev;
		before2 = node2->prev;

		list_del_node(lhead, node1);
		list_del_node(lhead, node2);

		list_insert_node(lhead, before1, node2);
		list_insert_node(lhead, before2, node1);
	}
}

/* NOTE: sub->prev points to the tail of @sub list */
void list_add_tail_sub(struct list_head *head, struct list_node *sub)
{
	struct list_node *lhead = &head->head;
	struct list_node *tail = lhead->prev;

	tail->next = sub;
	lhead->prev = sub->prev;
	sub->prev = tail;

#ifdef CONFIG_LIST_NR_CNT
	/* Update list count */
	for (lhead = sub; lhead != NULL; lhead = lhead->next)
		head->cnt++;
#endif
}

/* [from, to] taken out of the list */
struct list_node *list_del_sub(struct list_head *head, struct list_node *from, struct list_node *to)
{
	struct list_node *lhead = &head->head;
	struct list_node *from_prev = from->prev;
	struct list_node *to_next = to->next;

	assert(from != NULL);
	assert(to != NULL);

	from_prev->next = to_next;
	if (to_next)
		to_next->prev = from_prev;
	else
		lhead->prev = from_prev;

	from->prev = to;
	to->next = NULL;

#ifdef CONFIG_LIST_NR_CNT
	/* FIXME: O(n) efficiency */
	for (lhead = from; lhead != NULL; lhead = lhead->next)
		head->cnt--;
#endif

	return from;
}
