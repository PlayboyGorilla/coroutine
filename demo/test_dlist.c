#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/misc.h"
#include "lib/list.h"

struct test_list_node {
	int val;
	struct list_node node;
};

static struct test_list_node *alloc_node(int val)
{
	struct test_list_node *node;

	node = malloc(sizeof(*node));
	assert(node);

	node->val = val;
	return node;
}

static void free_node(struct test_list_node *node)
{
	free(node);
}

static void dump(struct list_head *head, const char *headline)
{
	struct list_node *node;
	struct test_list_node *tnode;

	printf("%s", headline);

	list_for_head2tail(head, node) {
		tnode = container_of(node, struct test_list_node, node);
		printf(" %d", tnode->val);
	}
	printf("\n");
}

static void test1(void)
{
	int vals[] = {1, 2, 3, 4, 5};
	struct list_head head;
	struct test_list_node *node;
	struct test_list_node *node1;
	struct test_list_node *node2;
	struct test_list_node *node3;
	struct test_list_node *node4;
	struct test_list_node *node5;
	unsigned int i;

	init_list_head(&head);

	for (i = 0; i < ARRAY_SIZE(vals); i++) {
		node = alloc_node(vals[i]);
		list_add_tail(&head, &node->node);

		if (i == 0) {
			node1 = node;
		} else if (i == 1) {
			node2 = node;
		} else if (i == 2) {
			node3 = node;
		} else if (i == 3) {
			node4 = node;
		} else if (i == 4) {
			node5 = node;
		}
	}
	dump(&head, "expect 1 2 3 4 5:");

	/* remove node 3 */
	list_del_node(&head, &node3->node);
	free_node(node3);
	dump(&head, "expect 1 2 4 5:");

	/* remove node 1 */
	list_del_node(&head, &node1->node);
	free_node(node1);
	dump(&head, "expect 2 4 5:");

	/* remove node 5 */
	list_del_node(&head, &node5->node);
	free_node(node5);
	dump(&head, "expect 2 4:");

	node = alloc_node(10);
	list_insert_node(&head, NULL, &node->node);
	dump(&head, "expect 10 2 4:");

	node = alloc_node(11);
	list_insert_node(&head, &node2->node, &node->node);
	dump(&head, "expect 10 2 11 4:");

	node = alloc_node(50);
	list_insert_node(&head, &node4->node, &node->node);
	dump(&head, "expect 10 2 11 4 50:");
}

int main(void)
{
	test1();
	return 0;
}
