#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/misc.h"
#include "lib/slist.h"

struct test_list_node {
	int val;
	struct slist_node node;
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

static void dump(struct slist_head *head, const char *headline)
{
	struct slist_node *node;
	struct test_list_node *tnode;

	printf("%s", headline);

	slist_for_head2tail(head, node) {
		tnode = container_of(node, struct test_list_node, node);
		printf(" %d", tnode->val);
	}
	printf("\n");
}

static void test1(void)
{
	int vals[] = {1, 2, 3, 4, 5};
	struct slist_head head;
	struct test_list_node *node;
	struct test_list_node *node1 = NULL;
	struct test_list_node *node2 = NULL;
	struct test_list_node *node3 = NULL;
	struct test_list_node *node4 = NULL;
	struct test_list_node *node5 = NULL;
	unsigned int i;

	slist_init(&head);

	for (i = 0; i < ARRAY_SIZE(vals); i++) {
		node = alloc_node(vals[i]);
		slist_add_tail(&head, &node->node);

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
	slist_del_node(&head, &node2->node, &node3->node);
	free_node(node3);
	dump(&head, "expect 1 2 4 5:");

	/* remove node 1 */
	slist_del_node(&head, NULL, &node1->node);
	free_node(node1);
	dump(&head, "expect 2 4 5:");

	/* remove node 5 */
	slist_del_node(&head, &node4->node, &node5->node);
	free_node(node5);
	dump(&head, "expect 2 4:");

	node = alloc_node(10);
	slist_insert_node(&head, NULL, &node->node);
	dump(&head, "expect 10 2 4:");

	node = alloc_node(11);
	slist_insert_node(&head, &node2->node, &node->node);
	dump(&head, "expect 10 2 11 4:");

	node = alloc_node(50);
	slist_insert_node(&head, &node4->node, &node->node);
	dump(&head, "expect 10 2 11 4 50:");
}

int main(void)
{
	test1();
	return 0;
}
