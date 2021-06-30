#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/hash.h"

DEFINE_HASH_TABLE_STRUCT(32);
static HASH_TABLE(32, 0, NULL, NULL, obj);

int main(void)
{
	(void)obj;

	return 0;
}
