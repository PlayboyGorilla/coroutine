#include <stdio.h>
#include <stdlib.h>

#include "debug.h"

#ifdef __DEBUG__
void dbg_hex_dump(const uint8_t *data, unsigned int len)
{
	unsigned int i;
	int cr_dumped;

	for (i = 0; i < len; i++) {
		printf("%02x ", data[i]);
		cr_dumped = 0;
		if ((i + 1) % 16 == 0) {
			printf("\n");
			cr_dumped = 1;
		}
	}

	if (!cr_dumped)
		printf("\n");
}
#endif
