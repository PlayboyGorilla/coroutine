#include "hosal/type.h"
#include "lib/compiler.h"

void hosal_type_stub(void)
{
	compile_time_assert(sizeof(uint_pointer) == sizeof(void *));
}
