#include <stdlib.h>

void *aligned_alloc(size_t align, size_t len)
{
	return memalign(align, len);
}
