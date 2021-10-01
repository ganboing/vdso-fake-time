#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>

static const char proc_maps_fmt[] =
	"%p-%p %c%c%c%c %" PRIx32 " %hhx:%hhx %lu %n ";

struct procmaps_entry{
	char *addr;
	char *limit;
	char r, w, x, p;
	uint32_t off;
	unsigned char maj, min;
	unsigned long inode;
	char *file;
};
