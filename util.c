#include "util.h"

static const char proc_maps_path_fmt[] =
	"/proc/%lu/maps";

void proc_maps_iterate(pid_t pid, void (*cb)(struct procmaps_entry*, void*), void *arg)
{
	char *line = NULL;
	size_t n = 0;
	ssize_t s = 0;
	FILE *f;
	if (pid) {
		int len = snprintf(NULL, 0, proc_maps_path_fmt, (unsigned long)pid);
		char path[len + 1];
		sprintf(path, proc_maps_path_fmt, (unsigned long)pid);
		f = fopen(path, "r");
	} else {
		f = fopen("/proc/self/maps", "r");
	}
	if (!f)
		abort();
	while ((s = getline(&line, &n, f)) > 0) {
		line[s - 1] = '\0';
		struct procmaps_entry entry;
		int skip = 0;
		int ret = sscanf(line, proc_maps_fmt, &entry.addr, &entry.limit,
				 &entry.r, &entry.w, &entry.x, &entry.p, &entry.off,
				 &entry.maj, &entry.min, &entry.inode, &skip);
		if (ret != 10)
			error(1, 0, "unable to parse proc maps");
		entry.file = line + skip;
		cb(&entry, arg);
	}
	free(line);
	fclose(f);
}
