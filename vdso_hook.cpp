#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <string_view>
#include <link.h>
#include "util.h"

#ifndef FAIL
#define FAIL(reason) do { \
  fprintf(stderr, "FAIL: %s at %s:%d (%s)\n", reason, __FILE__, __LINE__, __FUNCTION__); \
  abort();                 \
  __builtin_unreachable(); \
} while(0)
#endif

#ifdef __x86_64__
size_t pagesz = 4096;
#else
#error "unsupported architecture"
#endif

using namespace std::string_view_literals;

extern "C" {
__attribute__((visibility("default")))
unsigned int la_version(unsigned int version){
	return LAV_CURRENT;
}
}

static uint16_t hash_string(std::string_view str) {
	union {
		uint16_t v16;
		uint8_t v8[2];
	} v{};
	auto d = str.data();
	for(size_t i = 0; i < str.size(); ++i){
		v.v8[i % 2] += d[i];
	}
	return v.v16;
}

static void change_prot(void* ptr, size_t len, int prot) {
	auto base = (char*)ptr - (uintptr_t(ptr) % pagesz);
	len += (char*)ptr - base;
	len = (len % pagesz) ? pagesz * (len / pagesz + 1): len;
	int ret = mprotect(base, len, prot);
	if(ret < 0){
		FAIL("mprotect failed");
	}
}

static struct timeval off_timeval{};
static decltype(&gettimeofday) __real___vdso_gettimeofday;

int my___vdso_gettimeofday(struct timeval *tv, struct timezone *tz) noexcept {
	if (!__real___vdso_gettimeofday) {
		return -1;
	}
	int ret = __real___vdso_gettimeofday(tv, tz);
	if (ret < 0)
		return ret;
	if (tv->tv_usec < off_timeval.tv_usec) {
		struct timeval tmp{0, 1000ULL * 1000};
		tmp.tv_usec -= off_timeval.tv_usec;
		tmp.tv_usec += tv->tv_usec;
		--tv->tv_sec;
		tv->tv_usec = tmp.tv_usec;
	} else {
		tv->tv_usec -= off_timeval.tv_usec;
	}
	tv->tv_sec -= off_timeval.tv_sec;
	return ret;
}

static void* intercept___vdso_gettimeofday(std::string_view n, void* real) {
	if (n != "__vdso_gettimeofday"sv)
		return real;
	__real___vdso_gettimeofday = decltype(&gettimeofday)(real);
	decltype(&gettimeofday) p = &my___vdso_gettimeofday;
	return (void*)p;
}

static struct timespec off_timespec{};
static decltype(&clock_gettime) __real___vdso_clock_gettime;
int my___vdso_clock_gettime(int clock, struct timespec *tm) noexcept
{
	if (!__real___vdso_clock_gettime)
		return -1;
	int ret = __real___vdso_clock_gettime(clock, tm);
	if (ret < 0)
		return ret;
	if (clock != CLOCK_REALTIME) {
		return ret;
	}
	if (tm->tv_nsec < off_timespec.tv_nsec) {
		struct timespec tmp{0, 1000ULL * 1000 * 1000};
		tmp.tv_nsec -= off_timespec.tv_nsec;
		tmp.tv_nsec += tm->tv_nsec;
		--tm->tv_sec;
		tm->tv_nsec = tmp.tv_nsec;
	} else {
		tm->tv_nsec -= off_timespec.tv_nsec;
	}
	tm->tv_sec -= off_timespec.tv_sec;
	return ret;
}

static void* intercept___vdso_clock_gettime(std::string_view n, void* real) {
	if (n != "__vdso_clock_gettime"sv)
		return real;
	__real___vdso_clock_gettime = decltype(&clock_gettime)(real);
	decltype(&clock_gettime) p = &my___vdso_clock_gettime;
	return (void*)p;
}

static time_t off_time{};
static decltype(&time) __real___vdso_time;

time_t my___vdso_time(time_t *tloc) noexcept {
	auto t = __real___vdso_time(tloc);
	t -= off_time;
	if (tloc) {
		*tloc -= off_time;
	}
	return t;
}

static void* intercept___vdso_time(std::string_view n, void* real) {
	if (n != "__vdso_time"sv)
		return real;
	__real___vdso_time = decltype(&time)(real);
	decltype(&time) p = &my___vdso_time;
	return (void*)p;
}

static void* vdso_reloc;

static void hook () __attribute__ ((constructor));

static void hook() {
	auto cfg = getenv("MY_VDSO_CFG");
	if (!cfg) {
		FAIL("no MY_VDSO_CFG specified");
	}
	{
		unsigned long off = strtoul(cfg, nullptr, 10);
		off_time = off;
		off_timeval.tv_sec = off;
		off_timeval.tv_usec = 0;
		off_timespec.tv_sec = off;
		off_timespec.tv_nsec = 0;
	}
	struct _vdsoinfo {
		char *vdso;
		size_t vdso_sz;
		char *vvar;
		size_t vvar_sz;
	} vdsoinfo{};
	proc_maps_iterate(0, [](struct procmaps_entry* entry, void* priv){
		auto pvdsoinfo = (_vdsoinfo*)priv;
		if (!strcmp(entry->file, "[vvar]")) {
			pvdsoinfo->vvar = entry->addr;
			pvdsoinfo->vvar_sz = entry->limit - entry->addr;
		} else if (!strcmp(entry->file, "[vdso]")) {
			pvdsoinfo->vdso = entry->addr;
			pvdsoinfo->vdso_sz = entry->limit - entry->addr;
		}
	}, &vdsoinfo);
	if (!vdsoinfo.vvar || !vdsoinfo.vdso) {
		FAIL("failed to get vdso/vvar from /proc/maps");
	}
	if (vdsoinfo.vvar + vdsoinfo.vvar_sz != vdsoinfo.vdso) {
		FAIL("vvar and vdso must be contiguous");
	}
	unsigned long vdso_auxv = getauxval(AT_SYSINFO_EHDR);
	if (!vdso_auxv) {
		FAIL("vdso not found");
	}
	if ((uintptr_t)vdsoinfo.vdso != vdso_auxv) {
		FAIL("auxv and proc/maps disagree");
	}
	vdso_reloc = mmap(nullptr, vdsoinfo.vvar_sz + vdsoinfo.vdso_sz, PROT_NONE,
			  MAP_PRIVATE | MAP_NORESERVE | MAP_ANONYMOUS, -1, 0);
	if (vdso_reloc == MAP_FAILED) {
		FAIL("unable to map vdso location section");
	}
	if (mremap(vdsoinfo.vvar, vdsoinfo.vvar_sz, vdsoinfo.vvar_sz, MREMAP_MAYMOVE | MREMAP_FIXED, vdso_reloc) == MAP_FAILED) {
		FAIL("unable to relocate vvar");
	}
	if (mremap(vdsoinfo.vdso, vdsoinfo.vdso_sz, vdsoinfo.vdso_sz, MREMAP_MAYMOVE | MREMAP_FIXED, (char*)vdso_reloc + vdsoinfo.vvar_sz) == MAP_FAILED) {
		FAIL("unable to relocate vdso");
	}
	if (mmap(vdsoinfo.vdso, vdsoinfo.vdso_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
		FAIL("unable to allocate shadow vdso");
	}
	memcpy(vdsoinfo.vdso, (char*)vdso_reloc + vdsoinfo.vvar_sz, vdsoinfo.vdso_sz);
	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)(vdsoinfo.vdso);
	auto shoff = ehdr->e_shoff;
	if (!shoff) {
		FAIL("section table must be defined in vdso");
	}
	Elf64_Shdr *shdrs = (Elf64_Shdr*)(vdsoinfo.vdso + shoff);
	Elf64_Shdr *dynsym = nullptr;
	for (auto i = shdrs, j = shdrs + ehdr->e_shnum; i != j; ++i) {
		if (i->sh_type == SHT_DYNSYM) {
			dynsym = i;
		}
	}
	if (!dynsym) {
		FAIL("dynsym section must be found");
	}
	if(dynsym->sh_entsize != sizeof(Elf64_Sym)) {
		FAIL("dynsym section must have entsize == sizeof(sym)");
	}
	if (dynsym->sh_size % sizeof(Elf64_Sym)) {
		FAIL("dynsym section must size == multiple of sizeof(sym)");
	}

	Elf64_Shdr *dynstr = dynsym->sh_link + shdrs;
	Elf64_Sym *dynsyms = (Elf64_Sym*)(vdsoinfo.vdso + dynsym->sh_addr);
	auto dynsyms_end = dynsyms + dynsym->sh_size / sizeof(Elf64_Sym);
	//shadow_pages(dynsyms, (char*)dynsyms_end - (char*)dynsyms, PROT_READ | PROT_WRITE | PROT_EXEC);
	//change_prot(dynsyms, (char*)dynsyms_end - (char*)dynsyms, PROT_READ | PROT_WRITE | PROT_EXEC);
	for (auto i = dynsyms; i != dynsyms_end; ++i) {
		if (i->st_shndx == SHN_UNDEF) {
			continue;
		}
		if (ELF64_ST_BIND(i->st_info) != STB_GLOBAL) {
			continue;
		}
		if (ELF64_ST_TYPE(i->st_info) != STT_FUNC) {
			continue;
		}
		auto name = (char*)(i->st_name + dynstr->sh_addr + vdsoinfo.vdso);
		std::string_view n(name);
		//printf("%s, hash=%hu\n", name, hash_string(n));
		void *real = i->st_value + (char*)vdso_reloc + vdsoinfo.vvar_sz, *redir = real;
		switch(hash_string(name)) {
		case 41529: //gettimeofday
			redir = intercept___vdso_gettimeofday(name, real);
			break;
		case 4981: //time
			redir = intercept___vdso_time(name, real);
			break;
		case 6171: //clockgettime
			redir = intercept___vdso_clock_gettime(name, real);
			break;
		default:
			break;
		}
		if (redir == real)
			continue;
		//i->st_value = (Elf64_Addr)((char*)redir - (char*)vdso);
		struct __attribute__((packed)){
			char op1[2];
			uint64_t target;
			char op2[2];
		} absjmp;
		static_assert(sizeof(absjmp) == 12, "check insn patch size");
		if (i->st_size < sizeof(absjmp) ) {
			FAIL("vdso function too short for patching");
		}
		//movabs imm, %rax
		absjmp.op1[0] = 0x48;
		absjmp.op1[1] = 0xb8;
		absjmp.target = (uintptr_t)redir;
		//jmp *%rax
		absjmp.op2[0] = 0xff;
		absjmp.op2[1] = 0xe0;
		memcpy(i->st_value + (char*)vdsoinfo.vdso, &absjmp, sizeof(absjmp));
	}
	change_prot(vdsoinfo.vdso, vdsoinfo.vdso_sz, PROT_READ | PROT_EXEC);
}
