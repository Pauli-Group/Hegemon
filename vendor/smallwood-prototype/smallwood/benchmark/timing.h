#ifndef __TIMING_H__
#define __TIMING_H__

#include <stdint.h>
#include <time.h>
#include <sys/time.h>

typedef struct btimer_t {
    unsigned int counter;
    // gettimeofday
    double nb_milliseconds;
    struct timeval start, stop;
    // rdtscp or RDPMC
    uint64_t nb_cycles;
    unsigned int garbage;
    uint64_t cstart, cstop;
} btimer_t;

void btimer_init(btimer_t* timer);
void btimer_start(btimer_t *timer);
void btimer_count(btimer_t *timer);
void btimer_end(btimer_t *timer);
double btimer_diff(btimer_t *timer);
uint64_t btimer_diff_cycles(btimer_t *timer);
double btimer_get(btimer_t *timer);
double btimer_get_cycles(btimer_t *timer);

#ifdef MEASURE_CYCLES
/* ====================================================== */
/* Getting cycles primitives depending on the platform */
#if defined(__linux__) && (defined(__amd64__) || defined(__x86_64__))
/* On Linux specifically, we use the perf events */
/* NOTE: stolen and adapted from https://cpucycles.cr.yp.to/libcpucycles-20240318/cpucycles/amd64-pmc.c.html */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

static struct perf_event_attr attr;
static int fdperf = -1;
static struct perf_event_mmap_page *buf = 0;

static inline long long ticks(void)
{
  long long result;
  unsigned int seq;
  long long index;
  long long offset;

  if(buf == 0){
    return 0;
  }
  do {
    seq = buf->lock;
    asm volatile("" ::: "memory");
    index = buf->index;
    offset = buf->offset;
    asm volatile("rdpmc;shlq $32,%%rdx;orq %%rdx,%%rax"
      : "=a"(result) : "c"(index-1) : "%rdx");
    asm volatile("" ::: "memory");
  } while (buf->lock != seq);

  result += offset;
  result &= 0xffffffffffff;
  return result;
}

/* NOTE: constructor attribute to be executed first */
__attribute__((constructor)) static inline void ticks_setup(void)
{
  if (fdperf == -1) {
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    fdperf = syscall(__NR_perf_event_open,&attr,0,-1,-1,0);
    if (fdperf == -1){
        fprintf(stderr, "Error: performance counters configuration failed ...\n");
        fprintf(stderr, "  => Please configure RDPMC access with (as superuser) 'echo 2 > /proc/sys/kernel/perf_event_paranoid' (i.e. allow access from userland)\n");
        exit(-1);
    }
    buf = mmap(NULL,sysconf(_SC_PAGESIZE),PROT_READ,MAP_SHARED,fdperf,0);
  }

  return;
}

static inline long long platform_get_cycles(void)
{
  return ticks();
}

#elif defined(__amd64__) || defined(__x86_64__) || defined(__i386__)
/* On other platforms with x86, use rdtscp intrinsics */
#include <x86intrin.h>
static inline long long platform_get_cycles(void)
{
	unsigned int garbage;
	return __rdtscp(&garbage);
}
#elif defined(__aarch64__)
static inline long long platform_get_cycles(void)
{
	uint64_t result;
	asm volatile ("isb \n mrs %0, CNTVCT_EL0" : "=r" (result));
	return result;
}
#else
#error "Unsupported platform for cycles measurement ..."
#endif
#endif

#endif /* __TIMING_H__ */
