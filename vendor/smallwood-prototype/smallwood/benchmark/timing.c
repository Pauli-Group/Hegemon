#include "timing.h"

void btimer_init(btimer_t* timer) {
    if(timer != NULL) {
        timer->counter = 0;
        timer->nb_milliseconds = 0.;
        timer->nb_cycles = 0;
	timer->start.tv_sec = timer->start.tv_usec = 0;
	timer->stop.tv_sec = timer->stop.tv_usec = 0;
    }
}
void btimer_count(btimer_t *timer) {
    if(timer != NULL)
        timer->counter++;
}
void btimer_start(btimer_t *timer) {
    if(timer != NULL) {
#ifdef MEASURE_TIME
#if defined(CLOCK_MONOTONIC_COARSE) && !defined(BENCHMARK_USE_GETTIMEOFDAY)
        /* NOTE: when available, we use CLOCK_MONOTONIC_COARSE
         * as it does not require a costly system call */
	struct timespec t;
        clock_gettime(CLOCK_MONOTONIC_COARSE, &t);
	timer->start.tv_sec  = t.tv_sec;
	timer->start.tv_usec = (double)t.tv_nsec * 0.001;
#else
        /* NOTE: this requires a syscall, so this can
         * incur a perfomance hit and perturb the measurements */
        gettimeofday(&timer->start, NULL);
#endif
#else
       (void)timer;
#endif /* MEASURE_TIME */
      #ifdef MEASURE_CYCLES
        timer->cstart = platform_get_cycles();
      #endif
    }
}
double btimer_diff(btimer_t *timer) {
    return ( (timer->stop.tv_sec - timer->start.tv_sec) * 1000000 + (timer->stop.tv_usec - timer->start.tv_usec) )/1000.;
}
uint64_t btimer_diff_cycles(btimer_t *timer) {
    return (timer->cstop - timer->cstart);
}
void btimer_end(btimer_t *timer) {
    if(timer != NULL) {
#ifdef MEASURE_TIME
#if defined(CLOCK_MONOTONIC_COARSE) && !defined(BENCHMARK_USE_GETTIMEOFDAY)
        /* NOTE: when available, we use CLOCK_MONOTONIC_COARSE
         * as it does not require a costly system call */
	struct timespec t;
        clock_gettime(CLOCK_MONOTONIC_COARSE, &t);
	timer->stop.tv_sec  = t.tv_sec;
	timer->stop.tv_usec = (double)t.tv_nsec * 0.001;
#else
        /* NOTE: this requires a syscall, so this can
         * incur a perfomance hit and perturb the measurements */
        gettimeofday(&timer->stop, NULL);
#endif
        timer->nb_milliseconds += btimer_diff(timer);
#else
       (void)timer;
#endif /* MEASURE_TIME */
      #ifdef MEASURE_CYCLES
        timer->cstop = platform_get_cycles();
        timer->nb_cycles += btimer_diff_cycles(timer);
      #endif
    }
}
double btimer_get(btimer_t *timer) {
    return timer->nb_milliseconds/timer->counter;
}
double btimer_get_cycles(btimer_t *timer) {
    return (double)timer->nb_cycles/timer->counter;
}
