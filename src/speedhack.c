#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// Shared memory structure
typedef struct {
  double speed;
} SpeedhackConfig;

static SpeedhackConfig *config = NULL;

static double current_speed = 1.0;
static struct timespec initial_ts_mono = {0};
static struct timespec initial_ts_real = {0};
static double initial_uptime_mono = 0.0;
static double initial_uptime_real = 0.0;

// Original function pointers
static int (*orig_clock_gettime)(clockid_t clk_id, struct timespec *tp) = NULL;
static int (*orig_gettimeofday)(struct timeval *restrict tv,
                                struct timezone *restrict tz) = NULL;

// Helper to init config
static void init_speedhack() {
  if (orig_clock_gettime)
    return; // already init

  orig_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
  orig_gettimeofday = dlsym(RTLD_NEXT, "gettimeofday");

  char shm_name[64];
  snprintf(shm_name, sizeof(shm_name), "/speedhack_%d", getpid());

  int fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
  if (fd != -1) {
    ftruncate(fd, sizeof(SpeedhackConfig));
    config = mmap(NULL, sizeof(SpeedhackConfig), PROT_READ | PROT_WRITE,
                  MAP_SHARED, fd, 0);
    if (config != MAP_FAILED) {
      config->speed = 1.0;
    } else {
      config = NULL;
    }
    close(fd);
  }

  if (orig_clock_gettime) {
    orig_clock_gettime(CLOCK_MONOTONIC, &initial_ts_mono);
    orig_clock_gettime(CLOCK_REALTIME, &initial_ts_real);
  }
}

static double ts_to_double(struct timespec *ts) {
  return (double)ts->tv_sec + (double)ts->tv_nsec / 1e9;
}

static void double_to_ts(double d, struct timespec *ts) {
  ts->tv_sec = (time_t)d;
  ts->tv_nsec = (long)((d - (double)ts->tv_sec) * 1e9);
}

int clock_gettime(clockid_t clk_id, struct timespec *tp) {
  if (!orig_clock_gettime)
    init_speedhack();

  int res = orig_clock_gettime(clk_id, tp);
  if (res == 0 && (clk_id == CLOCK_MONOTONIC || clk_id == CLOCK_REALTIME)) {
    double speed = config ? config->speed : current_speed;
    if (speed == 1.0)
      return res;

    struct timespec *base_ts =
        (clk_id == CLOCK_MONOTONIC) ? &initial_ts_mono : &initial_ts_real;

    double current = ts_to_double(tp);
    double base = ts_to_double(base_ts);

    double new_time = base + (current - base) * speed;
    double_to_ts(new_time, tp);
  }
  return res;
}

int gettimeofday(struct timeval *restrict tv, void *restrict tz) {
  if (!orig_gettimeofday)
    init_speedhack();

  int res = orig_gettimeofday(tv, tz);
  if (res == 0 && tv != NULL) {
    double speed = config ? config->speed : current_speed;
    if (speed == 1.0)
      return res;

    double base = ts_to_double(&initial_ts_real);
    double current = (double)tv->tv_sec + (double)tv->tv_usec / 1e6;

    double new_time = base + (current - base) * speed;

    tv->tv_sec = (time_t)new_time;
    tv->tv_usec = (suseconds_t)((new_time - (double)tv->tv_sec) * 1e6);
  }
  return res;
}
