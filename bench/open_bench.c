// open_bench.c: latency of open()+close() on an existing, unrelated file (E3cred).
// Measures what the context interface costs processes that never use it: with
// openat markers the collector and the policy attach a probe to every openat on the
// host; with the execution credential they do not.
// Usage: open_bench --n 200000 --warmup 10000 --path /etc/hostname
// Output: one JSON line (n, p50_ns, p99_ns, mean_ns, ops_per_s).
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    long n = 200000, warmup = 10000;
    const char *path = "/etc/hostname";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc) n = atol(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) warmup = atol(argv[++i]);
        else if (!strcmp(argv[i], "--path") && i + 1 < argc) path = argv[++i];
        else { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
    }
    uint64_t *lat = malloc(sizeof(uint64_t) * (size_t)n);
    uint64_t t_start = 0;
    for (long i = -warmup; i < n; i++) {
        if (i == 0) t_start = now_ns();
        uint64_t t0 = now_ns();
        int fd = open(path, O_RDONLY);
        if (fd < 0) { perror("open"); return 1; }
        close(fd);
        if (i >= 0) lat[i] = now_ns() - t0;
    }
    uint64_t wall = now_ns() - t_start;
    double mean = 0;
    for (long i = 0; i < n; i++) mean += (double)lat[i];
    mean /= (double)n;
    qsort(lat, (size_t)n, sizeof(uint64_t), cmp_u64);
    printf("{\"n\":%ld,\"p50_ns\":%llu,\"p99_ns\":%llu,\"mean_ns\":%.1f,\"ops_per_s\":%.1f}\n", n,
           (unsigned long long)lat[n / 2], (unsigned long long)lat[(size_t)(n * 0.99)], mean,
           (double)n * 1e9 / (double)wall);
    return 0;
}
