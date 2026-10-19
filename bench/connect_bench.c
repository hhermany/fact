// connect_bench.c: connect() latency microbenchmark (E3).
//
// A child process accepts and closes connections; the parent measures, for each
// iteration, the wall-clock time of socket()+connect()+close() with CLOCK_MONOTONIC.
// Optionally emits the context markers (openat begin/end) around each connect,
// exactly as the FACT workload does, to measure the runtime-side cost of the
// context binding.
//
// Usage: connect_bench --n 20000 --warmup 1000 --port 40999 --markers 0|1 --out lat.csv [--host IP]
// With --host there is no local acceptor: it connects to the given IP (real network
// interface; the remote acceptor is workload/remote_farm.py).
// The client closes with SO_LINGER=0 (RST), so that TIME_WAIT does not accumulate.
// Output: CSV with one line per measured iteration (iter,ns) and a summary on stdout (JSON).
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void marker(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) close(fd);
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    long n = 20000, warmup = 1000;
    int port = 40999, markers = 0;
    const char *out = NULL, *host = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc) n = atol(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) warmup = atol(argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--markers") && i + 1 < argc) markers = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "--host") && i + 1 < argc) host = argv[++i];
        else { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    pid_t child = -1;
    if (host) {
        if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) { fprintf(stderr, "invalid host: %s\n", host); return 2; }
        goto measure;
    }

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(ls, (struct sockaddr *)&addr, sizeof addr) || listen(ls, 4096)) {
        perror("bind/listen");
        return 1;
    }
    child = fork();
    if (child == 0) {                       // acceptor
        for (;;) {
            int c = accept(ls, NULL, NULL);
            if (c >= 0) close(c);
        }
    }
    close(ls);

measure:;
    uint64_t *lat = malloc(sizeof(uint64_t) * (size_t)n);
    long failures = 0;
    uint64_t t_start = 0;
    for (long i = -warmup; i < n; i++) {
        if (i == 0) t_start = now_ns();
        uint64_t t0 = now_ns();
        if (markers) marker("/run/agentctx/begin/BENCH");
        int s = socket(AF_INET, SOCK_STREAM, 0);
        // abortive close (RST): avoids accumulating TIME_WAIT and exhausting
        // ephemeral ports between runs; recorded as a measurement decision.
        struct linger lg = {1, 0};
        setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        int r = connect(s, (struct sockaddr *)&addr, sizeof addr);
        close(s);
        if (markers) marker("/run/agentctx/end");
        uint64_t t1 = now_ns();
        if (r != 0) failures++;
        if (i >= 0) lat[i] = t1 - t0;
    }
    uint64_t wall = now_ns() - t_start;
    if (child > 0) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }

    if (out) {
        FILE *f = fopen(out, "w");
        fprintf(f, "iter,ns\n");
        for (long i = 0; i < n; i++) fprintf(f, "%ld,%lu\n", i, (unsigned long)lat[i]);
        fclose(f);
    }
    uint64_t *s = malloc(sizeof(uint64_t) * (size_t)n);
    memcpy(s, lat, sizeof(uint64_t) * (size_t)n);
    qsort(s, (size_t)n, sizeof(uint64_t), cmp_u64);
    double mean = 0;
    for (long i = 0; i < n; i++) mean += (double)lat[i];
    mean /= (double)n;
    printf("{\"n\":%ld,\"warmup\":%ld,\"markers\":%d,\"failures\":%ld,\"mean_ns\":%.1f,"
           "\"p50_ns\":%lu,\"p90_ns\":%lu,\"p99_ns\":%lu,\"max_ns\":%lu,\"wall_ns\":%lu,"
           "\"throughput_cps\":%.1f}\n",
           n, warmup, markers, failures, mean,
           (unsigned long)s[n / 2], (unsigned long)s[(long)(n * 0.9)], (unsigned long)s[(long)(n * 0.99)],
           (unsigned long)s[n - 1], (unsigned long)wall, (double)n * 1e9 / (double)wall);
    return failures ? 1 : 0;
}
