// send_bench.c: per-send latency microbenchmark (E3send): cost of authorizing every send.
//
// A receiver thread drains a local socket; the measuring thread sends --size-byte
// messages and times each send() / sendto() with CLOCK_MONOTONIC.
//   --proto tcp   one connected TCP socket (TCP_NODELAY)       -> send()
//   --proto udp   one connected UDP socket                     -> send()
//   --proto udpu  one unconnected UDP socket                   -> sendto() with an address
// The measuring thread emits the context marker once (openat /run/agentctx/begin/BENCH)
// before the warm-up, so a policy that authorizes sends finds an identity for it; the
// receiver thread has none (receives are not policed).
//
// Usage: send_bench --proto tcp|udp|udpu --n 200000 --warmup 10000 --port P --size 64 [--out lat.csv]
// Output: summary on stdout (JSON); optionally one CSV line per measured send.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

static volatile int done;

static void *drain(void *arg) {
    int fd = *(int *)arg;
    char buf[65536];
    while (!done) {
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r == 0) break;
    }
    return NULL;
}

int main(int argc, char **argv) {
    long n = 200000, warmup = 10000;
    int port = 63500, size = 64;
    const char *proto = "tcp", *out = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc) n = atol(argv[++i]);
        else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) warmup = atol(argv[++i]);
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--size") && i + 1 < argc) size = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--proto") && i + 1 < argc) proto = argv[++i];
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) out = argv[++i];
        else { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
    }
    int tcp = !strcmp(proto, "tcp"), udpu = !strcmp(proto, "udpu");
    if (!tcp && !udpu && strcmp(proto, "udp")) { fprintf(stderr, "unknown proto %s\n", proto); return 2; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int one = 1, rfd, s;
    if (tcp) {
        int ls = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(ls, (struct sockaddr *)&addr, sizeof addr) || listen(ls, 1)) { perror("bind/listen"); return 1; }
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(s, (struct sockaddr *)&addr, sizeof addr)) { perror("connect"); return 1; }
        rfd = accept(ls, NULL, NULL);
        close(ls);
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    } else {
        rfd = socket(AF_INET, SOCK_DGRAM, 0);
        int big = 8 << 20;
        setsockopt(rfd, SOL_SOCKET, SO_RCVBUF, &big, sizeof big);
        if (bind(rfd, (struct sockaddr *)&addr, sizeof addr)) { perror("bind"); return 1; }
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (!udpu && connect(s, (struct sockaddr *)&addr, sizeof addr)) { perror("connect"); return 1; }
    }
    pthread_t th;
    pthread_create(&th, NULL, drain, &rfd);

    // identity of the measuring thread (one marker; the policy keys identities by thread)
    int mfd = open("/run/agentctx/begin/BENCH", O_RDONLY);
    if (mfd >= 0) close(mfd);

    char *msg = calloc(1, (size_t)size);
    uint64_t *lat = malloc(sizeof(uint64_t) * (size_t)n);
    long failures = 0;
    uint64_t t_start = 0;
    for (long i = -warmup; i < n; i++) {
        if (i == 0) t_start = now_ns();
        uint64_t t0 = now_ns();
        ssize_t r = udpu ? sendto(s, msg, (size_t)size, 0, (struct sockaddr *)&addr, sizeof addr)
                         : send(s, msg, (size_t)size, 0);
        uint64_t t1 = now_ns();
        if (r != size) failures++;
        if (i >= 0) lat[i] = t1 - t0;
    }
    uint64_t wall = now_ns() - t_start;
    done = 1;
    shutdown(s, SHUT_RDWR);
    close(s);
    shutdown(rfd, SHUT_RDWR);
    pthread_join(th, NULL);

    if (out) {
        FILE *f = fopen(out, "w");
        fprintf(f, "iter,ns\n");
        for (long i = 0; i < n; i++) fprintf(f, "%ld,%lu\n", i, (unsigned long)lat[i]);
        fclose(f);
    }
    qsort(lat, (size_t)n, sizeof(uint64_t), cmp_u64);
    double mean = 0;
    for (long i = 0; i < n; i++) mean += (double)lat[i];
    mean /= (double)n;
    printf("{\"proto\":\"%s\",\"n\":%ld,\"warmup\":%ld,\"size\":%d,\"port\":%d,\"failures\":%ld,\"mean_ns\":%.1f,"
           "\"p50_ns\":%lu,\"p90_ns\":%lu,\"p99_ns\":%lu,\"max_ns\":%lu,\"wall_ns\":%lu,"
           "\"throughput_sps\":%.1f}\n",
           proto, n, warmup, size, port, failures, mean,
           (unsigned long)lat[n / 2], (unsigned long)lat[(long)(n * 0.9)], (unsigned long)lat[(long)(n * 0.99)],
           (unsigned long)lat[n - 1], (unsigned long)wall, (double)n * 1e9 / (double)wall);
    return failures ? 1 : 0;
}
