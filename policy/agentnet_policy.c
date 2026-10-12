// agentnet_policy: carrega o programa BPF, prende os mapas em /sys/fs/bpf/agentnet,
// anexa ao cgroup indicado e imprime cada decisão como uma linha JSON.
// Uso: agentnet_policy <cgroup_path> <porta_lo> <porta_hi> <no_ctx_allow 0|1> [obj]
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define ID_LEN 48
struct cfg { unsigned lo, hi, no_ctx_allow, pad; };
struct decision {
	unsigned long long ts; unsigned pid, tid, dport, daddr;
	unsigned char verdict, has_ctx, pad[6]; char id[ID_LEN];
};

static volatile int stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int on_event(void *ctx, void *data, size_t sz)
{
	(void)ctx; (void)sz;
	const struct decision *d = data;
	char ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &d->daddr, ip, sizeof(ip));
	char id[ID_LEN + 1];
	memcpy(id, d->id, ID_LEN); id[ID_LEN] = 0;
	printf("{\"ev\":\"decision\",\"ts\":%llu,\"pid\":%u,\"tid\":%u,\"daddr\":\"%s\",\"dport\":%u,"
	       "\"verdict\":\"%s\",\"has_ctx\":%u,\"ctx\":\"%s\"}\n",
	       d->ts, d->pid, d->tid, ip, d->dport, d->verdict ? "allow" : "deny", d->has_ctx, id);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 5) {
		fprintf(stderr, "uso: %s <cgroup> <lo> <hi> <no_ctx_allow> [obj]\n", argv[0]);
		return 2;
	}
	const char *obj_path = argc > 5 ? argv[5] : "agentnet_policy.bpf.o";
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	if (!obj) { perror("open"); return 1; }
	if (bpf_object__load(obj)) { fprintf(stderr, "load falhou\n"); return 1; }

	mkdir("/sys/fs/bpf/agentnet", 0700);
	const char *pins[] = {"ctx_map", "allow_map", "cfg_map"};
	for (int i = 0; i < 3; i++) {
		char p[128];
		snprintf(p, sizeof(p), "/sys/fs/bpf/agentnet/%s", pins[i]);
		unlink(p);
		if (bpf_map__pin(bpf_object__find_map_by_name(obj, pins[i]), p)) {
			fprintf(stderr, "pin %s falhou\n", p); return 1;
		}
	}
	struct cfg c = {(unsigned)atoi(argv[2]), (unsigned)atoi(argv[3]), (unsigned)atoi(argv[4]), 0};
	int k0 = 0;
	bpf_map__update_elem(bpf_object__find_map_by_name(obj, "cfg_map"), &k0, sizeof(k0), &c, sizeof(c), BPF_ANY);

	struct bpf_link *links[4] = {0};
	int nl = 0;
	const char *tps[] = {"on_openat", "on_fork", "on_exit"};
	for (int i = 0; i < 3; i++) {
		links[nl] = bpf_program__attach(bpf_object__find_program_by_name(obj, tps[i]));
		if (!links[nl]) { fprintf(stderr, "attach %s falhou\n", tps[i]); return 1; }
		nl++;
	}
	int cg = open(argv[1], O_RDONLY | O_DIRECTORY);
	if (cg < 0) { perror("cgroup"); return 1; }
	links[nl] = bpf_program__attach_cgroup(bpf_object__find_program_by_name(obj, "on_connect4"), cg);
	if (!links[nl]) { fprintf(stderr, "attach cgroup falhou\n"); return 1; }
	nl++;

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(obj, "events")),
						  on_event, NULL, NULL);
	printf("{\"ev\":\"ready\",\"lo\":%u,\"hi\":%u,\"no_ctx_allow\":%u}\n", c.lo, c.hi, c.no_ctx_allow);
	while (!stop) {
		int r = ring_buffer__poll(rb, 100);
		if (r < 0 && r != -EINTR) break;
	}
	ring_buffer__poll(rb, 0);
	ring_buffer__free(rb);
	for (int i = 0; i < nl; i++) bpf_link__destroy(links[i]);
	for (int i = 0; i < 3; i++) {
		char p[128];
		snprintf(p, sizeof(p), "/sys/fs/bpf/agentnet/%s", pins[i]);
		unlink(p);
	}
	bpf_object__close(obj);
	return 0;
}
