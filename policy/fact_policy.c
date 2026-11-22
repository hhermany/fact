// fact_policy: loads the BPF program, pins the maps at /sys/fs/bpf/fact,
// attaches it to the given cgroup, and prints each decision as one JSON line.
// Usage: fact_policy <cgroup_path> <port_lo> <port_hi> <no_ctx_allow 0|1> [obj] [lineage 0|1|2] [per_send 0|1] [budget 0|1|2] [cred 0|1]
// Attaches cgroup/connect4/connect6 and cgroup/sendmsg4/sendmsg6 (unconnected UDP; IPv6 and IPv4-mapped
// addresses are decided like IPv4, by port); with per_send=1 also the BPF LSM
// program on socket_sendmsg (needs lsm=...,bpf), which re-authorizes every send; with budget=1 (enforce)
// or 2 (count only) also the fexit programs on tcp_sendmsg/udp_sendmsg that charge accepted bytes to per-execution budgets.
// With cred=1 the identity is an execution credential switched by prctl(PR_FACT, ...) and authorized by the BPF LSM
// hook task_prctl (openat markers are not accepted); the kernel also stamps sockets and keeps per-credential usage
// (sent and received bytes). It needs the BPF LSM; the loader refuses to start without it.
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define ID_LEN 48
struct cfg { unsigned lo, hi, no_ctx_allow, lineage, per_send, budget, cred; };
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
	if (d->pad[2] == 2) {   /* credential switch refused: caller outside the trusted runtime */
		printf("{\"ev\":\"switch_denied\",\"ts\":%llu,\"pid\":%u,\"tid\":%u,\"claimed\":\"%s\"}\n",
		       d->ts, d->pid, d->tid, id);
		return 0;
	}
	if (d->pad[2]) {   /* marker ignored: emitted by a process outside the trusted runtime */
		printf("{\"ev\":\"marker_ignored\",\"ts\":%llu,\"pid\":%u,\"tid\":%u,\"marker\":\"%s\"}\n",
		       d->ts, d->pid, d->tid, id);
		return 0;
	}
	static const char *kinds[] = {"connect", "sendto", "send"};
	printf("{\"ev\":\"decision\",\"ts\":%llu,\"pid\":%u,\"tid\":%u,\"daddr\":\"%s\",\"dport\":%u,"
	       "\"verdict\":\"%s\",\"has_ctx\":%u,\"ctx\":\"%s\",\"conflict\":%u,\"from_lineage\":%u,\"kind\":\"%s\",\"budget\":%u,\"ip\":%u}\n",
	       d->ts, d->pid, d->tid, d->pad[5] ? "::" : ip, d->dport, d->verdict ? "allow" : "deny", d->has_ctx, id,
	       d->pad[0], d->pad[1], kinds[d->pad[3] < 3 ? d->pad[3] : 0], d->pad[4], d->pad[5] ? 6 : 4);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 5) {
		fprintf(stderr, "usage: %s <cgroup> <lo> <hi> <no_ctx_allow> [obj] [lineage] [per_send] [budget] [cred] [files]\n", argv[0]);
		return 2;
	}
	const char *obj_path = argc > 5 ? argv[5] : "fact_policy.bpf.o";
	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

	unsigned per_send = argc > 7 ? (unsigned)atoi(argv[7]) : 0;
	unsigned budget = argc > 8 ? (unsigned)atoi(argv[8]) : 0;
	unsigned cred = argc > 9 ? (unsigned)atoi(argv[9]) : 0;
	unsigned files = argc > 10 ? (unsigned)atoi(argv[10]) : 0;   /* file-write accounting by credential */
	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	if (!obj) { perror("open"); return 1; }
	/* the LSM program is loaded only when requested (it needs the BPF LSM) */
	bpf_program__set_autoload(bpf_object__find_program_by_name(obj, "on_sock_sendmsg"), per_send ? true : false);
	bpf_program__set_autoload(bpf_object__find_program_by_name(obj, "on_tcp_sent"), (budget || cred) ? true : false);
	bpf_program__set_autoload(bpf_object__find_program_by_name(obj, "on_udp_sent"), (budget || cred) ? true : false);
	bpf_program__set_autoload(bpf_object__find_program_by_name(obj, "on_udp6_sent"), (budget || cred) ? true : false);
	bpf_program__set_autoload(bpf_object__find_program_by_name(obj, "on_tcp_recv"), cred ? true : false);
	bpf_program__set_autoload(bpf_object__find_program_by_name(obj, "on_prctl"), cred ? true : false);
	bpf_program__set_autoload(bpf_object__find_program_by_name(obj, "on_openat"), cred ? false : true);
	bpf_program__set_autoload(bpf_object__find_program_by_name(obj, "on_vfs_write"), (cred && files) ? true : false);
	if (bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); return 1; }

	mkdir("/sys/fs/bpf/fact", 0700);
	const char *pins[] = {"ctx_map", "allow_map", "cfg_map", "dom_map", "owner_map", "trust_map",
			      "budget_map", "usage_map", "file_usage"};
	for (int i = 0; i < 9; i++) {
		char p[128];
		snprintf(p, sizeof(p), "/sys/fs/bpf/fact/%s", pins[i]);
		unlink(p);
		if (bpf_map__pin(bpf_object__find_map_by_name(obj, pins[i]), p)) {
			fprintf(stderr, "pin %s failed\n", p); return 1;
		}
	}
	struct cfg c = {(unsigned)atoi(argv[2]), (unsigned)atoi(argv[3]), (unsigned)atoi(argv[4]),
			argc > 6 ? (unsigned)atoi(argv[6]) : 0, per_send, budget, cred};
	int k0 = 0;
	bpf_map__update_elem(bpf_object__find_map_by_name(obj, "cfg_map"), &k0, sizeof(k0), &c, sizeof(c), BPF_ANY);

	struct bpf_link *links[16] = {0};
	int nl = 0;
	const char *tps[] = {"on_fork", "on_exit", "on_exec", "on_openat"};
	for (int i = 0; i < (cred ? 3 : 4); i++) {   /* with the credential, openat markers are not accepted */
		links[nl] = bpf_program__attach(bpf_object__find_program_by_name(obj, tps[i]));
		if (!links[nl]) { fprintf(stderr, "attach %s failed\n", tps[i]); return 1; }
		nl++;
	}
	int cg = open(argv[1], O_RDONLY | O_DIRECTORY);
	if (cg < 0) { perror("cgroup"); return 1; }
	links[nl] = bpf_program__attach_cgroup(bpf_object__find_program_by_name(obj, "on_connect4"), cg);
	if (!links[nl]) { fprintf(stderr, "attach cgroup failed\n"); return 1; }
	nl++;
	links[nl] = bpf_program__attach_cgroup(bpf_object__find_program_by_name(obj, "on_sendmsg4"), cg);
	if (!links[nl]) { fprintf(stderr, "attach cgroup/sendmsg4 failed\n"); return 1; }
	nl++;
	links[nl] = bpf_program__attach_cgroup(bpf_object__find_program_by_name(obj, "on_connect6"), cg);
	if (!links[nl]) { fprintf(stderr, "attach cgroup/connect6 failed\n"); return 1; }
	nl++;
	links[nl] = bpf_program__attach_cgroup(bpf_object__find_program_by_name(obj, "on_sendmsg6"), cg);
	if (!links[nl]) { fprintf(stderr, "attach cgroup/sendmsg6 failed\n"); return 1; }
	nl++;
	if (c.cred) {   /* the credential switch, authorized by the BPF LSM */
		links[nl] = bpf_program__attach_lsm(bpf_object__find_program_by_name(obj, "on_prctl"));
		if (!links[nl]) { fprintf(stderr, "attach lsm/task_prctl failed (is the BPF LSM enabled?)\n"); return 1; }
		nl++;
	}
	if (c.budget || c.cred) {   /* charge accepted (and, with cred, received) bytes */
		const char *fx[] = {"on_tcp_sent", "on_udp_sent", "on_udp6_sent", "on_tcp_recv"};
		for (int i = 0; i < (c.cred ? 4 : 3); i++) {
			links[nl] = bpf_program__attach(bpf_object__find_program_by_name(obj, fx[i]));
			if (!links[nl]) { fprintf(stderr, "attach %s failed\n", fx[i]); return 1; }
			nl++;
		}
	}
	if (c.cred && files) {   /* bytes written to regular files, per credential */
		links[nl] = bpf_program__attach(bpf_object__find_program_by_name(obj, "on_vfs_write"));
		if (!links[nl]) { fprintf(stderr, "attach fexit/vfs_write failed\n"); return 1; }
		nl++;
	}
	if (c.per_send) {
		links[nl] = bpf_program__attach_lsm(bpf_object__find_program_by_name(obj, "on_sock_sendmsg"));
		if (!links[nl]) { fprintf(stderr, "attach lsm/socket_sendmsg failed (is the BPF LSM enabled?)\n"); return 1; }
		nl++;
	}

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(obj, "events")),
						  on_event, NULL, NULL);
	printf("{\"ev\":\"ready\",\"lo\":%u,\"hi\":%u,\"no_ctx_allow\":%u,\"lineage\":%u,\"per_send\":%u,\"budget\":%u,\"cred\":%u}\n",
	       c.lo, c.hi, c.no_ctx_allow, c.lineage, c.per_send, c.budget, c.cred);
	while (!stop) {
		int r = ring_buffer__poll(rb, 100);
		if (r < 0 && r != -EINTR) break;
	}
	ring_buffer__poll(rb, 0);
	ring_buffer__free(rb);
	for (int i = 0; i < nl; i++) bpf_link__destroy(links[i]);
	for (int i = 0; i < 8; i++) {
		char p[128];
		snprintf(p, sizeof(p), "/sys/fs/bpf/fact/%s", pins[i]);
		unlink(p);
	}
	bpf_object__close(obj);
	return 0;
}
