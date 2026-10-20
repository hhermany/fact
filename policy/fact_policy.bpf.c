// SPDX-License-Identifier: GPL-2.0
/*
 * fact_policy.bpf.c: per-execution egress policy for agents.
 *
 * Same identity as the collector: the runtime hands the execution identity to
 * the kernel via openat on /run/agentctx/begin/<id> (or /run/agentctx/end); the
 * identity is kept in a per-thread map and inherited when threads and processes
 * are created. On IPv4 connect() (cgroup/connect4), the decision is taken by the
 * identity of the connecting thread:
 *   - with identity: allow if (id, port) is in the allow-list;
 *     otherwise deny (EPERM);
 *   - without identity: configurable default action (cfg.no_ctx_allow).
 * Lineage (cfg.lineage): user space registers the roots of process trees that
 * belong to ONE execution (owner_map); the root is inherited by threads and
 * child processes (dom_map). If the thread's label contradicts the tree owner:
 * mode 1 denies the connection (conflict); mode 2 decides by the tree owner.
 * Without a label, it decides by the tree owner. Roots shared by several
 * executions (a shared worker) are not registered: there lineage does not
 * separate executions and the decision follows the label, as before.
 * Only ports in the policed range [cfg.lo, cfg.hi] are evaluated; the others
 * pass (so as not to affect SSH, DNS, etc. on the test host).
 * Every decision is logged to a ring buffer (auditing and evaluation).
 * Trusted runtime (optional, E6spoof): when user space sets the key TRUST_ON in
 * trust_map, markers are accepted only from the thread groups (processes)
 * registered in trust_map, i.e., the agent runtime itself. A marker emitted by
 * any other process (e.g., a tool's child process) is ignored and logged, so the
 * child keeps the identity it inherited at fork. Without TRUST_ON, every marker
 * is accepted, as before.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define ID_LEN 48

struct task_struct { int pid; int tgid; } __attribute__((preserve_access_index));

struct ident { char id[ID_LEN]; };
struct pkey { char id[ID_LEN]; __u32 dport; };
struct cfg { __u32 lo; __u32 hi; __u32 no_ctx_allow; __u32 lineage; };
struct decision {
	__u64 ts; __u32 pid; __u32 tid; __u32 dport; __u32 daddr;
	__u8 verdict; __u8 has_ctx; __u8 pad[6]; char id[ID_LEN];
};

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
	 __type(key, __u32); __type(value, struct ident); } ctx_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
	 __type(key, struct pkey); __type(value, __u8); } allow_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
	 __type(key, __u32); __type(value, __u32); } dom_map SEC(".maps");      /* tid -> root */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
	 __type(key, __u32); __type(value, struct ident); } owner_map SEC(".maps"); /* root -> execution */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	 __type(key, __u32); __type(value, struct cfg); } cfg_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 22); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1024);
	 __type(key, __u32); __type(value, __u8); } trust_map SEC(".maps");      /* tgid -> 1; TRUST_ON -> 1 */
#define TRUST_ON 0xffffffffu

/* syscalls:sys_enter_openat (format: __syscall_nr at 8, dfd at 16, filename at 24) */
struct openat_args { __u64 common; int nr; int pad; long dfd; const char *filename; long flags; long mode; };

static const char BEGIN[] = "/run/agentctx/begin/";   /* 20 bytes */
static const char END[] = "/run/agentctx/end";

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct openat_args *a)
{
	char buf[20 + ID_LEN];
	long n = bpf_probe_read_user_str(buf, sizeof(buf), a->filename);
	if (n < 14)
		return 0;
	for (int i = 0; i < 14; i++)
		if (buf[i] != BEGIN[i])
			return 0;
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pt;
	__u32 on = TRUST_ON, tgid = pt >> 32;
	if (bpf_map_lookup_elem(&trust_map, &on) && !bpf_map_lookup_elem(&trust_map, &tgid)) {
		struct decision *d = bpf_ringbuf_reserve(&events, sizeof(*d), 0);
		if (d) {   /* marker from an untrusted process: ignored, logged */
			d->ts = bpf_ktime_get_ns(); d->pid = tgid; d->tid = tid; d->dport = 0; d->daddr = 0;
			d->verdict = 0; d->has_ctx = 0;
			__builtin_memset(d->pad, 0, sizeof(d->pad));
			d->pad[2] = 1;
			bpf_probe_read_kernel_str(d->id, ID_LEN, buf + 14);   /* "begin/<id>" or "end" */
			bpf_ringbuf_submit(d, 0);
		}
		return 0;
	}
	int is_begin = 1;
	for (int i = 14; i < 20; i++)
		if (buf[i] != BEGIN[i]) { is_begin = 0; break; }
	if (is_begin && n > 21) {
		struct ident v = {};
		bpf_probe_read_kernel_str(v.id, sizeof(v.id), buf + 20);
		bpf_map_update_elem(&ctx_map, &tid, &v, BPF_ANY);
		return 0;
	}
	for (int i = 14; i < 17; i++)
		if (buf[i] != END[i])
			return 0;
	bpf_map_delete_elem(&ctx_map, &tid);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int on_fork(__u64 *ctx)
{
	struct task_struct *parent = (struct task_struct *)ctx[0];
	struct task_struct *child = (struct task_struct *)ctx[1];
	__u32 ptid = BPF_CORE_READ(parent, pid);
	__u32 ctid = BPF_CORE_READ(child, pid);
	struct ident *v = bpf_map_lookup_elem(&ctx_map, &ptid);
	if (v)
		bpf_map_update_elem(&ctx_map, &ctid, v, BPF_ANY);
	__u32 *r = bpf_map_lookup_elem(&dom_map, &ptid);
	if (r) {
		__u32 root = *r;
		bpf_map_update_elem(&dom_map, &ctid, &root, BPF_ANY);
	}
	return 0;
}

SEC("tp_btf/sched_process_exit")
int on_exit(__u64 *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&ctx_map, &tid);
	bpf_map_delete_elem(&dom_map, &tid);
	return 0;
}

static __always_inline int id_eq(const char *a, const char *b)
{
	for (int i = 0; i < ID_LEN; i++) {
		if (a[i] != b[i])
			return 0;
		if (a[i] == 0)
			return 1;
	}
	return 1;
}

SEC("cgroup/connect4")
int on_connect4(struct bpf_sock_addr *sa)
{
	__u32 k0 = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &k0);
	if (!c)
		return 1;
	__u32 dport = bpf_ntohs((__u16)sa->user_port);
	if (dport < c->lo || dport > c->hi)
		return 1;
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pt;
	struct ident *v = bpf_map_lookup_elem(&ctx_map, &tid);
	struct ident *own = 0;
	if (c->lineage) {
		__u32 *r = bpf_map_lookup_elem(&dom_map, &tid);
		if (r)
			own = bpf_map_lookup_elem(&owner_map, r);
	}
	struct ident *who = v;        /* identity used in the decision */
	__u8 conflict = 0, from_lineage = 0;
	if (own) {
		if (!v) {
			who = own; from_lineage = 1;
		} else if (!id_eq(v->id, own->id)) {
			conflict = 1;
			if (c->lineage == 2) { who = own; from_lineage = 1; }
		}
	}
	__u8 verdict;
	struct pkey k = {};
	if (conflict && c->lineage == 1) {
		verdict = 0;
	} else if (who) {
		__builtin_memcpy(k.id, who->id, ID_LEN);
		k.dport = dport;
		verdict = bpf_map_lookup_elem(&allow_map, &k) ? 1 : 0;
	} else {
		verdict = c->no_ctx_allow ? 1 : 0;
	}
	struct decision *d = bpf_ringbuf_reserve(&events, sizeof(*d), 0);
	if (d) {
		d->ts = bpf_ktime_get_ns(); d->pid = pt >> 32; d->tid = tid;
		d->dport = dport; d->daddr = sa->user_ip4; d->verdict = verdict;
		d->has_ctx = v ? 1 : 0;
		__builtin_memset(d->pad, 0, sizeof(d->pad));
		d->pad[0] = conflict; d->pad[1] = from_lineage;
		if (v) __builtin_memcpy(d->id, v->id, ID_LEN); else __builtin_memset(d->id, 0, ID_LEN);
		bpf_ringbuf_submit(d, 0);
	}
	return verdict;
}

char LICENSE[] SEC("license") = "GPL";
