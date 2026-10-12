// SPDX-License-Identifier: GPL-2.0
/*
 * agentnet_policy.bpf.c — política de saída por execução de agente.
 *
 * Mesma identidade do coletor: o runtime entrega a identidade da execução ao
 * kernel por openat em /run/agentctx/begin/<id> (ou /run/agentctx/end); a
 * identidade fica num mapa por thread e é herdada na criação de threads e
 * processos. No connect() IPv4 (cgroup/connect4), a decisão é tomada pela
 * identidade da thread que conecta:
 *   - com identidade: permite se (id, porta) está na lista de permissões;
 *     caso contrário nega (EPERM);
 *   - sem identidade: ação padrão configurável (cfg.no_ctx_allow).
 * Só portas no intervalo policiado [cfg.lo, cfg.hi] são avaliadas; as demais
 * passam (para não afetar SSH, DNS etc. no host de teste).
 * Cada decisão é registrada num ring buffer (auditoria e avaliação).
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define ID_LEN 48

struct task_struct { int pid; int tgid; } __attribute__((preserve_access_index));

struct ident { char id[ID_LEN]; };
struct pkey { char id[ID_LEN]; __u32 dport; };
struct cfg { __u32 lo; __u32 hi; __u32 no_ctx_allow; __u32 pad; };
struct decision {
	__u64 ts; __u32 pid; __u32 tid; __u32 dport; __u32 daddr;
	__u8 verdict; __u8 has_ctx; __u8 pad[6]; char id[ID_LEN];
};

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
	 __type(key, __u32); __type(value, struct ident); } ctx_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536);
	 __type(key, struct pkey); __type(value, __u8); } allow_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	 __type(key, __u32); __type(value, struct cfg); } cfg_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 22); } events SEC(".maps");

/* syscalls:sys_enter_openat (formato: __syscall_nr em 8, dfd em 16, filename em 24) */
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
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
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
	return 0;
}

SEC("tp_btf/sched_process_exit")
int on_exit(__u64 *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&ctx_map, &tid);
	return 0;
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
	__u8 verdict;
	struct pkey k = {};
	if (v) {
		__builtin_memcpy(k.id, v->id, ID_LEN);
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
		if (v) __builtin_memcpy(d->id, v->id, ID_LEN); else __builtin_memset(d->id, 0, ID_LEN);
		bpf_ringbuf_submit(d, 0);
	}
	return verdict;
}

char LICENSE[] SEC("license") = "GPL";
