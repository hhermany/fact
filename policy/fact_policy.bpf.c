// SPDX-License-Identifier: GPL-2.0
/*
 * fact_policy.bpf.c: per-execution egress policy for agents.
 *
 * Same identity as the collector: the runtime hands the execution identity to
 * the kernel via openat on /run/agentctx/begin/<id> (or /run/agentctx/end); the
 * identity is kept in a per-thread map and inherited when threads and processes
 * are created. On connect() (cgroup/connect4 and cgroup/connect6, so IPv4, IPv6 and
 * IPv4-mapped IPv6 addresses), the decision is taken by the identity of the
 * connecting thread:
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
 * Destinations are identified by port: the allow-list holds (execution, port) pairs.
 * Only ports in the policed range [cfg.lo, cfg.hi] are evaluated; the others
 * pass (so as not to affect SSH, DNS, etc. on the test host).
 * Every decision is logged to a ring buffer (auditing and evaluation).
 * Datagrams (cgroup/sendmsg4 and cgroup/sendmsg6): an unconnected UDP send (sendto with an address)
 * is decided like a connect, by the identity of the sending thread (only denials
 * are logged).
 * Per-send authorization (cfg.per_send, BPF LSM socket_sendmsg): every send on an
 * IPv4 or IPv6 TCP or UDP socket to a policed port is decided again by the identity of the
 * SENDING thread, so a connection opened by one execution and reused by another
 * (e.g., a shared keep-alive pool) carries only the sends its current user is
 * allowed to make. It needs the BPF LSM enabled (lsm=...,bpf) and send binding in
 * the runtime; denied sends fail with EPERM and are logged.
 * Execution credential (cfg.cred, BPF LSM): the identity becomes a credential of
 * the task. The runtime switches it with prctl(PR_FACT, FACT_SET, id) or
 * prctl(PR_FACT, FACT_CLEAR); the LSM hook task_prctl authorizes the switch (only
 * trusted runtime processes, when TRUST_ON is set; others get EPERM), stores the
 * credential in task-local storage (with a thread-ID mirror for the cgroup hooks),
 * and the fork tracepoint copies it to every new thread and process. Markers via
 * openat are not accepted in this mode. Sockets are stamped with the credential of
 * their opener and of their last sender (socket-local storage), and the kernel
 * keeps per-credential usage: bytes accepted by tcp_sendmsg/udp_sendmsg/udpv6_sendmsg (charged to
 * the sending task) and bytes returned by tcp_recvmsg (charged to the socket's last
 * sender), for policed destinations.
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
#include <bpf/bpf_tracing.h>

#define ID_LEN 48

struct task_struct { int pid; int tgid; } __attribute__((preserve_access_index));
struct sock_common { unsigned short skc_family; __be16 skc_dport; __be32 skc_daddr; } __attribute__((preserve_access_index));
struct sock { struct sock_common __sk_common; } __attribute__((preserve_access_index));
struct socket { struct sock *sk; } __attribute__((preserve_access_index));
struct msghdr { void *msg_name; } __attribute__((preserve_access_index));
struct inode { unsigned short i_mode; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; } __attribute__((preserve_access_index));
#define PR_FACT 0x46414354   /* "FACT" */
#define FACT_SET 1
#define FACT_CLEAR 2
#define E_PERM 1
#define E_INVAL 22
#define E_ALREADY 114
struct fact_sin { unsigned short family; __be16 port; __be32 addr; };

struct ident { char id[ID_LEN]; };
struct pkey { char id[ID_LEN]; __u32 dport; };
struct cfg { __u32 lo; __u32 hi; __u32 no_ctx_allow; __u32 lineage; __u32 per_send; __u32 budget; __u32 cred; };
/* per-execution budget (0 = no limit) and usage, kept in the kernel (E10budget) */
struct budget { __u64 max_bytes; __u64 max_conns; };
struct usage { __u64 bytes; __u64 conns; __u64 denied; __u64 rx_bytes; };
struct skcred { struct ident opener; struct ident last; };
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
struct { __uint(type, BPF_MAP_TYPE_TASK_STORAGE); __uint(map_flags, BPF_F_NO_PREALLOC);
	 __type(key, int); __type(value, struct ident); } cred_store SEC(".maps");   /* credential of each task */
struct { __uint(type, BPF_MAP_TYPE_SK_STORAGE); __uint(map_flags, BPF_F_NO_PREALLOC);
	 __type(key, int); __type(value, struct skcred); } sk_cred SEC(".maps");      /* opener and last sender of each socket */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
	 __type(key, struct ident); __type(value, struct budget); } budget_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
	 __type(key, struct ident); __type(value, struct usage); } usage_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
	 __type(key, struct ident); __type(value, __u64); } file_usage SEC(".maps");   /* bytes written to files, per credential */

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
	__u32 k0 = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &k0);
	if (c && c->cred) {   /* the credential is inherited by every new thread and process */
		struct ident *pc = bpf_task_storage_get(&cred_store, parent, 0, 0);
		if (pc) {
			struct ident *cc = bpf_task_storage_get(&cred_store, child, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
			if (cc)
				__builtin_memcpy(cc->id, pc->id, ID_LEN);
		}
	}
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
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pt, tgid = pt >> 32;
	bpf_map_delete_elem(&ctx_map, &tid);
	bpf_map_delete_elem(&dom_map, &tid);
	if (tid == tgid)   /* the right to switch dies with the registered process (no PID reuse) */
		bpf_map_delete_elem(&trust_map, &tgid);
	return 0;
}

/* The right to switch credentials belongs to the registered program, not to its PID:
 * exec revokes it (the credential itself is kept, like any other task state). */
SEC("tp_btf/sched_process_exec")
int on_exec(__u64 *ctx)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&trust_map, &tgid);
	return 0;
}

/* The credential switch: prctl(PR_FACT, FACT_SET, (unsigned long)id) or
 * prctl(PR_FACT, FACT_CLEAR). A BPF LSM program can only deny or abstain: returning
 * 0 abstains, the hook default (-ENOSYS) then lets prctl reach its option switch,
 * and an unknown option fails with EINVAL. The switch is therefore acknowledged
 * with a reserved errno: -EALREADY (switch applied), -EPERM (caller not a trusted
 * runtime) or -EINVAL (no storage). Any other prctl option is left to the kernel.
 * Without this program loaded, prctl(PR_FACT, ...) fails with EINVAL, so the
 * runtime can tell that the credential is unavailable. */
SEC("lsm/task_prctl")
int BPF_PROG(on_prctl, int option, unsigned long arg2, unsigned long arg3, unsigned long arg4,
	     unsigned long arg5, int ret)
{
	if (option != PR_FACT)
		return ret;
	__u64 pt = bpf_get_current_pid_tgid();
	__u32 tid = (__u32)pt, tgid = pt >> 32, on = TRUST_ON;
	struct ident v = {};
	if (arg2 == FACT_SET && bpf_probe_read_user_str(v.id, sizeof(v.id), (const void *)arg3) <= 1)
		return -E_INVAL;
	if (arg2 != FACT_SET && arg2 != FACT_CLEAR)
		return -E_INVAL;
	if (bpf_map_lookup_elem(&trust_map, &on) && !bpf_map_lookup_elem(&trust_map, &tgid)) {
		struct decision *d = bpf_ringbuf_reserve(&events, sizeof(*d), 0);
		if (d) {   /* switch refused: the caller is not a trusted runtime process */
			d->ts = bpf_ktime_get_ns(); d->pid = tgid; d->tid = tid; d->dport = 0; d->daddr = 0;
			d->verdict = 0; d->has_ctx = 0;
			__builtin_memset(d->pad, 0, sizeof(d->pad));
			d->pad[2] = 2;
			__builtin_memcpy(d->id, v.id, ID_LEN);
			bpf_ringbuf_submit(d, 0);
		}
		return -E_PERM;
	}
	struct task_struct *t = bpf_get_current_task_btf();
	if (arg2 == FACT_SET) {
		struct ident *s = bpf_task_storage_get(&cred_store, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (!s)
			return -E_INVAL;
		__builtin_memcpy(s->id, v.id, ID_LEN);
		bpf_map_update_elem(&ctx_map, &tid, &v, BPF_ANY);
	} else {
		bpf_task_storage_delete(&cred_store, t);
		bpf_map_delete_elem(&ctx_map, &tid);
	}
	return -E_ALREADY;
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

/* kind: 0 = connect (cgroup/connect4), 1 = unconnected datagram (cgroup/sendmsg4),
 * 2 = send on an existing socket (LSM socket_sendmsg); v6 = 1 for an IPv6 socket or address (daddr is then 0). Per-datagram and per-send
 * decisions log only denials: logging every allowed datagram costs microseconds per
 * send (E3send pilot), while a connect is logged whatever the verdict. */
static __always_inline int decide(struct cfg *c, __u32 dport, __u32 daddr, __u8 kind, __u8 v6)
{
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
	__u8 verdict, over = 0;
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
	/* budget: the accounting of the same identity, kept in the kernel, drives the
	 * decision. A connection is allowed while fewer than max_conns were attempted; a
	 * send or datagram is allowed while the bytes accepted so far (charged at the
	 * return of tcp_sendmsg/udp_sendmsg) are below max_bytes, so an execution can
	 * exceed its byte budget by at most the send that crosses it. */
	if (verdict && who && c->budget == 1) {   /* 1: count and enforce; 2: count only */
		struct budget *b = bpf_map_lookup_elem(&budget_map, who);
		struct usage *u = bpf_map_lookup_elem(&usage_map, who);
		if (b && u) {
			if (kind == 0 && b->max_conns) {
				__u64 old = __sync_fetch_and_add(&u->conns, 1);
				if (old >= b->max_conns)
					over = 1;
			} else if (kind != 0 && b->max_bytes && u->bytes >= b->max_bytes) {
				over = 1;
			}
			if (over) {
				verdict = 0;
				__sync_fetch_and_add(&u->denied, 1);
			}
		}
	}
	if (kind != 0 && verdict)
		return verdict;
	struct decision *d = bpf_ringbuf_reserve(&events, sizeof(*d), 0);
	if (d) {
		d->ts = bpf_ktime_get_ns(); d->pid = pt >> 32; d->tid = tid;
		d->dport = dport; d->daddr = daddr; d->verdict = verdict;
		d->has_ctx = v ? 1 : 0;
		__builtin_memset(d->pad, 0, sizeof(d->pad));
		d->pad[0] = conflict; d->pad[1] = from_lineage; d->pad[3] = kind; d->pad[4] = over; d->pad[5] = v6;
		if (v) __builtin_memcpy(d->id, v->id, ID_LEN); else __builtin_memset(d->id, 0, ID_LEN);
		bpf_ringbuf_submit(d, 0);
	}
	return verdict;
}

/* stamp the socket with its opener's credential (credential mode) */
static __always_inline void stamp_opener(struct bpf_sock *sk)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct ident *v = bpf_map_lookup_elem(&ctx_map, &tid);
	struct skcred *s = bpf_sk_storage_get(&sk_cred, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
	if (s) {
		if (v) __builtin_memcpy(s->opener.id, v->id, ID_LEN);
		else __builtin_memset(s->opener.id, 0, ID_LEN);
		__builtin_memcpy(&s->last, &s->opener, sizeof(s->last));
	}
}

static __always_inline int on_connect(struct bpf_sock_addr *sa, __u32 daddr, __u8 v6)
{
	__u32 k0 = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &k0);
	if (!c)
		return 1;
	__u32 dport = bpf_ntohs((__u16)sa->user_port);
	if (dport < c->lo || dport > c->hi)
		return 1;
	int verdict = decide(c, dport, daddr, 0, v6);
	if (verdict && c->cred && sa->sk)
		stamp_opener(sa->sk);
	return verdict;
}

static __always_inline int on_dgram(struct bpf_sock_addr *sa, __u32 daddr, __u8 v6)
{
	__u32 k0 = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &k0);
	if (!c)
		return 1;
	__u32 dport = bpf_ntohs((__u16)sa->user_port);
	if (dport < c->lo || dport > c->hi)
		return 1;
	return decide(c, dport, daddr, 1, v6);
}

SEC("cgroup/connect4")
int on_connect4(struct bpf_sock_addr *sa)
{
	return on_connect(sa, sa->user_ip4, 0);
}

/* IPv6, including IPv4-mapped addresses on IPv6 sockets (decided like IPv4: by port) */
SEC("cgroup/connect6")
int on_connect6(struct bpf_sock_addr *sa)
{
	return on_connect(sa, 0, 1);
}

SEC("cgroup/sendmsg4")
int on_sendmsg4(struct bpf_sock_addr *sa)
{
	return on_dgram(sa, sa->user_ip4, 0);
}

SEC("cgroup/sendmsg6")
int on_sendmsg6(struct bpf_sock_addr *sa)
{
	return on_dgram(sa, 0, 1);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(on_sock_sendmsg, struct socket *sock, struct msghdr *msg, int size, int ret)
{
	if (ret)
		return ret;
	__u32 k0 = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &k0);
	if (!c || !c->per_send)
		return 0;
	struct sock *sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;
	unsigned short fam = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (fam != 2 && fam != 10)   /* AF_INET, AF_INET6 */
		return 0;
	__be16 port = BPF_CORE_READ(sk, __sk_common.skc_dport);
	__be32 addr = fam == 2 ? BPF_CORE_READ(sk, __sk_common.skc_daddr) : 0;
	void *name = BPF_CORE_READ(msg, msg_name);
	if (name) {   /* unconnected datagram: the destination is in the message */
		struct fact_sin sin = {};   /* sockaddr_in and sockaddr_in6 share family and port */
		bpf_probe_read_kernel(&sin, sizeof(sin), name);
		if (sin.family == 2) { port = sin.port; addr = sin.addr; }
		else if (sin.family == 10) { port = sin.port; addr = 0; }
	}
	__u32 dport = bpf_ntohs(port);
	if (dport < c->lo || dport > c->hi)
		return 0;
	return decide(c, dport, addr, 2, fam == 10) ? 0 : -1;   /* -EPERM */
}

/* Budget accounting: bytes accepted by the kernel (return value), charged to the
 * identity of the sending thread (as in decide), for policed destinations. */
static __always_inline void charge(struct sock *sk, struct msghdr *msg, int ret)
{
	if (ret <= 0)
		return;
	__u32 k0 = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &k0);
	if (!c || !(c->budget || c->cred) || !sk)
		return;
	unsigned short fam = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (fam != 2 && fam != 10)   /* AF_INET, AF_INET6 */
		return;
	__be16 port = BPF_CORE_READ(sk, __sk_common.skc_dport);
	void *name = BPF_CORE_READ(msg, msg_name);
	if (name) {
		struct fact_sin sin = {};
		bpf_probe_read_kernel(&sin, sizeof(sin), name);
		if (sin.family == 2 || sin.family == 10) port = sin.port;
	}
	__u32 dport = bpf_ntohs(port);
	if (dport < c->lo || dport > c->hi)
		return;
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct ident *who;
	if (c->cred)
		who = bpf_task_storage_get(&cred_store, bpf_get_current_task_btf(), 0, 0);
	else
		who = bpf_map_lookup_elem(&ctx_map, &tid);
	if (!who && c->lineage) {
		__u32 *r = bpf_map_lookup_elem(&dom_map, &tid);
		if (r)
			who = bpf_map_lookup_elem(&owner_map, r);
	}
	if (!who)
		return;
	struct usage *u = bpf_map_lookup_elem(&usage_map, who);
	if (!u && c->cred) {
		struct usage z = {};
		bpf_map_update_elem(&usage_map, who, &z, BPF_NOEXIST);
		u = bpf_map_lookup_elem(&usage_map, who);
	}
	if (u)
		__sync_fetch_and_add(&u->bytes, (__u64)ret);
	if (c->cred) {   /* the socket's last sender, to which received bytes are charged */
		struct skcred *s = bpf_sk_storage_get(&sk_cred, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
		if (s)
			__builtin_memcpy(s->last.id, who->id, ID_LEN);
	}
}

/* Received bytes (return value of tcp_recvmsg), charged to the socket's last sender. */
SEC("fexit/tcp_recvmsg")
int BPF_PROG(on_tcp_recv, struct sock *sk, struct msghdr *msg, __u64 len, int flags, int *addr_len, int ret)
{
	if (ret <= 0 || !sk)
		return 0;
	__u32 k0 = 0;
	struct cfg *c = bpf_map_lookup_elem(&cfg_map, &k0);
	if (!c || !c->cred)
		return 0;
	unsigned short fam = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (fam != 2 && fam != 10)
		return 0;
	__u32 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (dport < c->lo || dport > c->hi)
		return 0;
	struct skcred *s = bpf_sk_storage_get(&sk_cred, sk, 0, 0);
	if (!s || !s->last.id[0])
		return 0;
	struct usage *u = bpf_map_lookup_elem(&usage_map, &s->last);
	if (!u) {
		struct usage z = {};
		bpf_map_update_elem(&usage_map, &s->last, &z, BPF_NOEXIST);
		u = bpf_map_lookup_elem(&usage_map, &s->last);
	}
	if (u)
		__sync_fetch_and_add(&u->rx_bytes, (__u64)ret);
	return 0;
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(on_tcp_sent, struct sock *sk, struct msghdr *msg, __u64 size, int ret)
{
	charge(sk, msg, ret);
	return 0;
}

SEC("fexit/udp_sendmsg")
int BPF_PROG(on_udp_sent, struct sock *sk, struct msghdr *msg, __u64 size, int ret)
{
	/* on an IPv6 socket, udp_sendmsg runs only inside udpv6_sendmsg (IPv4-mapped
	 * destination), whose fexit charges the same bytes */
	if (sk && BPF_CORE_READ(sk, __sk_common.skc_family) == 10)
		return 0;
	charge(sk, msg, ret);
	return 0;
}

SEC("fexit/udpv6_sendmsg")
int BPF_PROG(on_udp6_sent, struct sock *sk, struct msghdr *msg, __u64 size, int ret)
{
	charge(sk, msg, ret);
	return 0;
}

/* Generality (the same credential on another kernel-mediated resource): bytes that
 * vfs_write accepted for regular files (its return value), charged to the writing
 * task's credential. Loaded only with files=1 (10th loader argument). */
SEC("fexit/vfs_write")
int BPF_PROG(on_vfs_write, struct file *file, const char *buf, __u64 count, void *pos, long ret)
{
	if (ret <= 0 || !file)
		return 0;
	unsigned short mode = BPF_CORE_READ(file, f_inode, i_mode);
	if ((mode & 0170000) != 0100000)   /* S_IFREG */
		return 0;
	struct ident *who = bpf_task_storage_get(&cred_store, bpf_get_current_task_btf(), 0, 0);
	if (!who || !who->id[0])
		return 0;
	__u64 *v = bpf_map_lookup_elem(&file_usage, who);
	if (!v) {
		__u64 z = 0;
		bpf_map_update_elem(&file_usage, who, &z, BPF_NOEXIST);
		v = bpf_map_lookup_elem(&file_usage, who);
	}
	if (v)
		__sync_fetch_and_add(v, (__u64)ret);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
