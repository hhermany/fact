# Fault-injection pilots (E5f, E6f, E6n, E7f)

Pilots (n = 1 per cell; E7f n = 2). They are not results of the paper: they validate the protocol
and size the confirmatory campaign. Code commit: 21f34fb.

Injected fault: an exact fraction p of each execution's calls carries another execution's identity
(in the MCP `_meta`, automatic binding; in N0/N1, in the marker). Positions drawn with a recorded seed.

| Exp. | Structure | p | Pilot outcome |
|---|---|---|---|
| E5f | shared MCP server, 4 tools, K = 2 and 8 | 0.04 and 0.20 | Every mislabeled connection was attributed to the wrong execution (I = mislabeled connections, in all 16 cells) and no other was affected: the fault does not propagate to later calls. |
| E6f | same, with policy | 0.04 and 0.20 | Every wrong decision came from a mislabeled call: 44 wrong allows and 88 wrong denies for 240 mislabeled calls (55%); no error in the others. Denied connections never reach tcp_connect and do not appear in the attribution. |
| E6n | N0 and N1 (distinct trees), with policy | 0.05 and 0.20 | Offline fusion flagged every captured mislabeled connection as ambiguous (I = 0), but the in-kernel policy, which trusts the label, was wrong in 75–80% of them (p = 0.20: 10 FA + 20 FD of 40; p = 0.05: 3 FA + 5 FD of 10). |
| E7f | 4 real LLM agents, policy active | 1 of 3 calls per agent | The 8 mislabeled calls were denied (fail closed: the agents' allow-lists are disjoint); no wrong allow. |

Reading: inside a shared worker no kernel information contradicts the label, so the fault reaches
accounting and policy, but only in the affected calls. With distinct trees, lineage detects the
contradiction offline, but the policy did not use that information yet: checking lineage in the policy
program itself (vetoing a contradicted label) removes these errors. This is the extension below.

Incident: the first attempt of E6f/E6n/E7f (campaigns 20261013T014638Z, 014703Z, 014716Z) failed in every
run because the policy loader does not build inside the Nix environment (bpf/libbpf.h is missing); it was
built with the host toolchain (`make -C policy`) and the pilots were repeated. The failed campaigns are
kept on record and not used.

## Policy with an in-kernel lineage check (E6L, E6Ls), commit 39fd8b2

The policy now knows the roots of single-owner process trees (registered by the launcher before the execution starts), inherited at each fork and thread creation. At connect, if the label contradicts the tree owner: mode 1 denies; mode 2 decides by the tree owner. Shared roots are not registered.

| Pilot | Structure | p | Mode 0 (label only) | Mode 1 (deny on conflict) | Mode 2 (tree owner) |
|---|---|---|---|---|---|
| E6L | N0 and N1, inproc and subproc | 0.05 | 3 FA + 5 FD | 0 FA + 7 FD | 0 errors |
| E6L | N0 and N1, inproc and subproc | 0.20 | 10 FA + 20 FD | 0 FA + 30 FD | 0 errors |

Per cell (equal in the 4 combinations). Conflicts flagged in the kernel = exactly the mislabeled connections, with no false alarm; mode 0 reproduced E6n. Control E6Ls (shared MCP server, mode 1): without mislabels, zero errors and zero vetoes; with p = 0.20, identical to E6f.
