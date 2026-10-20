// Task-scoped binding of the execution identity for Node.js (the same principle as
// fact_rt/agentctx.py, in a second runtime).
//
// The identity follows the asynchronous context (AsyncLocalStorage, which Node
// propagates through promises, timers, process.nextTick, and I/O callbacks) and is
// handed to the kernel immediately before each event the kernel attributes:
//   - TCP connect: the hook is on the libuv binding (TCP.prototype.connect/connect6),
//     the synchronous call that issues connect(2). net.Socket.connect itself defers
//     the call with process.nextTick, so another task could run between the public
//     API and the system call; at the binding nothing else runs before connect(2)
//     (assumption A2 of the paper's Proposition 2);
//   - process creation: ChildProcess.prototype.spawn (synchronous uv_spawn).
// The delivery mechanism is the collector's: openat on /run/agentctx/begin/<id> or
// /run/agentctx/end (nonexistent paths; one failed system call). A cache avoids
// re-marking when the identity has not changed (Node runs JavaScript on one thread;
// each worker thread loads its own copy of this module and has its own entry).
//
// Usage:
//   import * as agentctx from "../../fact_rt_node/agentctx.mjs";
//   agentctx.install();
//   await agentctx.bind("exec-42", async () => { ... });
import { AsyncLocalStorage } from "node:async_hooks";
import { createRequire } from "node:module";
import fs from "node:fs";

const require = createRequire(import.meta.url);
const CTX_BEGIN = "/run/agentctx/begin/";
const CTX_END = "/run/agentctx/end";
const UNSET = Symbol("unset");

export const current = new AsyncLocalStorage();
export const stats = { marks: 0, cached: 0 };
let last = UNSET;
let installed = false;

function emit(path) {
  try {
    fs.closeSync(fs.openSync(path, "r"));
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
}

function valid(id) {
  return typeof id === "string" && id.length > 0 && id.length <= 40 && !id.includes("/") && !id.includes("\0");
}

// Sets this thread's kernel context to the identity of the current task. Must run
// with no other task in between it and the system call it guards.
export function syncKernel() {
  const want = current.getStore();
  if (last === want) {
    stats.cached++;
    return;
  }
  emit(want !== undefined ? CTX_BEGIN + want : CTX_END);
  last = want;
  stats.marks++;
}

// Forgets the cache (use if other code emits markers).
export function invalidate() {
  last = UNSET;
}

// Runs fn with execId bound to the current asynchronous context.
export function bind(execId, fn) {
  if (execId !== undefined && execId !== null && !valid(execId)) {
    throw new Error(`invalid execution identity: ${execId}`);
  }
  return current.run(execId ?? undefined, fn);
}

// Installs the connect and process-creation hooks (idempotent).
export function install() {
  if (installed) return;
  const TCP = process.binding("tcp_wrap").TCP.prototype;
  for (const name of ["connect", "connect6"]) {
    const orig = TCP[name];
    TCP[name] = function (...args) {
      syncKernel();
      return orig.apply(this, args);
    };
  }
  const CP = require("node:child_process").ChildProcess.prototype;
  const spawn = CP.spawn;
  CP.spawn = function (...args) {
    syncKernel();
    return spawn.apply(this, args);
  };
  installed = true;
}

// MCP integration (official TypeScript SDK): wraps the tools/call handler so that each
// call runs bound to params._meta[key] of the request; tool code is unmodified.
export function instrumentMcp(mcpServer, key = "fact/exec") {
  install();
  const handlers = mcpServer.server._requestHandlers;
  const orig = handlers.get("tools/call");
  if (!orig) throw new Error("register the tools before instrumenting the server");
  handlers.set("tools/call", (request, extra) => {
    const id = request.params?._meta?.[key];
    return bind(id === undefined ? undefined : String(id), () => orig(request, extra));
  });
  return mcpServer;
}
