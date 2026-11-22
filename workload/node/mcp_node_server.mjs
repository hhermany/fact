#!/usr/bin/env node
// MCP server in Node.js (official TypeScript SDK, SSE transport) used in E5node: the
// second runtime. One process serves every client session (shared worker; one
// McpServer per session, all on the same event loop and the same thread). Each tool
// opens ONE TCP connection to the requested port:
//
//   async_get    asynchronous with a pending timer (0-5 ms) before net.connect: calls
//                of different sessions interleave on the single JavaScript thread
//   subproc_get  spawns a child process (node -e connect); the child inherits the
//                context of the thread that creates it
//   http_get     node:http client (core library, unmodified; no keep-alive) GET
//
// Binding modes (--binding):
//   manual  the tools emit FACT's markers at their start and end (thread-keyed
//           binding, as E4's manual mode; expected to fail when calls interleave);
//   auto    the tools emit nothing: the server is instrumented by
//           fact_rt_node/agentctx.mjs (per-task identity in AsyncLocalStorage,
//           handed to the kernel at connect and at spawn); the identity comes from
//           the request's _meta["fact/exec"].
//
// Usage: node mcp_node_server.mjs --port 64999 [--binding manual|auto]
import http from "node:http";
import net from "node:net";
import fs from "node:fs";
import { spawn } from "node:child_process";
import { parseArgs } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { z } from "zod";
import * as agentctx from "../../fact_rt_node/agentctx.mjs";

const CTX_BEGIN = "/run/agentctx/begin/";
const CTX_END = "/run/agentctx/end";
// 127.0.0.1, or ::1 with FACT_FAMILY=6 (as workload/netfam.py)
const LISTEN = process.env.FACT_FAMILY === "6" ? "::1" : "127.0.0.1";
const TARGET = process.env.FACT_DEST || LISTEN;
const SUB =
  "const s=require('net').connect({host:process.argv[1],port:+process.argv[2]});" +
  "s.setTimeout(2000,()=>process.exit(1));s.on('connect',()=>{s.destroy();process.exit(0)});" +
  "s.on('error',()=>process.exit(1))";

const { values: a } = parseArgs({
  options: { port: { type: "string", default: "64999" }, binding: { type: "string", default: "manual" } },
});
if (!["manual", "auto"].includes(a.binding)) throw new Error("--binding manual|auto");
const MANUAL = a.binding === "manual";

function mark(p) {
  if (!MANUAL) return;
  try {
    fs.closeSync(fs.openSync(p, "r"));
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ok = (t) => ({ content: [{ type: "text", text: t }] });

function tcpConnect(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: TARGET, port });
    s.setTimeout(2000, () => (s.destroy(), resolve(false)));
    s.on("connect", () => (s.destroy(), resolve(true)));
    s.on("error", () => resolve(false));
  });
}

function httpGet(port) {
  return new Promise((resolve) => {
    const req = http.get({ host: TARGET, port, path: "/", agent: false, timeout: 5000 }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode === 200));
    });
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(false));
  });
}

function childConnect(port) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, ["-e", SUB, TARGET, String(port)], { stdio: "ignore" });
    p.on("exit", (rc) => resolve(rc === 0));
    p.on("error", () => resolve(false));
  });
}

async function marked(execId, body) {
  mark(CTX_BEGIN + execId);
  try {
    return ok((await body()) ? "ok" : "fail");
  } finally {
    mark(CTX_END);
  }
}

function makeServer() {
  const s = new McpServer({ name: "fact-e5node", version: "1.0.0" });
  const args = { exec_id: z.string(), port: z.number().int() };
  s.tool("async_get", args, ({ exec_id, port }) =>
    marked(exec_id, async () => {
      await sleep(Math.random() * 5); // realistic interleaving point (pending I/O)
      return tcpConnect(port);
    }));
  s.tool("subproc_get", args, ({ exec_id, port }) => marked(exec_id, () => childConnect(port)));
  s.tool("http_get", args, ({ exec_id, port }) =>
    marked(exec_id, async () => {
      await sleep(Math.random() * 5);
      return httpGet(port);
    }));
  if (!MANUAL) agentctx.instrumentMcp(s);
  return s;
}

const transports = new Map();
const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === "GET" && url.pathname === "/sse") {
    const t = new SSEServerTransport("/messages/", res);
    transports.set(t.sessionId, t);
    res.on("close", () => transports.delete(t.sessionId));
    await makeServer().connect(t);
  } else if (req.method === "POST" && url.pathname.startsWith("/messages")) {
    const t = transports.get(url.searchParams.get("session_id") ?? url.searchParams.get("sessionId"));
    if (!t) {
      res.writeHead(404).end("unknown session");
      return;
    }
    await t.handlePostMessage(req, res);
  } else {
    res.writeHead(404).end();
  }
});
httpServer.listen(+a.port, LISTEN, () => {
  process.stderr.write(`fact-e5node listening on ${LISTEN}:${a.port} binding=${a.binding} node=${process.version}\n`);
});
process.on("SIGTERM", () => {
  if (!MANUAL) process.stderr.write(`agentctx stats ${JSON.stringify(agentctx.stats)}\n`);
  process.exit(0);
});
