import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, execFile } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import axios from "axios";

const execFileAsync = promisify(execFile);

const server = new McpServer({ name: "vuln", version: "1.0.0" });

// command injection: destructured tool arg -> exec
server.tool("run", { command: {} }, async ({ command }) => {
  return new Promise((resolve) => {
    exec(command, (_e, stdout) => resolve({ content: [{ type: "text", text: stdout }] }));
  });
});

// path traversal
server.tool("read", { path: {} }, async ({ path }) => {
  const data = fs.readFileSync(path, "utf8");
  return { content: [{ type: "text", text: data }] };
});

// SSRF
server.registerTool("fetch", { inputSchema: {} }, async ({ url }) => {
  const r = await axios.get(url);
  return { content: [{ type: "text", text: r.data }] };
});

// SQLi via template literal
server.tool("lookup", { name: {} }, async ({ name }) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${name}'`);
  return { content: [{ type: "text", text: JSON.stringify(rows) }] };
});

// command injection: execFile looks argv-safe, but `shell: this.shell` is a
// variable (not a literal false) -- if it's ever truthy at runtime, Node
// runs the joined command line through a shell anyway (the mac-shell-mcp
// CVE-2026-2035922 shape).
server.tool("runFile", { command: {}, args: {} }, async ({ command, args }) => {
  const { stdout } = await execFileAsync(command, args, { shell: this.shell });
  return { content: [{ type: "text", text: stdout }] };
});

// separator-check regex misses \n -- the cmd-line-mcp newline bypass, JS/TS
// shape.
function validateCommand(cmd: string): boolean {
  if (/[|;&]/.test(cmd)) {
    return false;
  }
  return true;
}

// NOT command injection: .exec() is also RegExp.prototype.exec(). A generic
// $CP.exec(...) pattern without a receiver check fires on any regex-based
// parser -- confirmed on real code (mcp-gitlab-server's log-line regex).
function extractLines(text: string): string[] {
  const lineRegex = /^.*$/gm;
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = lineRegex.exec(text)) !== null) out.push(m[0]);
  return out;
}
