# M2 plan: agent surface

Status: **done**. Invariant tests: IMPLEMENTATION_NOTES "Status".

Scope (section 15): MCP server, mediated browser tools, intent hook with one reference
host integration, auto-deny without intent, audit log. Invariant tests: 1, 4, 5, 7, 10.

## Shape

```
 agent (e.g. Claude Code) ──MCP over HTTP, 127.0.0.1, Bearer <agent token>──► @aab/mcp
                                                                              │ AgentBrowserPort
 agent host hook ──HTTP over unix socket run/intent.sock, Bearer <host token>─► @aab/core daemon
   (UserPromptSubmit)                                                         │
                                          signer (process) ◄── broker ──► managed Chromium
                                                                (one BrowserContext per agent)
```

- **One daemon** (`startDaemon` in core) owns the signer, SQLite, the broker, one managed
  Chromium, one BrowserContext per agent, the intent socket, and the MCP HTTP endpoint.
- **Agent identity** comes only from the agent token → `agents` row. Never from MCP
  `clientInfo` (agent-controlled). The approval prompt's agent name is the registered name.
- **Agent tokens** (`aab_agent_…`, 32 random bytes) authenticate MCP. Stored as SHA-256 in
  `agents.token_hash`. The agent may know its own token.
- **Host token** (`<dataDir>/host-token`, 0600) authenticates the intent socket. The model
  must never see it. Same-uid caveat from IMPLEMENTATION_NOTES applies: the agent must not
  be able to read that file (sandbox / separate user); document it in the integration.

## Contracts

### `@aab/mcp` (packages/mcp/src/port.ts is the source of truth)
- `startMcpHttpServer({ host, port, resolve: AgentResolver, onToolCall?: ToolCallObserver })`
  → `{ url, close() }`. Streamable HTTP (`@modelcontextprotocol/sdk`). Requires
  `Authorization: Bearer`; the token is resolved on every request and an MCP session stays
  bound to the agent that opened it. Rejects non-loopback Host headers and any request with
  an `Origin` header (DNS-rebinding / browser access).
- Tools: `browser_open{url}`, `browser_click{target}`, `browser_type{target,text,submit?}`,
  `browser_snapshot{}`, `auth_status{}`, `auth_login{timeoutMs?}`,
  `auth_enroll_passkey{timeoutMs?}`. No tool takes an origin, justification, script,
  selector-engine string, or CDP access. Nothing else is exposed.
- Errors: `ToolError` message → tool error text; anything else → `"internal error"`.

### Intent socket (core)
- `<dataDir>/run/intent.sock` (dir 0700, socket 0600). HTTP/1.1.
- `POST /v1/intents`, `Authorization: Bearer <host token>`, JSON `{ "agentId": string,
  "text": string }` (text 1..8000 chars, stored verbatim) → `201 {"intentId","expiresAt"}`.
  401 bad/missing token (constant-time compare), 400 bad body, 404 unknown agent,
  413 body > 64 KiB. Nothing else is routed.
- Audit: `intent.recorded {intentId, agentId, textSha256}`. Never the text.

### Daemon (core)
```ts
startDaemon({ dataDir, passphrase, approver, trustedApproverKeys,
              mcpHost?: '127.0.0.1', mcpPort?: number /* 0 = random */,
              headless?, launchArgs?, intentTtlMs?, approvalTimeoutMs? })
  → { mcpUrl, intentSocketPath, hostToken, broker, registry: AgentRegistry, stop() }
AgentRegistry: add(name) → { id, name, token }  // token shown once
               byToken(token) → { id, name } | null; list(); revoke(id)
```
- `Broker.handleWebAuthn(req, agent)` takes the agent bound to the BrowserContext the
  request came from.
- Audit additions: `tool.call {agentId, tool, ok, origin?}` (origin of the agent's page
  after the call; never arguments, typed text, or snapshots), `intent.recorded`, plus
  the existing request/approval/denied/passkey.* events.

### CLI + reference integration (phase 2)
- `aab daemon`, `aab agent add|list|revoke`, `aab hook claude-code` (UserPromptSubmit:
  reads the hook JSON on stdin, forwards `prompt` to the intent socket for the configured
  agent; never prints the token; exits 0 on failure so the user's prompt isn't blocked).
- `docs/integrations/claude-code.md`: MCP config, hook config, the sandbox requirement.

## Invariant tests (phase 2)
1. No secret material in any MCP tool output across register + sign-in flows.
4. No prompt without a live out-of-band intent: none, expired, other agent's, forged via
   MCP (impossible: no tool accepts one), wrong host token → auto-deny, logged.
5. Prompt shows only verbatim intent, verified origin, registered agent name, credential
   type. Page-controlled (rp.name, user.name/displayName, title) and agent-controlled
   (tool args, MCP clientInfo) strings never reach `ApprovalRequest.display` or the render.
7. No raw CDP for the agent: tool list is exactly the seven tools; no remote-debugging
   port/DevToolsActivePort; non-http(s) URLs refused.
10. Every request, decision, operation, tool call and intent is in the hash chain;
    tampering is detected; payloads carry no secrets.
