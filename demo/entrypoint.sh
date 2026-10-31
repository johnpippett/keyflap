#!/bin/sh
# Keyflap demo container entrypoint: test RP, demo fixtures, MCP relay, then the broker in the
# foreground (its terminal approver reads this container's stdin: run with -it).
set -eu

cd /opt/keyflap
DATA="$HOME/.keyflap"
# The key store's passphrase. A public demo value: the store only ever holds test fixtures.
export KEYFLAP_PASSPHRASE=keyflap-demo-not-secret

banner() {
  cat >&2 <<'EOF'

  ################################################################################
  ##                                                                            ##
  ##   DEMO -- test site only. Don't use it with real accounts.                 ##
  ##                                                                            ##
  ##   The browser in here can only reach the bundled test site (localhost,     ##
  ##   *.localhost); every other site fails to load. Everything is gone when    ##
  ##   the container stops. The demo is not a security boundary: an agent that  ##
  ##   can run commands as you can also run podman/docker.                      ##
  ##                                                                            ##
  ################################################################################

EOF
}

banner
if [ ! -t 0 ]; then
  echo "note: stdin is not a terminal. Approvals are typed here: run with -it (see demo/README.md)." >&2
fi

# 1. The test relying party (packages/test-rp), loopback only. Passkeys on
#    http://localhost:3000, password + TOTP on http://rp.localhost:3000 (same server).
node packages/test-rp/src/main.ts >"$HOME/test-rp.log" 2>&1 &
i=0
until node -e "fetch('http://127.0.0.1:3000/').then(()=>process.exit(0),()=>process.exit(1))" 2>/dev/null; do
  i=$((i + 1))
  [ "$i" -lt 50 ] || { echo "test RP did not start; see $HOME/test-rp.log" >&2; exit 1; }
  sleep 0.2
done

# 2. Demo fixtures: the test RP's seeded login (public test values, packages/test-rp/src/main.ts).
printf '%s\n%s\n' 'correct horse battery staple' 'JBSWY3DPEHPK3PXP' |
  keyflap password add rp.localhost --username alice --totp >/dev/null

# 3. The agent your MCP client connects as.
added=$(keyflap agent add demo-agent)
AGENT_ID=$(printf '%s\n' "$added" | sed -n 's/^Added agent "demo-agent" (id \([^)]*\))\.$/\1/p')
TOKEN=$(printf '%s\n' "$added" | grep -oE 'aab_agent_[A-Za-z0-9_-]{43}' | head -n 1)
[ -n "$AGENT_ID" ] && [ -n "$TOKEN" ] || { echo "could not create the demo agent" >&2; exit 1; }
printf '%s\n' "$AGENT_ID" >"$DATA/demo-agent-id"

# 4. Relay the published port to the loopback-only MCP endpoint (demo/mcp-relay.ts).
node demo/mcp-relay.ts &

cat >&2 <<EOF
== On your host ==============================================================

1. Connect an MCP client to http://127.0.0.1:8765/mcp with this agent token
   (it changes every run):

     export KEYFLAP_AGENT_TOKEN=$TOKEN

   Claude Code: put this in .mcp.json in an empty scratch directory, and start
   \`claude\` there with KEYFLAP_AGENT_TOKEN exported:

     {
       "mcpServers": {
         "keyflap": {
           "type": "http",
           "url": "http://127.0.0.1:8765/mcp",
           "headers": { "Authorization": "Bearer \${KEYFLAP_AGENT_TOKEN}" }
         }
       }
     }

2. Before each sign-in, tell the broker what you asked for, in a second host
   terminal (the agent can't do this for you; see demo/README.md):

     podman exec -it keyflap-demo say "sign me in to the test site"

3. Ask the agent, for example:
     Go to http://rp.localhost:3000/password/login and sign in with my password.
     Go to http://localhost:3000/signup, sign up as bob and add a passkey.

4. Approve or deny here: the approval prompt appears in this terminal; type y.

Ctrl-C stops the demo and deletes everything.
==============================================================================
EOF

# 5. The broker, in the foreground: approvals are read from this terminal.
exec keyflap daemon --unprotected --ephemeral-browser
