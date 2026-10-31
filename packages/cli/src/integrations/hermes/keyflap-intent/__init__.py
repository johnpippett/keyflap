"""Keyflap intent plugin for Hermes Agent (docs/integrations/hermes.md in the Keyflap repo).

On every admitted gateway message (``post_gateway_admission``) it runs
``keyflap hook hermes ...`` with the hook's arguments as JSON on stdin. That command decides
everything (owner allowlist, direct messages only, no synthetic turns) and records the
text verbatim as the Keyflap agent's live intent. This file only forwards: it never reads
the text, logs nothing about the message, never changes or consumes it, and always
returns None, so Hermes handles the message exactly as without the plugin.

Settings come from ``config.json`` next to this file (no secrets in it):
  {"command": ["/usr/bin/node", "/path/to/keyflap/packages/cli/src/main.ts"],
   "agent": "<agent id>", "owners": ["telegram:123456789"],
   "profile": null, "dataDir": null, "service": false}
Python standard library only.
"""

import asyncio
import json
import logging
import os

_DIR = os.path.dirname(os.path.abspath(__file__))
_TIMEOUT_SECONDS = 5.0
logger = logging.getLogger(__name__)


def build_argv(cfg):
    """The ``keyflap hook hermes`` argv from config.json; raises ValueError if it is unusable."""
    command, agent, owners = cfg.get("command"), cfg.get("agent"), cfg.get("owners")
    strings = lambda v: isinstance(v, list) and v and all(isinstance(x, str) and x for x in v)
    if not strings(command) or not os.path.isabs(command[0]):
        raise ValueError("command must be a list starting with an absolute path")
    if not isinstance(agent, str) or not agent or not strings(owners):
        raise ValueError("agent and owners are required")
    argv = [*command, "hook", "hermes", "--agent", agent]
    for owner in owners:
        argv += ["--owner", owner]
    if cfg.get("profile"):
        argv += ["--profile", str(cfg["profile"])]
    if cfg.get("service") is True:
        argv.append("--service")
    elif cfg.get("dataDir"):
        argv += ["--data-dir", str(cfg["dataDir"])]
    return argv


def make_callback(argv, timeout=_TIMEOUT_SECONDS):
    async def on_admission(**kwargs):
        proc = None
        try:
            payload = {"event": "post_gateway_admission", **{k: kwargs.get(k) for k in (
                "platform", "session_key", "message_id", "text", "source")}}
            data = json.dumps(payload, default=str).encode("utf-8")
            proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            await asyncio.wait_for(proc.communicate(data), timeout)
        except asyncio.CancelledError:
            _kill(proc)
            raise  # the gateway is cancelling this turn; Hermes treats it as "not handled"
        except Exception:
            _kill(proc)  # timeout, missing command, ...: no intent (the login is denied)
            try:
                if proc is not None:
                    await asyncio.wait_for(proc.wait(), 1.0)
            except Exception:
                pass
        return None
    return on_admission


def _kill(proc):
    try:
        if proc is not None and proc.returncode is None:
            proc.kill()
    except Exception:
        pass


def register(ctx):
    try:
        with open(os.path.join(_DIR, "config.json"), encoding="utf-8") as f:
            argv = build_argv(json.load(f))
    except Exception:
        logger.warning("keyflap-intent: config.json missing or invalid; no Keyflap intents are recorded")
        return
    ctx.register_hook("post_gateway_admission", make_callback(argv))
