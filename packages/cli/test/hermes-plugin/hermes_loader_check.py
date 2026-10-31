"""Loads the keyflap-intent plugin through a real Hermes checkout's plugin loader and fires
``post_gateway_admission`` through Hermes's own ``run_post_admission_hook`` with a real
``SessionSource``. Hermes is only imported: no gateway, no platforms, no model.

Usage (run by inv4-hermes-hook.test.ts when KEYFLAP_TEST_HERMES_SRC is set):
  HERMES_HOME=<empty temp dir> HERMES_SITE_PACKAGES=<its venv site-packages> python3 -I -B hermes_loader_check.py <hermes checkout> <plugin dir> <config.json text>
Prints one JSON line: {"hooks": [...], "handled": bool, "results": [...]}.
The HERMES_HOME must be a throwaway directory: the loader reads config.yaml from it.
"""

import asyncio
import json
import os
import shutil
import sys
import types

hermes_src, plugin_src, config_text = sys.argv[1], sys.argv[2], sys.argv[3]
home = os.environ["HERMES_HOME"]
if os.path.realpath(home) == os.path.realpath(os.path.expanduser("~/.hermes")):
    sys.exit("refusing to use the real ~/.hermes")
sys.dont_write_bytecode = True
sys.path.insert(0, hermes_src)
# Hermes's dependencies (a site-packages dir of its install), added read-only: Hermes's own
# activation takes install locks, which would write to the owner's ~/.hermes.
for site_dir in filter(None, os.environ.get("HERMES_SITE_PACKAGES", "").split(os.pathsep)):
    sys.path.append(site_dir)

dest = os.path.join(home, "plugins", "keyflap-intent")
shutil.copytree(plugin_src, dest, ignore=shutil.ignore_patterns("__pycache__", "config.json"))
with open(os.path.join(dest, "config.json"), "w") as f:
    f.write(config_text)
with open(os.path.join(home, "config.yaml"), "w") as f:
    f.write("plugins:\n  enabled:\n    - keyflap-intent\n")

from hermes_cli import plugins  # noqa: E402
from gateway.config import Platform  # noqa: E402
from gateway.session import SessionSource  # noqa: E402
from gateway.run_inbound_consumer import run_post_admission_hook  # noqa: E402

plugins.discover_plugins(force=True)
hooks = sorted(name for name, cbs in plugins.get_plugin_manager()._hooks.items() if cbs)

source = SessionSource(platform=Platform(os.environ.get("CHECK_PLATFORM", "telegram")),
                       chat_id="1001", chat_type=os.environ.get("CHECK_CHAT_TYPE", "dm"),
                       user_id=os.environ.get("CHECK_USER_ID", "1001"), user_name="owner")
event = types.SimpleNamespace(message_id=os.environ.get("CHECK_MESSAGE_ID", "42"),
                              text=os.environ["CHECK_TEXT"])
runner = types.SimpleNamespace(config=types.SimpleNamespace(multiplex_profiles=False))
handled, reply = asyncio.run(run_post_admission_hook(runner, event, source, "agent:main:telegram:dm:1001"))
print(json.dumps({"hooks": hooks, "handled": handled, "reply": reply}))
