"""Loads the keyflap-intent plugin from <plugin dir> (with its config.json), registers it on a
fake ctx and fires post_gateway_admission once with the keyword arguments in <kwargs json>,
as Hermes's gateway would. Prints the callback's return value as JSON. Test helper for
agent-hosts.e2e.test.ts; needs no Hermes install.

  python3 -I -B drive_plugin.py <plugin dir> <kwargs json>
"""

import asyncio
import importlib.util
import json
import os
import sys

plugin_dir, kwargs = sys.argv[1], json.loads(sys.argv[2])
spec = importlib.util.spec_from_file_location("keyflap_intent_e2e", os.path.join(plugin_dir, "__init__.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class Ctx:
    hooks = []

    def register_hook(self, name, cb):
        self.hooks.append((name, cb))


ctx = Ctx()
mod.register(ctx)
assert [n for n, _ in ctx.hooks] == ["post_gateway_admission"], ctx.hooks
print(json.dumps(asyncio.run(ctx.hooks[0][1](**kwargs))))
