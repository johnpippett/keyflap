"""Unit tests for the Hermes keyflap-intent plugin (stdlib unittest; run by
packages/cli/test/inv4-hermes-hook.test.ts). A fake ctx stands in for Hermes; the command
is a small Python script that saves its argv and stdin, or a fake create_subprocess_exec."""

import asyncio
import importlib.util
import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_DIR = os.path.join(HERE, "..", "..", "src", "integrations", "hermes", "keyflap-intent")
SECRET = "zebra-umbrella-7781"


def load_plugin(dir_):
    spec = importlib.util.spec_from_file_location(
        "keyflap_intent_under_test", os.path.join(dir_, "__init__.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeCtx:
    def __init__(self):
        self.hooks = []

    def register_hook(self, name, cb):
        self.hooks.append((name, cb))


def payload(text=SECRET):
    return dict(platform="telegram", session_key="agent:main:telegram:dm:1", message_id="42",
                text=text, source={"platform": "telegram", "chat_id": "1", "chat_type": "dm",
                                   "user_id": "1"}, telemetry_schema_version=1)


class PluginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out = os.path.join(self.tmp, "got.json")
        self.script = os.path.join(self.tmp, "fake_keyflap.py")
        with open(self.script, "w") as f:
            f.write("import json, sys\n"
                    "data = sys.stdin.buffer.read()\n"
                    f"open({self.out!r}, 'w').write(json.dumps({{'argv': sys.argv[1:], 'stdin': data.decode()}}))\n"
                    "print('stdout noise ' + data.decode()); sys.stderr.write('stderr noise')\n")
        self.cfg = {"command": [sys.executable, self.script], "agent": "agent-1",
                    "owners": ["telegram:1", "discord:2"], "profile": None, "dataDir": None,
                    "service": False}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def plugin_with(self, cfg):
        d = os.path.join(self.tmp, "plugin")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(PLUGIN_DIR, "__init__.py")) as src, \
                open(os.path.join(d, "__init__.py"), "w") as dst:
            dst.write(src.read())
        if cfg is not None:
            with open(os.path.join(d, "config.json"), "w") as f:
                f.write(cfg if isinstance(cfg, str) else json.dumps(cfg))
        return load_plugin(d)

    def registered(self, cfg):
        ctx = FakeCtx()
        self.plugin_with(cfg).register(ctx)
        return ctx.hooks

    def test_registers_only_post_gateway_admission(self):
        hooks = self.registered(self.cfg)
        self.assertEqual([h[0] for h in hooks], ["post_gateway_admission"])

    def test_forwards_the_hook_arguments_verbatim_and_returns_none(self):
        (_, cb), = self.registered(self.cfg)
        text = f'sign me in "{SECRET}"\n ünïcødé 🔑 \\ </script>'
        self.assertIsNone(asyncio.run(cb(**payload(text))))
        with open(self.out) as f:
            got = json.load(f)
        self.assertEqual(got["argv"], ["hook", "hermes", "--agent", "agent-1",
                                       "--owner", "telegram:1", "--owner", "discord:2"])
        sent = json.loads(got["stdin"])
        self.assertEqual(sent["event"], "post_gateway_admission")
        self.assertEqual(sent["text"], text)
        self.assertEqual(sent["source"]["chat_type"], "dm")
        self.assertNotIn("telemetry_schema_version", sent)

    def test_profile_service_and_data_dir_flags(self):
        p = self.plugin_with(self.cfg)
        argv = p.build_argv({**self.cfg, "profile": "work", "dataDir": "/d"})
        self.assertEqual(argv[-4:], ["--profile", "work", "--data-dir", "/d"])
        argv = p.build_argv({**self.cfg, "service": True, "dataDir": "/d"})
        self.assertEqual(argv[-1], "--service")
        self.assertNotIn("--data-dir", argv)

    def test_child_output_never_reaches_hermes(self):
        seen = {}

        async def fake_exec(*argv, **kw):
            seen.update(kw)
            raise OSError("no such file")
        (_, cb), = self.registered(self.cfg)
        with mock.patch("asyncio.create_subprocess_exec", fake_exec):
            self.assertIsNone(asyncio.run(cb(**payload())))
        self.assertEqual(seen["stdout"], asyncio.subprocess.DEVNULL)
        self.assertEqual(seen["stderr"], asyncio.subprocess.DEVNULL)
        self.assertEqual(seen["stdin"], asyncio.subprocess.PIPE)

    def test_errors_are_swallowed_and_logged_without_text(self):
        with self.assertLogs(level=logging.DEBUG) as logs:
            logging.getLogger("x").debug("marker")
            (_, cb), = self.registered({**self.cfg, "command": ["/nonexistent/keyflap"]})
            self.assertIsNone(asyncio.run(cb(**payload())))
            self.assertIsNone(asyncio.run(cb(**{**payload(), "source": object()})))
            self.assertIsNone(asyncio.run(cb()))
        self.assertNotIn(SECRET, "\n".join(logs.output))

    def test_a_hung_command_is_killed_after_the_timeout(self):
        hang = os.path.join(self.tmp, "hang.py")
        with open(hang, "w") as f:
            f.write("import time\ntime.sleep(30)\n")
        p = self.plugin_with(self.cfg)
        cb = p.make_callback([sys.executable, hang], timeout=0.5)
        loop = asyncio.new_event_loop()
        try:
            started = loop.time()
            self.assertIsNone(loop.run_until_complete(cb(**payload())))
            self.assertLess(loop.time() - started, 5)
        finally:
            loop.close()

    def test_cancellation_propagates(self):
        hang = os.path.join(self.tmp, "hang.py")
        with open(hang, "w") as f:
            f.write("import time\ntime.sleep(30)\n")
        cb = self.plugin_with(self.cfg).make_callback([sys.executable, hang], timeout=20)

        async def main():
            t = asyncio.ensure_future(cb(**payload()))
            await asyncio.sleep(0.3)
            t.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await t
        asyncio.run(main())

    def test_bad_or_missing_config_registers_nothing(self):
        for cfg in (None, "not json", {"agent": "a", "owners": ["telegram:1"]},
                    {**self.cfg, "command": ["relative/keyflap"]}, {**self.cfg, "owners": []},
                    {**self.cfg, "agent": ""}, {**self.cfg, "owners": "telegram:1"}):
            with self.assertLogs(level=logging.WARNING) as logs:
                self.assertEqual(self.registered(cfg), [])
            self.assertIn("no Keyflap intents are recorded", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
