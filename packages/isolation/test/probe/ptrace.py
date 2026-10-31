"""ptrace(PTRACE_ATTACH) probe, run in the test container as an ordinary uid.

usage: python3 ptrace.py PID...   (prints one JSON object: {"<pid>": "ok" | "<errno name>"})

The key "control" is our own child: attaching to it must work (also under Yama
ptrace_scope=1), which shows the probe itself is capable and a refusal for the broker's
processes comes from the uid boundary.
"""
import ctypes
import errno
import json
import os
import subprocess
import sys
import time

PTRACE_ATTACH = 16
PTRACE_DETACH = 17

libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]


def attach(pid):
    if libc.ptrace(PTRACE_ATTACH, pid, None, None) == -1:
        e = ctypes.get_errno()
        return errno.errorcode.get(e, str(e))
    os.waitpid(pid, 0)
    libc.ptrace(PTRACE_DETACH, pid, None, None)
    return "ok"


out = {}
child = subprocess.Popen(["sleep", "30"])
time.sleep(0.1)
out["control"] = attach(child.pid)
child.kill()
for arg in sys.argv[1:]:
    out[arg] = attach(int(arg))
print(json.dumps(out))
