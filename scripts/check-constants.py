#!/usr/bin/env python3
"""Check every constant in src/sys.rs against the installed Linux UAPI
headers (needs gcc and linux-libc-dev).

    python3 scripts/check-constants.py
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADERS = [
    "stdio.h", "linux/netlink.h", "linux/netfilter.h", "linux/netfilter_arp.h",
    "linux/netfilter/nfnetlink.h", "linux/netfilter/nf_tables.h",
    "linux/netfilter/nfnetlink_log.h", "linux/netfilter/nf_log.h",
    "linux/netfilter/nf_nat.h", "linux/netfilter/nf_conntrack_common.h",
    "linux/netfilter/nfnetlink_cttimeout.h", "linux/netfilter/nfnetlink_queue.h",
    "linux/netfilter/nfnetlink_conntrack.h",
]
# Constants that are not defined in the headers (computed values).
EXPECTED_MISSING = {
    "NFGENMSG_LEN", "NF_CT_STATE_ESTABLISHED_BIT", "NF_CT_STATE_NEW_BIT", "NF_CT_STATE_RELATED_BIT",
}

src = open(os.path.join(ROOT, "src", "sys.rs")).read()
consts = re.findall(r"pub const (\w+): \w+ = ([^;]+);", src)
env = {}
for name, expr in consts:
    e = re.sub(r"(\d)(u32|u16|u8)\b", r"\1", expr.strip()).replace("!(", "~(")
    env[name] = eval(e, {}, env)

with tempfile.TemporaryDirectory() as d:
    names = set(env)
    for _ in range(20):
        prog = "".join(f"#include <{h}>\n" for h in HEADERS) + "int main(){\n"
        prog += "".join(f'printf("{n} %lld\\n",(long long)({n}));\n' for n in sorted(names))
        prog += "return 0;}\n"
        open(os.path.join(d, "c.c"), "w").write(prog)
        r = subprocess.run(["gcc", "-o", os.path.join(d, "c"), os.path.join(d, "c.c")], capture_output=True, text=True)
        if r.returncode == 0:
            break
        bad = set(re.findall(r"[‘'](\w+)[’'] undeclared", r.stderr))
        if not bad:
            sys.exit(r.stderr)
        names -= bad
    out = subprocess.run([os.path.join(d, "c")], capture_output=True, text=True, check=True).stdout

cvals = {l.split()[0]: int(l.split()[1]) for l in out.splitlines()}
mismatch = [(n, env[n], v) for n, v in sorted(cvals.items()) if (env[n] - v) % (1 << 32) != 0]
missing = set(env) - set(cvals) - EXPECTED_MISSING
print(f"checked {len(cvals)} of {len(env)} constants")
if mismatch or missing:
    sys.exit(f"mismatches: {mismatch}\nnot found in headers: {sorted(missing)}")
print("all constants match the kernel headers")
