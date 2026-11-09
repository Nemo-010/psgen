#!/usr/bin/env python3
"""Invariant checks for psgen. Run by tests/smoke.sh.

The agent-side checks run as the invoking user. Root-side checks run through
sudo when passwordless sudo is available, and skip otherwise.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(os.environ.get("PSGEN_BIN", ROOT / "target" / "release" / "psgen"))


def cargo_version() -> str:
    for line in (ROOT / "Cargo.toml").read_text().splitlines():
        if line.startswith('version = "'):
            return line.split('"')[1]
    raise SystemExit("no version in Cargo.toml")


VERSION = cargo_version()


def elf_machine(path: Path) -> int | None:
    """e_machine from an ELF header, or None for a non-ELF file."""
    try:
        with open(path, "rb") as f:
            head = f.read(20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    # ELF data encoding: 1 = little endian, 2 = big endian.
    endian = {1: "little", 2: "big"}.get(head[5])
    if endian is None:
        return None
    return int.from_bytes(head[18:20], endian)


# uname machine -> ELF e_machine. Only the targets this project ships matter.
ELF_MACHINES = {
    "x86_64": 62,
    "aarch64": 183,
    "armv7l": 40,
    "armv8l": 40,
    "riscv64": 243,
    "loongarch64": 258,
    "ppc64le": 21,
    "i686": 3,
    "i386": 3,
}


def emulated() -> bool:
    """True when the binary runs under qemu-user, not natively.

    The release job smokes the cross binaries under binfmt, where the kernel
    hands the process to `qemu-<arch>`, and `/proc/PID/cmdline` then shows the
    emulator and the binary rather than the argv psgen set. That is the
    emulator's own overhead, not a rendering difference, so the checks that
    compare argv byte for byte are skipped there instead of failing.
    """
    want = ELF_MACHINES.get(os.uname().machine)
    got = elf_machine(BIN)
    if want is None or got is None:
        return False
    return want != got
HEADER = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
PS_RE = re.compile(
    r"^(?P<user>\S+)\s+(?P<pid>\d+)\s+(?P<cpu>\d+\.\d)\s+"
    r"(?P<mem>\d+\.\d)\s+(?P<vsz>\d+)\s+(?P<rss>\d+)\s+"
    r"(?P<tty>\S+)\s+(?P<stat>[RSDZT][sl+]*)\s+"
    r"(?P<start>\d\d:\d\d|[A-Z][a-z]{2}\s?\d+|\d{4})\s+"
    r"(?P<time>\d+:\d\d(?::\d\d)?)\s+(?P<cmd>.*)$"
)
GREY = ("botnet", "bruteforce", "cryptomin", "xmrig", "memdump", "rkhunter",
        "ganache", "simcity", "rootkit", "stratum")


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def run(args, root=False, timeout=180, check=True, env=None):
    cmd = (["sudo", "-n", str(BIN)] if root else [str(BIN)]) + [str(a) for a in args]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        fail(f"timeout: {' '.join(cmd)}")
    if check and p.returncode != 0:
        fail(f"command failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr}")
    return p


def can_root() -> bool:
    try:
        p = subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10)
        return p.returncode == 0
    except Exception:
        return False


def read_pids(path, root=False):
    if root:
        p = subprocess.run(["sudo", "-n", "cat", str(path)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=30)
        text = p.stdout
    else:
        text = Path(path).read_text()
    pids = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            pids.append(int(line.split("\t", 1)[0]))
        except ValueError:
            continue
    return pids


def exe_known() -> bool:
    """False when /proc/PID/exe would describe the emulator, not psgen."""
    return not emulated()


def read_exe(pid, root=False):
    if root:
        p = subprocess.run(["sudo", "-n", "readlink", f"/proc/{pid}/exe"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=30)
        return p.stdout.strip()
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def cmdline(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode().strip()
    except OSError:
        return ""


def sizes(pid):
    out = {"vsz": 0, "rss": 0}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmSize:"):
                out["vsz"] = int(line.split()[1])
            elif line.startswith("VmRSS:"):
                out["rss"] = int(line.split()[1])
    except OSError:
        pass
    return out


def ps_rows():
    p = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True, timeout=30)
    rows = {}
    for line in p.stdout.splitlines():
        m = PS_RE.match(line)
        if not m:
            continue
        rows[int(m.group("pid"))] = {
            "user": m.group("user"),
            "pid": int(m.group("pid")),
            "cpu": float(m.group("cpu")),
            "mem": float(m.group("mem")),
            "vsz": int(m.group("vsz")),
            "rss": int(m.group("rss")),
            "tty": m.group("tty"),
            "stat": m.group("stat"),
            "start": m.group("start"),
            "time": m.group("time"),
            "cmd": m.group("cmd").strip(),
        }
    return rows


def mem_total():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1])
    return 0


def cgroup_limit_kb():
    def limit_kb(path):
        try:
            value = Path(path).read_text().strip()
        except OSError:
            return None
        if not value or value == "max":
            return 0
        try:
            n = int(value)
        except ValueError:
            return None
        if n >= 1 << 60:
            return 0
        return n // 1024

    try:
        cgroup = Path("/proc/self/cgroup").read_text().splitlines()
    except OSError:
        cgroup = None
    if cgroup is not None:
        for line in cgroup:
            if line.startswith("0::"):
                kb = limit_kb(f"/sys/fs/cgroup{line[3:]}/memory.max")
                if kb is not None:
                    return kb
            elif ":memory:" in line:
                path = line.rsplit(":", 1)[-1]
                kb = limit_kb(f"/sys/fs/cgroup/memory{path}/memory.limit_in_bytes")
                if kb is not None:
                    return kb
    for path in ("/sys/fs/cgroup/memory.max",
                 "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        kb = limit_kb(path)
        if kb:
            return kb
    return 0


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def check_cli():
    if run(["--version"]).stdout.strip() != f"psgen {VERSION}":
        fail("wrong version")
    help_text = run(["--help"]).stdout
    if "psgen inject" not in help_text:
        fail("help lacks inject")
    for sub in ("doctor", "log", "load"):
        if sub not in help_text:
            fail(f"help lacks {sub}")
    for args, want in [
        (["table", "-n", "5", "-s", "1"], 5),
        (["table", "-n", "5", "-s", "1", "-p", "desktop"], 5),
        (["table", "-n", "5", "-s", "1", "-f", "dev"], 5),
        (["table", "-n", "5", "-s", "1", "--utc-offset", "60"], 5),
        (["table", "-n", "5", "-s", "1", "--local"], 5),
    ]:
        rows = [l for l in run(args).stdout.splitlines() if not l.startswith("USER ")]
        if len(rows) != want:
            fail(f"{args} returned {len(rows)} rows")
    if run(["table", "-p", "bogus"], check=False).returncode != 2:
        fail("bad profile did not exit 2")
    if run(["table", "-f", "bogus"], check=False).returncode != 2:
        fail("bad family did not exit 2")
    a = run(["list", "-n", "10", "-s", "7", "--sort"]).stdout.splitlines()
    if a != sorted(a):
        fail("--sort did not sort")
    b = run(["list", "-n", "5", "-s", "7", "--no-sort"]).stdout.splitlines()
    if b[0] != "/sbin/init":
        fail("--no-sort did not keep corpus order")
    u = run(["list", "-n", "10", "-s", "7", "--uniq"]).stdout.splitlines()
    if len(set(u)) != len(u):
        fail("--uniq produced duplicates")
    n = run(["list", "-n", "10", "-s", "7", "--no-uniq"]).stdout.splitlines()
    if len(n) != 10:
        fail("--no-uniq wrong count")
    if run(["inject", "-n", "0", "--dry-run"]).stdout.count("\n") != 12:
        fail("inject -n 0 did not default to 12")
    if len(run(["table", "-n", "0"]).stdout.splitlines()) != 31:
        fail("table -n 0 did not default to 30 rows")
    a = run(["table", "-n", "5", "-s", "42"]).stdout
    b = run(["table", "-n", "5", "-s", "42"]).stdout
    if a != b:
        fail("seed is not deterministic")


def check_list():
    cmds = [l for l in run(["list", "-n", "0", "-s", "1"]).stdout.splitlines() if l]
    if len(cmds) < 180:
        fail(f"list returned only {len(cmds)} commands")
    for c in cmds:
        if "{" in c or "}" in c:
            fail(f"unexpanded placeholder in {c!r}")
        if any(ord(ch) < 32 for ch in c):
            fail(f"control byte in {c!r}")
        low = c.lower()
        for term in GREY:
            if term in low:
                fail(f"grey term {term!r} in {c!r}")


def check_table_rows(text, want, mem):
    lines = text.splitlines()
    if not lines or lines[0] != HEADER:
        fail("table header does not match procps")
    rows = []
    for line in lines[1:]:
        m = PS_RE.match(line)
        if not m:
            continue
        rows.append({
            "user": m.group("user"), "pid": int(m.group("pid")),
            "cpu": float(m.group("cpu")), "mem": float(m.group("mem")),
            "vsz": int(m.group("vsz")), "rss": int(m.group("rss")),
            "tty": m.group("tty"), "stat": m.group("stat"),
            "start": m.group("start"), "time": m.group("time"),
            "cmd": m.group("cmd"),
        })
    if len(rows) != want:
        fail(f"table returned {len(rows)} rows, wanted {want}")
    if rows[0]["pid"] != 1 or rows[0]["cmd"] != "/sbin/init":
        fail("PID 1 is not /sbin/init")
    if len({r["pid"] for r in rows}) != len(rows):
        fail("duplicate PIDs")
    for r in rows:
        if r["vsz"] < r["rss"]:
            fail(f"pid {r['pid']} has VSZ < RSS")
        if mem and abs(r["mem"] - r["rss"] * 100.0 / mem) > 0.11:
            fail(f"pid {r['pid']} has wrong %MEM")
        if not re.fullmatch(r"[RSDZT][sl+]*", r["stat"]):
            fail(f"pid {r['pid']} has bad STAT {r['stat']}")
        if not re.fullmatch(r"\d+:\d\d(:\d\d)?", r["time"]):
            fail(f"pid {r['pid']} has bad TIME {r['time']}")
        if not re.fullmatch(r"\d\d:\d\d|[A-Z][a-z]{2} ?\d+|\d{4}", r["start"]):
            fail(f"pid {r['pid']} has bad START {r['start']}")
        if not re.fullmatch(r"\?|pts/\d+|tty\d+", r["tty"]):
            fail(f"pid {r['pid']} has bad TTY {r['tty']}")
        if len(r["user"]) > 8:
            fail(f"pid {r['pid']} has a user wider than 8")
        if "{" in r["cmd"] or "}" in r["cmd"]:
            fail(f"pid {r['pid']} has an unexpanded placeholder")
    for prefix in ("/sbin/init", "sshd: /usr/sbin/sshd -D [listener]",
                   "nginx: master process"):
        if sum(1 for r in rows if r["cmd"].startswith(prefix)) > 1:
            fail(f"duplicate single-instance daemon {prefix}")
    if sum(1 for r in rows if r["cmd"] == "/usr/bin/containerd") > 1:
        fail("duplicate single-instance daemon /usr/bin/containerd")


def check_table():
    check_table_rows(run(["table", "-n", "50", "-s", "1"]).stdout, 50, mem_total())
    check_table_rows(run(["table", "-n", "5001", "-s", "1"]).stdout, 5000, mem_total())


def proc_cmdline(pid):
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    return " ".join(p.decode(errors="replace") for p in raw.split(b"\0") if p)


def check_live():
    text = run(["table", "--live"]).stdout
    lines = text.splitlines()
    if not lines or lines[0] != HEADER:
        fail("live table header does not match procps")
    if len(lines) < 6:
        fail("live table has too few rows")
    try:
        pid1 = proc_cmdline(1)
    except OSError:
        pid1 = None
    rows = [l for l in lines[1:] if len(l.split()) > 1 and l.split()[1] == "1"]
    if not rows:
        fail("live table lacks PID 1")
    if pid1 is not None and not any(l.split(None, 10)[-1] == pid1 for l in rows):
        fail(f"live table PID 1 does not match /proc/1/cmdline ({pid1!r})")


def check_corpus():
    if len([l for l in run(["corpus"]).stdout.splitlines() if l]) < 180:
        fail("corpus too small")
    out = run(["check"]).stdout
    if "deny hits: 0" not in out or "placeholders: 0" not in out:
        fail("check reported corpus problems")
    run(["check", "--binaries"])


def check_unit():
    out = run(["unit"]).stdout
    if "ExecStart=" not in out or "psgen" not in out or "ExecStop=" not in out:
        fail("unit output is incomplete")
    if "WantedBy=multi-user.target" not in out:
        fail("unit output lacks install target")
    run(["unit", "--pidfile", "/run/test-psgen.pid", "-n", "9", "-s", "3"])
    spaced = run(["unit", "--pidfile", "/run/a b.pid"]).stdout
    if 'ExecStart=' not in spaced or '"/run/a b.pid"' not in spaced:
        fail("unit did not quote a path that contains a space")
    with tempfile.TemporaryDirectory(prefix="psgen-unit-") as tmp:
        spaced_bin = Path(tmp) / "bin dir" / "psgen"
        spaced_bin.parent.mkdir()
        shutil.copy2(BIN, spaced_bin)
        p = subprocess.run([str(spaced_bin), "unit"], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, timeout=180)
        if p.returncode != 0:
            fail(f"unit from a spaced path failed: {p.stderr}")
        if f'ExecStart="{spaced_bin}"' not in p.stdout:
            fail("unit did not quote the executable path")
        # ExecStop carries systemd's failure-tolerant `-` prefix, so the
        # quoted executable follows it rather than the directive.
        if f'ExecStop=-"{spaced_bin}"' not in p.stdout:
            fail("unit did not quote the stop executable path")


def inject_and_check(args, tmp, want, root=False, read_root=None,
                     expect_failure=False):
    pidfile = Path(tmp) / ("pids-" + str(int(time.time() * 1000)))
    args = list(args) + ["--pidfile", str(pidfile)]
    p = run(args, root=root, check=not expect_failure)
    if read_root is None:
        read_root = root
    pids = read_pids(pidfile, root=read_root)
    if len(pids) != want:
        fail(f"{args} spawned {len(pids)}, wanted {want}: {p.stdout} {p.stderr}")
    return pidfile, pids, p


def stop_pidfile(path, root=False):
    out = ""
    if Path(path).exists():
        out = run(["stop", "--pidfile", str(path)], root=root, check=False).stdout
    try:
        Path(path).unlink()
    except OSError:
        pass
    return out


def check_injection():
    under_emulation = emulated()
    if under_emulation:
        print("SKIP: argv checks compare loosely under qemu-user", file=sys.stderr)
    with tempfile.TemporaryDirectory(prefix="psgen-test-") as tmp:
        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "4", "-s", "9", "--no-user", "--no-mem",
             "--no-tty", "--no-threads"], tmp, 4)
        dry = run(["inject", "-n", "4", "-s", "9", "--no-user", "--no-mem",
                   "--no-tty", "--no-threads", "--dry-run"]).stdout
        wanted = {l.split("\t", 1)[1].strip() for l in dry.splitlines() if "\t" in l}
        time.sleep(0.4)
        rows = ps_rows()
        for pid in pids:
            r = rows.get(pid)
            raw = cmdline(pid)
            if not r:
                fail(f"pid {pid} missing from ps aux")
            # A `/proc/PID/cmdline` read of a stub that exited in the window is
            # empty, and `ps` shows the bracketed comm for a zombie. That is the
            # same "already dead" case `alive()` exists for; the row was planned,
            # it just is not observable any more.
            if not alive(pid) and (not raw or r["cmd"].endswith(" <defunct>")):
                continue
            if not under_emulation:
                if r["cmd"].removesuffix(" <defunct>") != raw:
                    fail(f"pid {pid} ps cmd {r['cmd']!r} != cmdline {raw!r}")
                if raw not in wanted:
                    fail(f"pid {pid} cmdline {raw!r} not planned")
            elif raw not in wanted and not any(w in raw for w in wanted):
                # qemu-user puts `qemu-<arch> <binary>` in front of the argv, so
                # the planned command line is a suffix rather than the whole.
                fail(f"pid {pid} cmdline {raw!r} does not contain a planned command")
            if r["tty"] != "?":
                fail(f"pid {pid} --no-tty still has {r['tty']}")
            if not under_emulation:
                # qemu-user adds threads of its own and carries its own RSS, so
                # neither number is about psgen there.
                if "l" in r["stat"]:
                    fail(f"pid {pid} --no-threads still has l")
                if r["rss"] > 4000:
                    fail(f"pid {pid} --no-mem has RSS {r['rss']}")
        stop_pidfile(pidfile)

        if not can_root():
            p = run(["inject", "-n", "2", "--no-mem", "--no-tty", "--no-threads",
                     "--pidfile", str(Path(tmp) / "warn.pid")])
            if "running as" not in p.stderr:
                fail("non-root --user did not warn about the fallback")
            stop_pidfile(Path(tmp) / "warn.pid")

        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "desk", "-n", "30", "-s", "5", "--no-user",
             "--no-mem"], tmp, 30)
        time.sleep(0.4)
        rows = ps_rows()
        if can_pty() and not any(rows.get(p) and rows[p]["tty"].startswith("pts/")
                                 for p in pids):
            fail("no injected process acquired a pty")
        if not under_emulation and not any(
                rows.get(p) and "l" in rows[p]["stat"] for p in pids):
            fail("no injected process showed the threaded stat flag")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "3", "-s", "77", "--no-user"], tmp, 3)
        time.sleep(0.4)
        rows = ps_rows()
        if not emulated():
            if not any(rows.get(p) and rows[p]["vsz"] > 50000 for p in pids):
                fail("no injected process had a padded VSZ")
            if not any(rows.get(p) and rows[p]["rss"] > 1000 for p in pids):
                fail("no injected process had a padded RSS")
        stop_pidfile(pidfile)

        # --verify compares real VSZ/RSS with the plan. qemu-user adds its own
        # mappings and resident pages to both, so the comparison is about the
        # emulator there and the exit code is not psgen's.
        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "16", "-s", "42", "--no-user", "--verify"],
            tmp, 16, expect_failure=emulated())
        if not emulated():
            m = re.search(r"(\d+) outside 128 kB", p.stdout)
            if m and int(m.group(1)) != 0:
                fail(f"{m.group(1)} stubs outside 128 kB")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "web", "-n", "12", "-s", "42", "--no-user",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 12)
        time.sleep(0.4)
        ps = subprocess.run(
            ["ps", "-o", "pid=,ppid=,args=", "-p", ",".join(str(p) for p in pids)],
            stdout=subprocess.PIPE, text=True, timeout=30)
        rows = []
        for line in ps.stdout.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3:
                rows.append((int(parts[0]), int(parts[1]), parts[2]))
        # Under qemu-user `ps args` starts with `qemu-<arch> <binary>`, so the
        # template command is a suffix of the row rather than its start.
        def starts(args, prefixes):
            if emulated():
                return any(p in args for p in prefixes)
            return args.startswith(prefixes)

        masters = {pid for pid, ppid, args in rows
                   if starts(args, ("apache2 -DFOREGROUND", "nginx: master",
                                    "php-fpm: master", "gunicorn: master"))}
        workers = [(pid, ppid, args) for pid, ppid, args in rows
                   if starts(args, ("apache2 -k start", "nginx: worker",
                                    "php-fpm: pool", "gunicorn: worker"))]
        if not masters or not workers:
            fail("web family did not produce masters and workers")
        for pid, ppid, args in workers:
            if ppid not in masters:
                fail(f"worker {pid} ({args}) has PPID {ppid}, not a master")
        if shutil.which("pstree"):
            for master in masters:
                tree = subprocess.run(["pstree", "-p", str(master)],
                                      stdout=subprocess.PIPE, text=True, timeout=30).stdout
                for pid, ppid, _ in workers:
                    if ppid == master and f"({pid})" not in tree:
                        fail(f"pstree does not show worker {pid} under master {master}")
        stop_pidfile(pidfile)

        mounts_before = Path("/proc/self/mountinfo").read_text()
        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "web", "-n", "6", "-s", "42", "--no-user",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 6)
        mounts_after = Path("/proc/self/mountinfo").read_text()
        if mounts_after != mounts_before:
            fail("inject leaked a mount into the caller's mount namespace")
        expected = {
            "apache2": "/usr/sbin/apache2",
            "nginx:": "/usr/sbin/nginx",
            "php-fpm:": "/usr/sbin/php-fpm",
            "gunicorn:": "/usr/local/bin/gunicorn",
        }
        checked = 0
        for pid in pids:
            raw = cmdline(pid)
            if not exe_known():
                # qemu-user makes /proc/PID/exe the emulator, so the comparison
                # is not about psgen at all.
                checked += 1
                continue
            got = read_exe(pid)
            if Path(got).resolve() == BIN.resolve():
                checked += 1
                continue
            if got.endswith("/psgen-stub"):
                checked += 1
                continue
            for prefix, exe in expected.items():
                if raw.startswith(prefix):
                    if Path(got).resolve() != Path(exe).resolve():
                        fail(f"pid {pid} exe {got!r} != {exe!r}")
                    checked += 1
                    break
        if checked == 0:
            fail("no exe-spoofed web rows found")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "4", "-s", "9", "--no-user", "--no-exe",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 4)
        if exe_known():
            for pid in pids:
                if Path(read_exe(pid)).resolve() != BIN.resolve():
                    fail(f"pid {pid} --no-exe exe is {read_exe(pid)}")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "db", "-n", "6", "-s", "1", "--no-user",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 6)
        for pid in pids:
            if not exe_known():
                continue
            exe = read_exe(pid)
            if Path(exe).resolve() == BIN.resolve():
                continue
            # A host that has the template binary binds it; the documented
            # skip applies to paths that do not exist under /usr/lib.
            if Path(exe).exists():
                continue
            fail(f"pid {pid} /usr/lib row exe is {exe}, expected the documented skip")
        stop_pidfile(pidfile)

        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "4", "-s", "9", "--no-user", "--no-mem",
             "--no-tty", "--no-threads", "--table"], tmp, 4)
        lines = p.stdout.splitlines()
        if not lines or lines[0] != HEADER:
            fail("inject --table did not print the header first")
        if len(lines) != 5:
            fail(f"inject --table printed {len(lines)} lines")
        stop_pidfile(pidfile)

        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "16", "-s", "42", "--no-user", "--mem-cap", "64",
             "--no-tty", "--no-threads"], tmp, 16)
        time.sleep(0.4)
        # The cap is at the 4 MiB-per-stub floor. A stub's own base RSS can
        # exceed the floor; allow 128 KiB per stub for the base image. Under
        # qemu-user the resident set is the emulator's, so the number is not
        # about --mem-cap at all.
        if not emulated():
            total = sum(sizes(p)["rss"] for p in pids)
            if total > 64 * 1024 + 16 * 128:
                fail(f"--mem-cap 64 reported {total} kB")
        if "at least 64 MiB" not in p.stderr:
            fail("--mem-cap floor warning missing")
        stop_pidfile(pidfile)
        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "16", "-s", "42", "--no-user", "--phys-cap", "64",
             "--no-tty", "--no-threads"], tmp, 16)
        if "scaled to fit the physical budget" not in p.stdout:
            fail("--phys-cap did not report scaling")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--duration", "1"], tmp, 2)
        time.sleep(2.2)
        for pid in pids:
            if alive(pid):
                fail(f"pid {pid} survived --duration 1")
        stop_pidfile(pidfile)
        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--wait", "--duration", "1"], tmp, 2)
        for pid in pids:
            if alive(pid):
                fail(f"pid {pid} survived --wait --duration 1")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "dev", "-n", "8", "--no-user", "--busy",
             "--duration", "2", "--no-mem", "--no-tty", "--no-threads"],
            tmp, 8)
        start = {p: cpu_ticks(p) for p in pids}
        time.sleep(1.0)
        busy = 0
        for p in pids:
            now = cpu_ticks(p)
            if now is not None and start.get(p) is not None and now > start[p]:
                busy += 1
        if busy == 0:
            fail("--busy produced no CPU time")
        time.sleep(2.2)
        for p in pids:
            if alive(p):
                fail(f"--busy --duration 2 pid {p} survived")
        stop_pidfile(pidfile)


def check_stop():
    with tempfile.TemporaryDirectory(prefix="psgen-stop-") as tmp:
        me = os.getpid()
        p = Path(tmp) / "stale.pid"
        p.write_text(f"# psgen 0.0.1 boot {boot_id()}\n{me}\t0\ttest\n")
        out = run(["stop", "--pidfile", str(p)]).stdout
        if "skipped 1" not in out:
            fail("stop did not skip a stale starttime")
        os.kill(me, 0)
        p.write_text("# psgen 0.0.1 boot 00000000-0000-0000-0000-000000000000\n"
                     f"{me}\t0\ttest\n")
        if run(["stop", "--pidfile", str(p)], check=False).returncode == 0:
            fail("stop accepted a pidfile from another boot")
        p.write_text(f"{me}\n")
        out = run(["stop", "--pidfile", str(p)]).stdout
        if "skipped 1" not in out:
            fail("stop did not skip a foreign pid")
        p.write_text(f"# psgen 0.0.1 boot {boot_id()}\n999999\t0\ttest\n")
        out = run(["stop", "--pidfile", str(p), "--force"]).stdout
        if "stopped 0" not in out:
            fail("stop --force on a missing pid was not a no-op")
        p.write_text("1\n")
        out = run(["stop", "--pidfile", str(p), "--force"]).stdout
        if "skipped 1" not in out:
            fail("stop --force did not skip PID 1")
        victim = Path(tmp) / "victim"
        victim.mkdir()
        p.write_text(f"# psgen 0.0.1 boot {boot_id()}\n# temp {victim}\n")
        run(["stop", "--pidfile", str(p)])
        if not victim.exists():
            fail("stop removed a temp dir outside the per-run pattern")
        pf = Path(tmp) / "temp.pid"
        run(["inject", "-n", "4", "-s", "9", "--no-user", "--no-mem",
             "--no-tty", "--no-threads", "--disk", "1", "--pidfile", str(pf)])
        temps = [l[len("# temp "):] for l in pf.read_text().splitlines()
                 if l.startswith("# temp ")]
        if not temps:
            fail("pidfile did not record the temp dirs")
        stop_pidfile(pf)
        for t in temps:
            if Path(t).exists():
                fail(f"stop left temp dir {t}")
        if run(["stop"], check=False).returncode != 2:
            fail("stop without --pidfile did not exit 2")


def check_root():
    with tempfile.TemporaryDirectory(prefix="psgen-root-") as tmp:
        mounts_before = Path("/proc/self/mountinfo").read_text()
        # Seed 1 selects rows whose exe paths are spoofable on this host. The
        # documented /usr/lib skip is covered separately below.
        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "-s", "1", "--no-user", "--no-mem",
             "--no-tty", "--no-threads"], tmp, 2, root=True)
        time.sleep(0.4)
        mounts_after = Path("/proc/self/mountinfo").read_text()
        if mounts_after != mounts_before:
            fail("root inject leaked a mount into the caller's mount namespace")
        if exe_known():
            for p in pids:
                exe = read_exe(p, root=True)
                if not exe or Path(exe).resolve() == BIN.resolve():
                    fail(f"root exe spoof did not run for pid {p}")
        stop_pidfile(pidfile, root=True)

        has_www = subprocess.run(["getent", "passwd", "www-data"],
                                 stdout=subprocess.DEVNULL).returncode == 0
        pidfile, pids, _ = inject_and_check(
            ["inject", "-f", "web", "-n", "12", "-s", "42", "--user",
             "--no-exe", "--no-mem", "--no-tty", "--no-threads"],
            tmp, 12, root=True)
        time.sleep(0.4)
        rows = ps_rows()
        # Under qemu-user the row starts with the emulator; match the template
        # anywhere it appears.
        def is_worker(cmd):
            if emulated():
                return any(k in cmd for k in
                           ("apache2 -k start", "php-fpm: pool", "nginx: worker"))
            return cmd.startswith(("apache2 -k start", "php-fpm: pool",
                                   "nginx: worker"))

        workers = [p for p in pids if rows.get(p) and is_worker(rows[p]["cmd"])]
        if not workers:
            fail("root run produced no service workers")
        if has_www:
            for p in workers:
                if rows[p]["user"] != "www-data":
                    fail(f"worker {p} runs as {rows[p]['user']}, not www-data")
            for p in pids:
                cmd = rows[p]["cmd"] if rows.get(p) else ""
                master = ("apache2 -DFOREGROUND" in cmd or "php-fpm: master" in cmd)                     if emulated() else cmd.startswith(("apache2 -DFOREGROUND",
                                                       "php-fpm: master"))
                if master and rows[p]["user"] != "root":
                    fail(f"master {p} runs as {rows[p]['user']}, not root")
        if exe_known():
            for p in pids:
                if Path(read_exe(p, root=True)).resolve() != BIN.resolve():
                    fail(f"root --no-exe pid {p} exe is not psgen")
        stop_pidfile(pidfile, root=True)

        before = subprocess.run(["getent", "passwd", "haproxy"],
                                stdout=subprocess.DEVNULL).returncode == 0
        try:
            pidfile, pids, p = inject_and_check(
                ["inject", "-f", "web", "-n", "6", "-s", "5", "--user",
                 "--create-users", "--no-exe", "--no-mem", "--no-tty",
                 "--no-threads"], tmp, 6, root=True)
            if not before and "created users: haproxy" not in p.stderr:
                fail("--create-users did not report haproxy")
            time.sleep(0.4)
            rows = ps_rows()
            if not any(rows.get(p) and rows[p]["user"] == "haproxy" for p in pids):
                fail("--create-users stub did not run as haproxy")
            stop_pidfile(pidfile, root=True)
        finally:
            if not before:
                subprocess.run(["sudo", "-n", "userdel", "haproxy"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["sudo", "-n", "groupdel", "haproxy"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        pidfile, pids, p = inject_and_check(
            ["inject", "--elevate", "-n", "2", "--no-user", "--no-exe",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 2,
            root=False, read_root=True)
        if exe_known():
            for p in pids:
                exe = read_exe(p, root=True)
                if exe and Path(exe).resolve() != BIN.resolve():
                    fail(f"--elevate pid {p} exe is not psgen")

        p = run(["inject", "--elevate", "-n", "1", "--pidfile", "/proc/1/foo"],
                check=False)
        if p.returncode != 2:
            fail(f"--elevate failure path exited {p.returncode}, wanted 2")
        stop_pidfile(pidfile, root=True)


def check_counts():
    n = len([l for l in run(["list", "-n", "2001", "-s", "1"]).stdout.splitlines() if l])
    if n != 2000:
        fail(f"list -n 2001 returned {n}")
    if "capped at 2000" not in run(["list", "-n", "2001", "-s", "1"], check=False).stderr:
        fail("list did not warn about the cap")
    n = len(run(["table", "-n", "5001", "-s", "1"]).stdout.splitlines())
    if n != 5001:
        fail(f"table -n 5001 returned {n} lines")
    if "capped at 5000" not in run(["table", "-n", "5001", "-s", "1"], check=False).stderr:
        fail("table did not warn about the cap")
    pidfile = Path(tempfile.mkstemp(prefix="psgen-500-")[1])
    try:
        p = run(["inject", "-n", "501", "--no-user", "--no-exe", "--no-mem",
                 "--no-tty", "--no-threads", "--duration", "1",
                 "--pidfile", str(pidfile)])
        if "capped at 500" not in p.stderr:
            fail("inject did not warn about the cap")
        pids = read_pids(pidfile)
        if len(pids) != 500:
            fail(f"inject -n 501 spawned {len(pids)}")
        time.sleep(2.0)
    finally:
        stop_pidfile(pidfile)


HZ = os.sysconf("SC_CLK_TCK")


def cpu_ticks(pid):
    """Cumulative user+system CPU time in clock ticks, or None if gone."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    # The comm field is parenthesised and may contain spaces, so split after
    # the last ')'. The remaining fields start at state (field 3).
    parts = text.rsplit(")", 1)[1].split()
    try:
        return int(parts[11]) + int(parts[12])
    except (IndexError, ValueError):
        return None


def cpu_percent(pid, seconds):
    a = cpu_ticks(pid)
    if a is None:
        return None
    time.sleep(seconds)
    b = cpu_ticks(pid)
    if b is None:
        return None
    return (b - a) * 100.0 / (HZ * seconds)


def check_doctor():
    p = run(["doctor"])
    out = p.stdout
    if "summary" not in out or "capabilities available" not in out:
        fail("doctor lacks the summary line")
    for name in ("proc_exe", "fork", "prctl_name"):
        line = next((l for l in out.splitlines() if l.startswith(name)), None)
        if line is None:
            fail(f"doctor does not report {name}")
        if "ALLOW" not in line:
            fail(f"doctor reports {name} denied on the test host: {line}")
    # memfd is optional: inject falls back to an unlinked temp file.
    if not any(l.startswith("memfd") for l in out.splitlines()):
        fail("doctor does not report memfd")
    # A non-root user_switch denial is a degradation, not a failure.
    if p.returncode != 0:
        fail(f"doctor exited {p.returncode} with only non-core denials")

    probe_names = ("cap_eff", "has_caps", "seccomp_mode", "no_new_privs", "bpf",
                   "seccomp_user_notif", "ptrace_scope", "unprivileged_bpf_disabled",
                   "proc_1_cmdline")
    if "probe" not in out:
        fail("doctor does not print the probe block")
    for name in probe_names:
        line = next((l for l in out.splitlines() if l.strip().startswith(name + "\t")), None)
        if line is None:
            fail(f"doctor probe block lacks {name}")

    j = run(["doctor", "--json"])
    try:
        doc = json.loads(j.stdout)
    except json.JSONDecodeError as e:
        fail(f"doctor --json is not valid JSON: {e}")
    if doc.get("version") != VERSION:
        fail(f"doctor --json version {doc.get('version')!r}")
    if doc.get("ok") is not True:
        fail("doctor --json says not ok")
    for key in ("uid", "euid", "mem_total_kb", "page_kb", "hz", "cwd"):
        if key not in doc.get("env", {}):
            fail(f"doctor --json env lacks {key}")
    checks = doc.get("checks")
    if not isinstance(checks, list) or not checks:
        fail("doctor --json has no checks")
    probe = doc.get("probe")
    if not isinstance(probe, dict):
        fail("doctor --json has no probe object")
    for name in probe_names:
        if not probe.get(name):
            fail(f"doctor --json probe lacks {name}")
    by_name = {}
    for item in checks:
        if "name" not in item or "ok" not in item:
            fail("doctor --json check is not an object with a name field")
        by_name[item["name"]] = item
    if os.geteuid() != 0:
        us = by_name.get("user_switch")
        if not us or us.get("ok") is not False:
            fail("doctor did not deny user_switch for a non-root caller")
        if "errno" not in us:
            fail("doctor denial lacks an errno")
    pidfile = Path(tempfile.mkdtemp(prefix="psgen-doctor-")) / "probe.pid"
    j = run(["doctor", "--json", "--pidfile", str(pidfile)])
    doc = json.loads(j.stdout)
    pf = doc.get("pidfile", {})
    if pf.get("path") != str(pidfile) or not pf.get("writable"):
        fail(f"doctor --json did not report the pidfile writable: {pf}")
    shutil.rmtree(pidfile.parent, ignore_errors=True)


def check_log():
    listing = run(["log", "-m", "list"]).stdout.strip()
    if not listing.startswith("modules:"):
        fail(f"log -m list printed {listing!r}")
    # The first line is the canonical module names; the alias lines that follow
    # are indented, so only the first line's tail is the module list.
    modules = listing.splitlines()[0][len("modules:"):].split()
    if len(modules) < 14:
        fail(f"log lists only {len(modules)} modules")
    for name in ("weblog", "bootlog", "cargo", "docker_build", "kernel_compile"):
        if name not in modules:
            fail(f"log -m list lacks {name}")
    for name in modules:
        p = run(["log", "-m", name, "--lines", "2"])
        if not p.stdout.strip():
            fail(f"log -m {name} printed nothing")
        if "{" in p.stdout or "}" in p.stdout:
            fail(f"log -m {name} left an unexpanded placeholder")
    apache = run(["log", "-m", "weblog", "--lines", "3"]).stdout.splitlines()
    clf = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} \d+(?: "[^"]*" "[^"]*")?$')
    for line in apache:
        if not clf.match(line):
            fail(f"weblog apache line is malformed: {line!r}")
    for line in run(["log", "-m", "weblog", "--log-fmt", "json", "--lines", "3"]).stdout.splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            fail(f"weblog json line is malformed: {line!r}")
        if not {"ip", "ts", "method", "path", "status"} <= set(rec):
            fail(f"weblog json lacks keys: {line!r}")
    syslog = re.compile(r"^(?:<[0-9]+>)?[A-Z][a-z]{2} [ 0-9]\d \d\d:\d\d:\d\d \S+ ")
    for line in run(["log", "-m", "weblog", "--log-fmt", "syslog", "--lines", "3"]).stdout.splitlines():
        if not syslog.match(line):
            fail(f"weblog syslog line is malformed: {line!r}")
    if run(["log", "-m", "cargo", "--log-fmt", "apache"], check=False).returncode != 2:
        fail("log accepted apache format for a non-web module")
    p = run(["log", "-m", "nope"], check=False)
    if p.returncode != 2 or "unknown module" not in p.stderr:
        fail("log did not reject an unknown module")
    t0 = time.monotonic()
    run(["log", "-m", "weblog", "--lines", "40", "--delay", "20", "--speed", "4"])
    if time.monotonic() - t0 > 1.5:
        fail("--speed did not shorten the delay")


def check_load():
    if run(["load"], check=False).returncode != 2:
        fail("load without a util flag did not exit 2")

    total = mem_total()
    cg = cgroup_limit_kb()
    if cg > 0:
        total = min(total, cg)
    proc = subprocess.Popen([str(BIN), "load", "--mem-util", "2", "--duration", "4"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(0.8)
        rss = sizes(proc.pid)["rss"]
        want = total * 2 // 100
        if not (want * 8 // 10 <= rss <= want * 13 // 10):
            fail(f"--mem-util 2 held {rss} kB, wanted about {want} kB")
    finally:
        proc.wait(timeout=20)
    if proc.returncode != 0:
        fail(f"load --mem-util exited {proc.returncode}: {proc.stderr.read()}")

    proc = subprocess.Popen([str(BIN), "load", "--cpu-util", "50", "--duration", "4"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        util = cpu_percent(proc.pid, 1.5)
        if util is None:
            fail("load --cpu-util process vanished")
        if not 35.0 <= util <= 65.0:
            fail(f"--cpu-util 50 measured {util:.1f}%")
    finally:
        proc.wait(timeout=20)

    with tempfile.TemporaryDirectory(prefix="psgen-load-") as load_tmp:
        env = os.environ.copy()
        env["TMPDIR"] = load_tmp
        proc = subprocess.Popen([str(BIN), "load", "--disk-util", "8", "--duration", "4"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                text=True, env=env)
        try:
            time.sleep(0.8)
            held = []
            for fd in Path(f"/proc/{proc.pid}/fd").iterdir():
                try:
                    st = fd.stat()
                except OSError:
                    continue
                if st.st_size == 8 * 1024 * 1024:
                    held.append(st.st_size)
            if not held:
                fail("load --disk-util did not hold an 8 MiB temp file")
        finally:
            proc.wait(timeout=20)
        if list(Path(load_tmp).iterdir()):
            fail("load --disk-util left a path behind")

    # Both disk guards must refuse before a huge file is attempted. Each is
    # exercised on its own: the free-space guard with the file size limit at
    # its hard maximum, the RLIMIT guard with a small soft limit.
    import resource

    def limited(args, fsize):
        def preexec():
            soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            # a soft limit can never exceed the hard limit: clamping keeps the
            # guard test runnable on a host whose hard RLIMIT_FSIZE is finite
            lim = hard if fsize is None else (
                fsize if hard == resource.RLIM_INFINITY else min(fsize, hard))
            resource.setrlimit(resource.RLIMIT_FSIZE, (lim, hard))
        cmd = [str(BIN)] + [str(a) for a in args]
        return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=60, preexec_fn=preexec)

    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    hard_mib = None if hard == resource.RLIM_INFINITY else hard // (1024 * 1024)
    free_mib = shutil.disk_usage(tempfile.gettempdir()).free // (1024 * 1024)
    over = free_mib + 4096
    if hard_mib is not None and hard_mib <= over:
        print(f"free-space guard not reachable: RLIMIT_FSIZE is {hard_mib} MiB")
    else:
        p = limited(["load", "--disk-util", over], None)
        if p.returncode != 1 or "exceeds the free space" not in p.stderr:
            fail(f"load --disk-util {over} ignored the free-space guard")

    p = limited(["load", "--disk-util", "2048"], 1024 ** 3)
    if p.returncode != 1 or "exceeds RLIMIT_FSIZE" not in p.stderr:
        fail("load --disk-util ignored the RLIMIT_FSIZE guard")


def can_pty() -> bool:
    """True when this host lets a process acquire a pty (doctor says so)."""
    p = run(["doctor", "--json"])
    try:
        doc = json.loads(p.stdout)
    except json.JSONDecodeError:
        return True
    for c in doc.get("checks", []):
        if c.get("name") == "pty":
            return bool(c.get("ok"))
    return True


def alive(pid: int) -> bool:
    """False when the PID is gone, or when it is a zombie left by a parent
    that never reaped it: either way there is nothing left to signal."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat[stat.rindex(")") + 2] != "Z"


def check_inject_flags():
    with tempfile.TemporaryDirectory(prefix="psgen-flags-") as tmp:
        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "3", "-s", "3", "--no-user", "--no-mem",
             "--no-tty", "--no-threads", "--cpu", "40"], tmp, 3)
        try:
            for pid in pids:
                if emulated():
                    continue
                util = cpu_percent(pid, 1.0)
                if util is None:
                    fail(f"--cpu pid {pid} vanished")
                if not 28.0 <= util <= 55.0:
                    fail(f"--cpu 40 measured {util:.1f}% on pid {pid}")
        finally:
            stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "4", "-s", "3", "--no-user", "--no-tty",
             "--no-threads", "--phys-cap", "0", "--mem-target", "65536"], tmp, 4)
        time.sleep(0.3)
        # --mem-target sets RSS. A row whose template VSZ leaves less room is
        # clamped below the target, never above it.
        if not emulated():
            sizes_now = [sizes(p)["rss"] for p in pids]
            if not any(abs(v - 65536) <= 8 for v in sizes_now):
                fail(f"--mem-target 65536 produced {sizes_now}")
            if any(v > 65536 + 16 for v in sizes_now):
                fail(f"--mem-target 65536 exceeded the target: {sizes_now}")
        stop_pidfile(pidfile)

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "-s", "3", "--no-user", "--no-tty",
             "--no-threads", "--disk", "2"], tmp, 2)
        temps = [l[len("# temp "):] for l in Path(pidfile).read_text().splitlines()
                 if l.startswith("# temp ")]
        found = [Path(t) / "data.bin" for t in temps]
        found = [f for f in found if f.exists()]
        if len(found) != 2:
            fail(f"--disk 2 produced {len(found)} data files in {temps}")
        for f in found:
            if f.stat().st_size != 2 * 1024 * 1024:
                fail(f"--disk 2 wrote {f.stat().st_size} bytes")
        stop_pidfile(pidfile)
        for f in found:
            if f.exists():
                fail("stop left a --disk file behind")

        pidfile, pids, p = inject_and_check(
            ["inject", "-n", "2", "-s", "3", "--no-root", "--no-mem",
             "--no-tty", "--no-threads"], tmp, 2)
        if "disables user switching" not in p.stderr:
            fail("--no-root did not explain itself")
        if exe_known():
            for pid in pids:
                if Path(read_exe(pid)).resolve() != BIN.resolve():
                    fail(f"--no-root pid {pid} exe is {read_exe(pid)}")
        stop_pidfile(pidfile)

        shadow = Path(tmp) / "shadow"
        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "-s", "3", "--no-root", "--no-mem",
             "--no-tty", "--no-threads", "--shadow-dir", str(shadow)], tmp, 2)
        for pid in pids:
            if not exe_known():
                continue
            exe = read_exe(pid)
            if not exe.startswith(str(shadow) + "/"):
                fail(f"--shadow-dir pid {pid} exe is {exe}")
        stop_pidfile(pidfile)
        if shadow.exists() and any(shadow.iterdir()):
            fail("stop left shadow copies behind")

        pidfile, pids, _ = inject_and_check(
            ["inject", "-n", "2", "-s", "3", "--allow-proc-exe", "--no-user",
             "--no-mem", "--no-tty", "--no-threads"], tmp, 2)
        if exe_known():
            for pid in pids:
                if Path(read_exe(pid)).resolve() != BIN.resolve():
                    fail(f"--allow-proc-exe pid {pid} exe is {read_exe(pid)}")
        stop_pidfile(pidfile)

        p = run(["inject", "-n", "1", "--flame"], check=False)
        if p.returncode != 2 or "flame" not in p.stderr:
            fail("--flame was not rejected with an explanation")

def check_regressions():
    """Regressions for the QA findings. Each one failed at bf80156."""
    # F-01: the same seed must give the same non-time columns a second apart.
    def masked(text):
        rows = []
        for line in text.splitlines()[1:]:
            m = PS_RE.match(line)
            if not m:
                continue
            rows.append((m.group("pid"), m.group("cmd"), m.group("vsz"),
                         m.group("rss"), m.group("stat")))
        return rows
    a = masked(run(["table", "-n", "20", "-s", "42"]).stdout)
    time.sleep(1.2)
    b = masked(run(["table", "-n", "20", "-s", "42"]).stdout)
    if a != b:
        fail("F-01: table is not deterministic across one second with the same seed")

    # F-03: an existing psgen pidfile is accepted as an output path.
    with tempfile.TemporaryDirectory(prefix="psgen-reg-") as tmp:
        pf = Path(tmp) / "existing.pid"
        pf.write_text("# psgen 0.0.1 boot x\n")
        p = run(["inject", "-n", "1", "-s", "3", "--no-user", "--no-mem",
                 "--no-tty", "--no-threads", "--pidfile", str(pf), "--duration", "2"])
        if p.returncode != 0:
            fail(f"F-03: an existing psgen pidfile was refused: {p.stderr}")
        stop_pidfile(pf)

        # F-02: stop --dry-run must be a parse error, not a kill.
        if run(["stop", "--pidfile", str(pf), "--dry-run"], check=False).returncode != 2:
            fail("F-02: stop --dry-run was accepted")

        # F-17: a pidfile naming a live process with the wrong starttime keeps
        # the temp dirs and exits nonzero only when the process is unreadable;
        # a readable but mismatched process is skipped.
        me = os.getpid()
        pf.write_text(f"# psgen 0.0.1 boot {boot_id()}\n{me}\t0\ttest\n")
        out = run(["stop", "--pidfile", str(pf)], check=False).stdout
        if "skipped 1" not in out:
            fail("F-17: a readable mismatched starttime was not skipped")
        os.kill(me, 0)

        # F-31/F-35: 40-row stop must report 40, not a timing-dependent count.
        pf.write_text("")
        run(["inject", "-n", "40", "-s", "7", "--no-user", "--no-mem",
             "--no-tty", "--threads", "--pidfile", str(pf)])
        out = run(["stop", "--pidfile", str(pf)]).stdout
        if "stopped 40 processes" not in out:
            fail(f"F-31/F-35: stop reported {out.strip()!r} for 40 rows")

        # F-13: seccomp filter with a null program is reachable, so DENY here
        # would be wrong. Only assert the probe returns a known verdict.
        j = run(["doctor", "--json"])
        doc = json.loads(j.stdout)
        val = doc.get("probe", {}).get("seccomp_user_notif")
        if val not in ("reachable", "blocked"):
            fail(f"F-13: seccomp probe returned {val!r}")

        # F-12: cargo on PATH must not be reported missing.
        out = run(["check", "--binaries"]).stdout
        if "missing: cargo  <-" in out:
            fail("F-12: check --binaries reported cargo missing")

        # F-23: %MEM is rounded, not truncated.
        mem = mem_total()
        for line in run(["table", "-n", "40", "-s", "1"]).stdout.splitlines()[1:]:
            m = PS_RE.match(line)
            if not m:
                continue
            rss = int(m.group("rss"))
            want = round(rss * 100.0 / mem, 1)
            got = float(m.group("mem"))
            if abs(got - want) > 0.051:
                fail(f"F-23: %MEM {got} for RSS {rss} kB, want {want}")

        # F-15: the help must describe the 4 MiB floor.
        if "4 MiB" not in run(["--help"]).stdout:
            fail("F-15: help does not mention the 4 MiB mem-cap floor")

        # F-16: the unit must not name a nonexistent target.
        if "proc-fs-nets.target" in run(["unit"]).stdout:
            fail("F-16: unit still names proc-fs-nets.target")

        # F-11: a group without a user is repaired.
        if can_root():
            before_group = subprocess.run(
                ["getent", "group", "haproxy"], stdout=subprocess.DEVNULL).returncode == 0
            before_user = subprocess.run(
                ["getent", "passwd", "haproxy"], stdout=subprocess.DEVNULL).returncode == 0
            if not before_group and not before_user:
                subprocess.run(["sudo", "-n", "groupadd", "-r", "haproxy"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    pf.write_text("")
                    run(["inject", "-f", "web", "-n", "60", "-s", "8", "--user",
                         "--create-users", "--no-exe", "--no-mem", "--no-tty",
                         "--no-threads", "--pidfile", str(pf), "--duration", "2"],
                        root=True)
                    if subprocess.run(["getent", "passwd", "haproxy"],
                                      stdout=subprocess.DEVNULL).returncode != 0:
                        fail("F-11: --create-users did not repair a missing user")
                finally:
                    stop_pidfile(pf, root=True)
                    subprocess.run(["sudo", "-n", "userdel", "haproxy"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["sudo", "-n", "groupdel", "haproxy"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            print("SKIP: F-11 needs passwordless sudo", file=sys.stderr)

        check_regressions2(tmp)


def check_regressions2(tmp):
    """Second batch: the defects the earlier round left open."""

    # #4: a second stop must not count zombies as stopped, and must not fail.
    pf = Path(tmp) / "zombie.pid"
    run(["inject", "-n", "6", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    first = run(["stop", "--pidfile", str(pf)]).stdout
    if "stopped 6 processes" not in first:
        fail(f"#4: first stop reported {first.strip()!r} for 6 rows")
    time.sleep(0.5)
    second = run(["stop", "--pidfile", str(pf)]).stdout
    if "stopped 0 processes" not in second:
        fail(f"#4: a second stop counted zombies as stopped: {second.strip()!r}")
    pf.unlink()

    # #4 (second half): a subtree is counted once per row, not once per signal
    # that happened to land before the process exited.
    pf = Path(tmp) / "subtree.pid"
    run(["inject", "-n", "40", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--threads", "--pidfile", str(pf)])
    out = run(["stop", "--pidfile", str(pf)]).stdout
    if "stopped 40 processes" not in out:
        fail(f"#4: stop reported {out.strip()!r} for a 40-row tree")
    pf.unlink()

    # #22: a one-field pidfile line must not report success without signalling.
    pf = Path(tmp) / "full.pid"
    one = Path(tmp) / "one.pid"
    run(["inject", "-n", "2", "-s", "5", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    pids = read_pids(pf)
    one.write_text("".join(f"{p}\n" for p in pids))
    p = run(["stop", "--pidfile", str(one)], check=False)
    # A zombie is gone for every purpose `stop` reports, so the liveness test
    # is the same one the tool uses.
    alive_now = [pid for pid in pids if alive(pid)]
    # The one-field form identifies a row by its exe. Under qemu-user that is
    # the emulator, so it cannot identify any row; the three-field form is the
    # supported one there and is exercised above.
    if exe_known() and p.returncode == 0 and alive_now:
        fail(f"#22: a one-field pidfile reported success with {len(alive_now)} rows alive")
    stop_pidfile(pf)

    # #15: stop --dry-run must be refused; stop --plan must not signal.
    pf = Path(tmp) / "plan.pid"
    run(["inject", "-n", "2", "-s", "5", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    pids = read_pids(pf)
    if run(["stop", "--pidfile", str(pf), "--dry-run"], check=False).returncode != 2:
        fail("#15: stop --dry-run was accepted")
    plan = run(["stop", "--pidfile", str(pf), "--plan"], check=False)
    if "would stop 2 processes" not in plan.stdout:
        fail(f"#15: stop --plan printed {plan.stdout.strip()!r}")
    for pid in pids:
        if not alive(pid):
            fail(f"#15: stop --plan signalled pid {pid}")
    stop_pidfile(pf)

    # #26: a basename near NAME_MAX is refused before anything is spawned.
    for length in (200, 220, 225, 230, 240, 250):
        name = "d" * length
        p = run(["inject", "-n", "1", "--no-user", "--no-mem", "--no-tty",
                 "--no-threads", "--pidfile", str(Path(tmp) / name)], check=False)
        if p.returncode != 0 and "spawned" in p.stdout:
            fail(f"#26: basename {length} failed after spawning")
        if p.returncode == 0 and not (Path(tmp) / name).exists():
            fail(f"#26: basename {length} reported success without a pidfile")
        if (Path(tmp) / name).exists():
            stop_pidfile(Path(tmp) / name)

    # #25: a config on fd 3 that the injector did not write must be ignored.
    import struct
    magic = b"PGCFG023"
    hdr = bytearray(104)
    hdr[:8] = magic
    struct.pack_into("<I", hdr, 8, 3)      # version
    struct.pack_into("<I", hdr, 92, 0)     # self_copy len
    struct.pack_into("<I", hdr, 96, 4)     # nonce len
    blob = bytes(hdr) + b"dead"
    cfg = Path(tmp) / "cfg.bin"
    cfg.write_bytes(blob)
    with open(cfg, "rb") as f:
        p = subprocess.run([str(BIN)], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           pass_fds=(f.fileno(),),
                           preexec_fn=lambda: os.dup2(f.fileno(), 3),
                           timeout=30)
    # The stub path must not be entered: the process behaves like `psgen list`
    # with no arguments (one line per template) and says nothing on stderr.
    lines = [l for l in p.stdout.decode().splitlines() if l]
    if p.returncode != 0 or p.stderr:
        fail(f"#25: an inherited fd 3 config was acted on: rc={p.returncode} "
             f"{p.stderr.decode()[:200]}")
    if len(lines) < 180:
        fail(f"#25: a stray config changed the command line ({len(lines)} lines)")

    # #25 (stronger): a config with a matching nonce but an attacker-named
    # self_copy must not exec it and must not create the named directory.
    hdr = bytearray(104)
    hdr[:8] = magic
    self_copy = b"/bin/sh"
    temp = str(Path(tmp) / "attack").encode()
    cmd = b"/usr/sbin/nginx"
    comm = b"nginx"
    nonce = b"deadbeefdeadbeef"

    def w(off, v):
        struct.pack_into("<I", hdr, off, v)

    w(8, 3)                        # version
    w(40, 1)                       # stage
    w(44, len(comm))
    w(48, len(self_copy))
    w(52, len(cmd))
    w(56, 1)
    w(60, len(temp))
    struct.pack_into("<i", hdr, 72, 5)     # max_fd
    struct.pack_into("<i", hdr, 76, -1)    # arena_fd
    struct.pack_into("<i", hdr, 80, -1)    # status_fd
    w(88, 1024)                    # disk_kb
    w(92, len(self_copy))
    w(96, len(nonce))
    blob = (bytes(hdr) + comm + self_copy + cmd + b"u" + temp + self_copy + nonce)
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.memfd_create(b"psgen-test", 0)
    if fd >= 0:
        os.write(fd, blob)
        os.lseek(fd, 0, 0)
        p = subprocess.Popen([str(BIN)], env=dict(os.environ, PSGEN_NONCE="deadbeefdeadbeef"),
                             preexec_fn=lambda: os.dup2(fd, 3), pass_fds=(fd,),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        try:
            exe = os.readlink(f"/proc/{p.pid}/exe")
        except OSError:
            exe = ""
        if exe == "/bin/sh":
            p.kill()
            p.wait()
            fail("#25: a forged config with a matching nonce executed its self_copy")
        if (Path(tmp) / "attack").exists():
            p.kill()
            p.wait()
            fail("#25: a forged config created the directory it named")
        p.kill()
        p.wait()
        os.close(fd)

    # #14: a denied getrandom must not abort after the stubs are spawned.
    #     (The fallback is total; a run with --pidfile must exit 0 or, at
    #     worst, report the rows without a panic.)
    pf = Path(tmp) / "rand.pid"
    p = run(["inject", "-n", "2", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--pidfile", str(pf), "--duration", "1"],
            check=False)
    if p.returncode >= 128:
        fail(f"#14: inject died with signal {p.returncode - 128}")
    stop_pidfile(pf)

    # #8: doctor --json checks are objects with a name field.
    doc = json.loads(run(["doctor", "--json"]).stdout)
    if not all(isinstance(c, dict) and "name" in c for c in doc["checks"]):
        fail("#8: doctor --json checks are not named objects")
    if "core_ok" not in doc:
        fail("#8: doctor --json lacks core_ok")
    pf = Path(tmp) / "doctor.pid"
    doc = json.loads(run(["doctor", "--json", "--pidfile", str(pf)]).stdout)
    if doc.get("pidfile", {}).get("path") != str(pf):
        fail("#8: doctor --json pidfile is not an object with a path")

    # #7: a pidfile header with another version is still recognised.
    me = os.getpid()
    pf.write_text(f"# psgen 9.9.9 boot 00000000-0000-0000-0000-000000000000\n{me}\t0\ttest\n")
    p = run(["stop", "--pidfile", str(pf)], check=False)
    if "another boot" not in p.stderr:
        fail("#7: a foreign-version pidfile header was not parsed")

    # #17: --utc-offset is bounded.
    if run(["table", "-n", "1", "--utc-offset", "9223372036854775807"],
           check=False).returncode != 2:
        fail("#17: an absurd --utc-offset was accepted")
    env = dict(os.environ, TZ="Asia/Kolkata")
    loc = run(["table", "-f", "dev", "-n", "4", "-s", "1", "--local"], env=env).stdout
    both = run(["table", "-f", "dev", "-n", "4", "-s", "1", "--local",
                "--utc-offset", "120"], env=env).stdout
    if loc != both:
        fail("#17: --local and --utc-offset were both applied")

    # #16: a count is honoured by spreading the repeats over the templates that
    # can run more than once, and a request that cannot be met at all says so.
    for fam, n in (("mail", 50), ("mon", 50), ("sto", 50), ("net", 50)):
        p = run(["table", "-f", fam, "-n", str(n)])
        cmds = [" ".join(r.split()[10:]) for r in p.stdout.splitlines()[1:]]
        if cmds and max(cmds.count(c) for c in set(cmds)) > n // 2:
            fail(f"#16: {fam} -n {n} is dominated by one command")
        if "can supply" in p.stderr and not cmds:
            fail(f"#16: {fam} warned but produced no rows")
        # `list` never repeats, so it stops short and says so.
        lp = run(["list", "-f", fam, "-n", str(n)])
        lines = lp.stdout.splitlines()
        if len(lines) < n and "a list never repeats" not in lp.stderr:
            fail(f"#16: list -f {fam} shortfall was silent")
        if len(set(lines)) != len(lines):
            fail(f"#16: list -f {fam} repeated a command")
    rows = run(["table", "-f", "sys", "-n", "200"]).stdout.splitlines()[1:]
    cmds = [" ".join(r.split()[10:]) for r in rows]
    # The regression was one command taking 60% of the table (120 of 200 rows
    # were `sshd: user [priv]`).
    top = max(cmds.count(c) for c in set(cmds))
    if top > len(cmds) // 3:
        fail(f"#16: sys -n 200 has one command {top} of {len(cmds)} rows")
    if len(set(cmds)) < 30:
        fail(f"#16: sys -n 200 used only {len(set(cmds))} distinct commands")
    big = [" ".join(r.split()[10:]) for r in
           run(["table", "-n", "5000", "-s", "1"]).stdout.splitlines()[1:]]
    if len(big) < 1000:
        fail(f"#16: table -n 5000 produced only {len(big)} rows")
    top = max(big.count(c) for c in set(big))
    if top > len(big) // 25:
        fail(f"#16: table -n 5000 has one command {top} of {len(big)} rows")

    # #28: RSS cannot exceed MemTotal, %MEM cannot exceed 100, PIDs stay below
    # pid_max.
    mem = mem_total()
    pid_max = int(Path("/proc/sys/kernel/pid_max").read_text())
    for line in run(["table", "-n", "5000", "-s", "1"]).stdout.splitlines()[1:]:
        m = PS_RE.match(line)
        if not m:
            continue
        rss, mempct, pid = int(m.group("rss")), float(m.group("mem")), int(m.group("pid"))
        if rss > mem:
            fail(f"#28: RSS {rss} kB exceeds MemTotal {mem} kB")
        if mempct > 100.0:
            fail(f"#28: %MEM {mempct} is impossible for one process")
        if pid > pid_max:
            fail(f"#28: PID {pid} exceeds pid_max {pid_max}")

    # #3: table --live matches ps aux on the cases a monitor hits.
    live = run(["table", "--live"]).stdout.splitlines()
    ref = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True,
                         timeout=30).stdout.splitlines()
    if live[0] != ref[0]:
        fail("#3: live header differs from ps aux")

    def offsets(lines):
        out = []
        for line in lines[1:]:
            m = PS_RE.match(line)
            if not m:
                out.append(None)
                continue
            try:
                stat = line.index(m.group("stat"), 40)
                start = line.index(m.group("start"), stat)
                tm = line.index(m.group("time"), start)
                cmd = line.index(m.group("cmd"), tm)
            except ValueError:
                out.append(None)
                continue
            out.append((stat, start, tm, cmd))
        return out

    # Only compare rows that both sides parsed: the two reads are not atomic, so
    # a process that exits between them has no pair.
    def by_pid(lines):
        out = {}
        for line in lines[1:]:
            m = PS_RE.match(line)
            if not m:
                continue
            try:
                stat = line.index(m.group("stat"), 40)
                start = line.index(m.group("start"), stat)
                tm = line.index(m.group("time"), start)
                cmd = line.index(m.group("cmd"), tm)
            except ValueError:
                continue
            out[int(m.group("pid"))] = (stat, start, tm, cmd)
        return out

    mine, theirs = by_pid(live), by_pid(ref)
    common = set(mine) & set(theirs)
    if len(common) < 5:
        fail(f"#3: only {len(common)} rows are common to the two tables")
    for pid in common:
        if mine[pid] != theirs[pid]:
            fail(f"#3: live column offsets {mine[pid]} differ from ps {theirs[pid]} for {pid}")
    if any("\n" in l for l in live):
        fail("#3: live table emitted a raw newline")
    # A zombie's COMMAND must carry <defunct>, as ps prints it.
    ps_rows_ref = {}
    for line in ref[1:]:
        m = PS_RE.match(line)
        if m:
            ps_rows_ref[int(m.group("pid"))] = m.group("cmd")
    live_rows_now = {}
    for line in live[1:]:
        m = PS_RE.match(line)
        if m:
            live_rows_now[int(m.group("pid"))] = m.group("cmd")
    for pid, want in ps_rows_ref.items():
        if want.endswith("<defunct>") and pid in live_rows_now:
            if live_rows_now[pid] != want:
                fail(f"#3: zombie {pid} cmd {live_rows_now[pid]!r} != ps {want!r}")

    # A newline in argv must not split a row.
    script = ("import subprocess,time,sys;"
              "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)',"
              "'line1\\nline2','tab\\there','','empty-argv']);print(p.pid,flush=True);"
              "time.sleep(30)")
    helper = subprocess.Popen([sys.executable, "-c", script],
                              stdout=subprocess.PIPE, text=True)
    try:
        time.sleep(0.8)
        wide = run(["table", "--live"]).stdout
        for line in wide.splitlines():
            if "line1" in line:
                if "line2" in line.split("line1", 1)[1][:8]:
                    pass
                break
        else:
            pass
        bad = [l for l in wide.splitlines() if l.startswith("line2")]
        if bad:
            fail("#3: a newline in argv split a live table row")
        # The empty argv elements must survive as the extra spaces `ps` shows.
        inner = int(helper.stdout.readline().strip())
        mine = None
        for line in wide.splitlines():
            m = PS_RE.match(line)
            if m and int(m.group("pid")) == inner:
                mine = m.group("cmd")
                break
        ps_args = subprocess.run(["ps", "-o", "args=", "-p", str(inner)],
                                 stdout=subprocess.PIPE, text=True,
                                 timeout=30).stdout.strip()
        if mine is None:
            fail("#3: the empty-argv process is missing from the live table")
        if mine != ps_args:
            fail(f"#3: live cmd {mine!r} != ps {ps_args!r} for an empty argv element")
    finally:
        helper.kill()
        helper.wait()
        try:
            os.kill(inner, 9)
        except (ProcessLookupError, UnboundLocalError, OSError):
            pass

    # #9: an option that does not apply to the subcommand is an error.
    for args in (["stop", "-n", "40", "--pidfile", str(Path(tmp) / "x.pid")],
                 ["corpus", "-n", "5"],
                 ["list", "-d", "5", "-n", "1"],
                 ["list", "--json", "-n", "1"],
                 ["table", "--live", "-f", "web"],
                 ["doctor", "--json", "--lines", "5"],
                 ["check", "--utc-offset", "300"],
                 ["check", "-p", "desktop"],
                 ["inject", "--plan"]):
        if run(args, check=False).returncode != 2:
            fail(f"#9: {args} was accepted")

    # #9/#13.2: unit forwards what it was given and caps -n.
    unit = run(["unit", "-p", "desktop", "-f", "desk", "--no-mem", "-d", "300",
                "-n", "40"]).stdout
    for want in ("-p desktop", "-f desk", "-d 300", "--no-mem", "-n 40"):
        if want not in unit.split("ExecStart=")[1].splitlines()[0]:
            fail(f"#13.2: unit did not forward {want}")
    capped = run(["unit", "-n", "1000"]).stdout
    if "-n 500" not in capped:
        fail("#27: unit -n was not capped at the inject cap")

    # #12: --dry-run keeps its two columns; --plan and --json add the plan.
    dry = run(["inject", "-n", "2", "-s", "3", "--dry-run", "--no-user"]).stdout
    if not all(len(l.split("\t")) == 2 for l in dry.splitlines() if l):
        fail("#12: --dry-run changed its two-column format")
    plan = run(["inject", "-n", "2", "-s", "3", "--dry-run", "--plan",
                "--no-user"]).stdout
    if "tier " not in plan or "row 0 " not in plan:
        fail("#12: --plan printed no plan")
    doc = json.loads(run(["inject", "-n", "2", "-s", "3", "--dry-run", "--json",
                          "--no-user"]).stdout)
    if doc.get("tier") not in ("bind", "shadow", "proc-self") or len(doc["rows"]) != 2:
        fail("#12: --dry-run --json is not a plan")

    # #5: a --duration run that nobody stops leaves nothing for the next run.
    shadow = Path(tmp) / "staging"
    env = dict(os.environ, TMPDIR=str(Path(tmp) / "tmpdir"))
    (Path(tmp) / "tmpdir").mkdir()
    run(["inject", "-n", "3", "-s", "7", "-d", "1", "--disk", "1",
         "--no-user", "--no-mem", "--no-tty", "--no-threads",
         "--shadow-dir", str(shadow), "--pidfile", str(Path(tmp) / "d.pid")],
        env=env)
    time.sleep(2.2)
    leftovers = list(shadow.rglob("*")) + list((Path(tmp) / "tmpdir").glob(".psgen-*"))
    if not leftovers:
        fail("#5: the --duration run left no staging behind to test the prune")
    for p in leftovers:
        try:
            os.utime(p, (0, 0))
        except OSError:
            pass
    p = run(["inject", "-n", "1", "-s", "7", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--shadow-dir", str(shadow),
             "--pidfile", str(Path(tmp) / "p.pid")], env=env, check=False)
    stop_pidfile(Path(tmp) / "p.pid")
    if "pruned" not in p.stderr:
        fail("#5: the next run did not prune the staging directories")
    if list((Path(tmp) / "tmpdir").glob(".psgen-*")):
        fail("#5: the prune left a dead run's data directory")

    # #5 (second half): a live --duration run must keep its staging until its
    # last stub exits. The injector is already gone, so only the live marker
    # can tell the prune that the data is still in use.
    live_tmp = Path(tmp) / "livetmp"
    live_tmp.mkdir()
    live_shadow = Path(tmp) / "live-staging"
    live_env = dict(os.environ, TMPDIR=str(live_tmp))
    pf1 = Path(tmp) / "live1.pid"
    pf2 = Path(tmp) / "live2.pid"
    run(["inject", "-n", "1", "-s", "7", "-d", "8", "--disk", "1",
         "--no-user", "--no-mem", "--no-tty", "--no-threads",
         "--shadow-dir", str(live_shadow), "--pidfile", str(pf1)], env=live_env)
    dirs = list(live_tmp.glob(".psgen-*"))
    if not dirs:
        fail("#5: the live run created no staging directory")
    try:
        p = run(["inject", "-n", "1", "-s", "7", "-d", "1", "--no-user",
                 "--no-mem", "--no-tty", "--no-threads",
                 "--shadow-dir", str(live_shadow), "--pidfile", str(pf2)],
                env=live_env, check=False)
        if "pruned" in p.stderr:
            fail("#5: the prune removed a live --duration run's staging")
        if not dirs[0].is_dir():
            fail("#5: the live --duration run's staging directory is gone")
        if not (dirs[0] / "data.bin").is_file():
            fail("#5: the live --duration run's disk data is gone")
    finally:
        stop_pidfile(pf2)
        stop_pidfile(pf1)

    # #1: a pidfile that still records live stubs cannot be reused. The second
    # inject must refuse, and the first run must remain stoppable.
    pf = Path(tmp) / "reuse.pid"
    run(["inject", "-n", "2", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    p = run(["inject", "-n", "2", "-s", "7", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--pidfile", str(pf)], check=False)
    if p.returncode != 2 or "records live processes" not in p.stderr:
        fail(f"#1: reusing a live pidfile was not refused: rc {p.returncode}")
    out = stop_pidfile(pf)
    if "stopped 2 processes" not in out:
        fail(f"#1: the first run could not be stopped after the refusal: {out!r}")
    run(["inject", "-n", "2", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    stop_pidfile(pf)

    # #4 (third case): a malformed starttime is skipped, not treated as a
    # one-field line whose executable check can kill a psgen stub.
    pf = Path(tmp) / "malformed.pid"
    run(["inject", "-n", "1", "-s", "7", "--no-exe", "--no-user", "--no-mem",
         "--no-tty", "--no-threads", "--pidfile", str(pf)])
    lines = pf.read_text().splitlines()
    row = next(l for l in lines if l and not l.startswith("#"))
    fields = row.split("\t")
    pid = int(fields[0])
    fields[1] = "notanumber"
    lines = [("\t".join(fields) if l == row else l) for l in lines]
    pf.write_text("\n".join(lines) + "\n")
    try:
        out = run(["stop", "--pidfile", str(pf)]).stdout
        if "skipped 1" not in out:
            fail(f"#4: a malformed starttime was not skipped: {out.strip()!r}")
        if not Path(f"/proc/{pid}").exists():
            fail("#4: a malformed starttime killed the named psgen stub")
    finally:
        try:
            os.kill(pid, 9)
        except OSError:
            pass
        pf.unlink(missing_ok=True)

    # #24: a closed reader stops the generator, and --lines is bounded.
    proc = subprocess.Popen([str(BIN), "log", "-m", "weblog", "--lines", "100000",
                             "--delay", "10"], stdout=subprocess.PIPE)
    proc.stdout.readline()
    proc.stdout.close()
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        proc.kill()
        fail("#24: log kept generating after its reader exited")
    p = run(["log", "--lines", "1000000000"], check=False, timeout=120)
    if len(p.stdout) > 200 * 1024 * 1024:
        fail("#24: log --lines 1000000000 produced an unbounded amount of output")
    if "capped" not in p.stderr:
        fail("#24: log did not warn about the cap")

    # #23: --mem-util above MemAvailable is refused without --force.
    avail = 0
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            avail = int(line.split()[1])
    if avail and avail * 1000 // mem_total() < 950:
        p = run(["load", "--mem-util", "95", "-d", "1"], check=False, timeout=120)
        if p.returncode != 2 or "MemAvailable" not in p.stderr:
            fail("#23: load --mem-util above MemAvailable was not refused")

    # #21: check --binaries does not report an installed path as missing.
    out = run(["check", "--binaries"]).stdout
    for line in out.splitlines():
        if not line.startswith("missing: "):
            continue
        path = line.split("<- ", 1)[1].strip().split()[0]
        if os.access(path, os.X_OK):
            fail(f"#21: check --binaries reported an existing path missing: {path}")
    if run(["check", "--require-binaries"], check=False).returncode not in (0, 1):
        fail("#21: --require-binaries exited with an unexpected code")


def seccomp_helper() -> Path | None:
    """Build the seccomp launcher, or None when there is no C compiler."""
    src = ROOT / "tests" / "helpers" / "deny_syscall.c"
    if not src.is_file():
        return None
    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        return None
    out = Path(tempfile.mkdtemp(prefix="psgen-seccomp-")) / "deny_syscall"
    p = subprocess.run([cc, "-O2", "-o", str(out), str(src)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        print(f"SKIP: cannot build the seccomp helper: {p.stderr.strip()[:200]}",
              file=sys.stderr)
        return None
    return out


def check_residuals(tmp):
    """Regressions for the defects a second review found in the first PR."""

    # #16: `-n` is a guarantee, not a target, for one family as well as for the
    # whole corpus. Every family that has a template able to repeat must reach
    # the requested count exactly, and the busiest command must stay under
    # half the table.
    for fam in ("sys", "web", "db", "mon", "net", "mail", "sto", "desk", "dev", "ctr"):
        p = run(["table", "-f", fam, "-n", "200"], check=False)
        rows = p.stdout.splitlines()[1:]
        if len(rows) != 200:
            fail(f"#16: table -f {fam} -n 200 returned {len(rows)} rows")
        cmds = [" ".join(r.split()[10:]) for r in rows]
        top = max(cmds.count(c) for c in set(cmds))
        if top > len(cmds) // 2:
            fail(f"#16: table -f {fam} -n 200 has one command {top} of {len(cmds)} rows")
    # The count is exact for `inject` too.
    rows = run(["inject", "-f", "web", "-n", "120", "--dry-run"]).stdout.splitlines()
    if len(rows) != 120:
        fail(f"#16: inject -f web -n 120 printed {len(rows)} rows")

    # #16 (opt-out): `--repeat-max 1` is how a caller asks for fewer rows rather
    # than a repeated command, and the shortfall names the reason.
    p = run(["table", "-f", "sto", "-n", "200", "--repeat-max", "1"], check=False)
    rows = p.stdout.splitlines()[1:]
    if len(rows) >= 200:
        fail("#16: --repeat-max 1 still reached 200 rows")
    if "row" not in p.stderr or "could be produced" not in p.stderr:
        fail(f"#16: the shortfall message is unhelpful: {p.stderr.strip()!r}")
    cmds = [" ".join(r.split()[10:]) for r in rows]
    if cmds and max(cmds.count(c) for c in set(cmds)) > 1:
        fail("#16: --repeat-max 1 repeated a command")
    # ... and the default reaches the count for the same family.
    rows = run(["table", "-f", "sto", "-n", "200"]).stdout.splitlines()[1:]
    if len(rows) != 200:
        fail(f"#16: table -f sto -n 200 returned {len(rows)} rows by default")

    # #28: a small pid_max caps the table, reports the gap, and never repeats or
    # exceeds a PID.
    for pid_max in (2, 3, 4, 10, 100):
        p = run(["table", "-n", "50", "--host-pid-max", str(pid_max)], check=False)
        rows = p.stdout.splitlines()[1:]
        pids = [int(r.split()[1]) for r in rows]
        if len(set(pids)) != len(pids):
            fail(f"#28: pid_max {pid_max} produced a duplicate PID")
        for pid in pids:
            if pid < 1 or pid >= pid_max:
                fail(f"#28: pid_max {pid_max} produced PID {pid}")
        room = max(pid_max - 1, 1)
        if len(pids) > room:
            fail(f"#28: pid_max {pid_max} produced {len(pids)} rows with room for {room}")
        if pid_max < 50 and "could be produced" not in p.stderr:
            fail(f"#28: pid_max {pid_max} silently under-delivered")
        if pid_max >= 50 and p.stderr:
            fail(f"#28: pid_max {pid_max} printed a shortfall it does not have")

    # #28 (memory half): a small host is fitted, not exceeded.
    rows = run(["table", "-n", "600", "--host-mem", "256"]).stdout.splitlines()[1:]
    total = 0
    for line in rows:
        m = PS_RE.match(line)
        if not m:
            continue
        rss = int(m.group("rss"))
        total += rss
        if rss > 256 * 1024:
            fail(f"#28: a 256 MiB host got a {rss} kB row")
        if float(m.group("mem")) > 100.0:
            fail("#28: %MEM above 100 on a 256 MiB host")
    if total > 256 * 1024:
        fail(f"#28: a 256 MiB host got {total} kB of RSS")

    # #2: the same seed must give the same non-time columns at any uptime, with
    # no private mount and no fake host: the generator takes the uptime.
    def masked(args, uptime):
        out = run(args + ["--host-uptime", str(uptime)]).stdout
        rows = []
        for line in out.splitlines()[1:]:
            m = PS_RE.match(line)
            if not m:
                continue
            rows.append((m.group("pid"), m.group("cpu"), m.group("vsz"),
                         m.group("rss"), m.group("stat"), m.group("cmd")))
        return rows

    for uptime in (0, 1, 5, 10, 11, 30, 60, 61, 600):
        a = masked(["table", "-n", "30", "-s", "165"], uptime)
        b = masked(["table", "-n", "30", "-s", "165"], uptime + 1)
        if a != b:
            fail(f"#2: seed 165 differs between uptime {uptime} and {uptime + 1}")

    # #14: a real seccomp denial of getrandom must not abort after the pidfile
    # header is written, and the run must stay stoppable.
    helper = seccomp_helper()
    if helper is None:
        print("SKIP: #14 needs a C compiler for the seccomp launcher",
              file=sys.stderr)
    else:
        pf = Path(tmp) / "getrandom.pid"
        p = subprocess.run([str(helper), "getrandom", str(BIN), "inject", "-n", "2",
                            "--no-user", "--no-mem", "--no-tty", "--no-threads",
                            "--pidfile", str(pf)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=180)
        if p.returncode >= 128:
            fail(f"#14: inject died by signal {p.returncode - 128} under a getrandom denial")
        if p.returncode != 0:
            fail(f"#14: inject failed under a getrandom denial: {p.stderr.strip()[:300]}")
        if not pf.exists():
            fail("#14: no pidfile after a getrandom denial")
        pids = read_pids(pf)
        if len(pids) != 2:
            fail(f"#14: {len(pids)} rows recorded under a getrandom denial")
        out = stop_pidfile(pf)
        if "stopped 2 processes" not in out:
            fail(f"#14: the run was not stoppable after a getrandom denial: {out!r}")

        # The other half: a failure inside spawn, after the header-only pidfile
        # exists. Nothing may be spawned and the header must be removed.
        pf = Path(tmp) / "pipe2.pid"
        p = subprocess.run([str(helper), "pipe2", str(BIN), "inject", "-n", "2",
                            "--no-user", "--no-mem", "--no-tty", "--no-threads",
                            "--pidfile", str(pf)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=180)
        if p.returncode == 0:
            fail("#14: inject succeeded with pipe2 denied")
        if pf.exists():
            fail("#14: a post-header spawn failure left a pidfile behind")
        if "pipe2" not in p.stderr:
            fail(f"#14: the failure does not name the syscall: {p.stderr.strip()[:200]!r}")

    # #25: a hardlink named psgen-stub must not be executed. A hardlink is a
    # regular file with a second link, which is exactly what the leaf check
    # refuses.
    if not (shutil.which("ln") and os.path.isdir("/proc/self/fd")):
        print("SKIP: #25 hardlink leaf needs ln", file=sys.stderr)
    else:
        staging = Path(tmp) / "hardlink"
        staging.mkdir()
        run(["inject", "-n", "1", "-s", "5", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--shadow-dir", str(staging),
             "--pidfile", str(Path(tmp) / "hl.pid")], check=False)
        dirs = list(staging.glob(".psgen-*"))
        if not dirs:
            print("SKIP: #25 no shadow staging was created", file=sys.stderr)
        else:
            d = dirs[0]
            run([str(BIN), "stop", "--pidfile", str(Path(tmp) / "hl.pid")], check=False)
            run([str(BIN), "stop", "--pidfile", str(Path(tmp) / "hl.pid")], check=False)
            leaf = d / "psgen-stub"
            victim = d / "victim"
            if leaf.exists():
                leaf.unlink()
            shutil.copy2("/bin/echo", victim)
            try:
                os.link(victim, leaf)
            except OSError as e:
                print(f"SKIP: #25 cannot make a hardlink here: {e}", file=sys.stderr)
            else:
                # Feed the stub a config that names the hardlinked leaf. It must
                # not exec it.
                cfg = Path(tmp) / "hl.cfg"
                nonce = b"deadbeefdeadbeef"
                comm = b"nginx"
                cmd = b"/usr/sbin/nginx"
                self_copy = str(leaf).encode()
                temp = str(d).encode()
                import struct
                hdr = bytearray(104)
                hdr[:8] = b"PGCFG023"

                def w(off, v):
                    struct.pack_into("<I", hdr, off, v)

                w(8, 3)
                w(40, 1)
                w(44, len(comm))
                w(48, len(self_copy))
                w(52, len(cmd))
                w(56, 1)
                w(60, len(temp))
                struct.pack_into("<i", hdr, 72, 5)
                struct.pack_into("<i", hdr, 76, -1)
                struct.pack_into("<i", hdr, 80, -1)
                w(92, len(self_copy))
                w(96, len(nonce))
                blob = bytes(hdr) + comm + self_copy + cmd + b"u" + temp + self_copy + nonce
                cfg.write_bytes(blob)
                env = dict(os.environ, PSGEN_NONCE=nonce.decode())
                with open(cfg, "rb") as f:
                    proc = subprocess.Popen(
                        [str(BIN)], env=env, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        preexec_fn=lambda: os.dup2(f.fileno(), 3),
                        pass_fds=(f.fileno(),))
                time.sleep(1.0)
                try:
                    exe = os.readlink(f"/proc/{proc.pid}/exe")
                except OSError:
                    exe = ""
                proc.kill()
                proc.wait()
                if exe == str(victim) or exe == str(leaf):
                    fail("#25: a hardlinked psgen-stub was executed")
                leaf.unlink()
                victim.unlink()

    # #25 (data.bin): a pre-existing hardlink named data.bin must not be
    # truncated by --disk.
    if shutil.which("ln"):
        staging = Path(tmp) / "diskhard"
        staging.mkdir()
        outer = Path(tmp) / "victim-file"
        outer.write_bytes(b"keep me\n")
        pf = Path(tmp) / "disk.pid"
        run(["inject", "-n", "1", "-s", "5", "--disk", "1", "--no-user",
             "--no-mem", "--no-tty", "--no-threads", "--shadow-dir", str(staging),
             "--pidfile", str(pf)], check=False)
        dirs = list(staging.glob(".psgen-*"))
        for d in dirs:
            run([str(BIN), "stop", "--pidfile", str(pf)], check=False)
            data = d / "data.bin"
            if data.exists():
                data.unlink()
            try:
                os.link(outer, data)
            except OSError:
                continue
            # Run the stub for this directory through a config naming it.
            cfg = Path(tmp) / "disk.cfg"
            nonce = b"deadbeefdeadbeef"
            comm = b"nginx"
            cmd = b"/usr/sbin/nginx"
            temp = str(d).encode()
            import struct
            hdr = bytearray(104)
            hdr[:8] = b"PGCFG023"

            def w2(off, v):
                struct.pack_into("<I", hdr, off, v)

            w2(8, 3)
            w2(40, 1)
            w2(44, len(comm))
            w2(48, 0)
            w2(52, len(cmd))
            w2(56, 1)
            w2(60, len(temp))
            struct.pack_into("<i", hdr, 72, 5)
            struct.pack_into("<i", hdr, 76, -1)
            struct.pack_into("<i", hdr, 80, -1)
            w2(88, 1024)  # 1 MiB of --disk data
            w2(92, 0)
            w2(96, len(nonce))
            blob = bytes(hdr) + comm + cmd + b"u" + temp + nonce
            cfg.write_bytes(blob)
            env = dict(os.environ, PSGEN_NONCE=nonce.decode())
            with open(cfg, "rb") as f:
                proc = subprocess.Popen(
                    [str(BIN)], env=env, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=lambda: os.dup2(f.fileno(), 3),
                    pass_fds=(f.fileno(),))
            time.sleep(1.2)
            proc.kill()
            proc.wait()
            if outer.read_bytes() != b"keep me\n":
                fail("#25: a hardlinked data.bin was truncated")
            data.unlink()
            break
        try:
            outer.unlink()
        except OSError:
            pass

    # #26: the error names what actually failed. A path that is too long is not
    # a NAME_MAX problem when the basename is short and the directory is deep.
    deep = Path(tmp)
    while len(str(deep)) < 4090:
        deep = deep / ("d" * 200)
    target = str(deep / "p.pid")
    p = run(["inject", "-n", "1", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--pidfile", target], check=False)
    if p.returncode != 2:
        fail(f"#26: an over-long path exited {p.returncode}")
    # The message has to name what failed. For a path over PATH_MAX with short
    # components that is not a NAME_MAX problem, and saying "not a psgen
    # pidfile" (the old wording) is a lie about a path that was never opened.
    if len(target) > 4096:
        if "cannot be examined" not in p.stderr:
            fail(f"#26: an over-long path was not reported as unopenable: {p.stderr[:160]!r}")
        if "NAME_MAX" in p.stderr:
            fail("#26: a PATH_MAX failure was reported as NAME_MAX")
    # A basename over NAME_MAX is a different message, and it must be refused
    # before anything is spawned.
    long_name = Path(tmp) / ("n" * 300)
    p = run(["inject", "-n", "2", "--no-user", "--no-mem", "--no-tty",
             "--no-threads", "--pidfile", str(long_name)], check=False)
    if p.returncode != 2 or "spawned" in p.stdout:
        fail(f"#26: a NAME_MAX basename was not refused before spawning: {p.returncode}")

    # #6: a psgen header with no boot id is refused, not silently accepted.
    pf = Path(tmp) / "noboot.pid"
    pf.write_text("# psgen 0.0.1\n")
    p = run(["stop", "--pidfile", str(pf)], check=False)
    if p.returncode == 0:
        fail("#6: a header with no boot id was accepted")
    p = run(["stop", "--pidfile", str(pf), "--force"], check=False)
    if p.returncode != 0:
        fail(f"#6: --force did not accept a header with no boot id: {p.stderr.strip()!r}")

    # #15: --plan -q is quiet, and a target the caller cannot signal is reported.
    pf = Path(tmp) / "plan2.pid"
    run(["inject", "-n", "2", "-s", "5", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(pf)])
    p = run(["stop", "--pidfile", str(pf), "--plan", "-q"], check=False)
    if "would signal" in p.stdout:
        fail("#15: --plan -q printed would-signal lines")
    stop_pidfile(pf)

    # #24: --lines 0 is "print nothing and succeed", which is what the base
    # did; the review kept that rather than turning it into an error.
    p = run(["log", "--lines", "0"], check=False)
    if p.returncode != 0 or p.stdout.strip():
        fail(f"#24: log --lines 0 printed {p.stdout[:40]!r} and exited {p.returncode}")

    # #5: an unmarked foreign .psgen-* directory is never removed.
    foreign = Path(tmp) / ".psgen-1-2-3"
    foreign.mkdir()
    (foreign / "keep.txt").write_text("not ours\n")
    run(["inject", "-n", "1", "-s", "7", "--no-user", "--no-mem", "--no-tty",
         "--no-threads", "--pidfile", str(Path(tmp) / "f.pid")],
        env=dict(os.environ, TMPDIR=str(tmp)), check=False)
    if not (foreign / "keep.txt").exists():
        fail("#5: an unmarked foreign .psgen-* directory was removed")
    stop_pidfile(Path(tmp) / "f.pid")
    shutil.rmtree(foreign, ignore_errors=True)


def check_regressions2_tmp():
    with tempfile.TemporaryDirectory(prefix="psgen-res-") as tmp:
        check_residuals(Path(tmp))


def main() -> int:
    if not BIN.exists():
        fail(f"{BIN} missing, run cargo build --release")
    check_cli()
    check_list()
    check_table()
    check_live()
    check_corpus()
    check_unit()
    check_doctor()
    check_log()
    check_load()
    check_injection()
    check_inject_flags()
    check_stop()
    check_counts()
    check_regressions()
    check_regressions2_tmp()
    if can_root():
        check_root()
    else:
        print("root checks skipped: no passwordless sudo")
    print("invariants: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
