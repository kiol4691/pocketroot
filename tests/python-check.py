# SPDX-License-Identifier: MIT
"""zng 转发层实战验证（在 guest 的 python3 里跑）

每一项都直接对应 zng_fwd.c 里实现的某个转发钩子。
"""
import os
import sys
import tempfile
import ctypes
import subprocess
import mmap
import threading

fails = []


def ok(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  " + str(extra)) if not cond and extra else ""))
    if not cond:
        fails.append(name)


print("python:", sys.version.split()[0])
print()

# ---- realpath / pathlib（zng_fwd.c: realpath, canonicalize_file_name）----
ok("realpath", os.path.realpath("/etc") == "/etc")
try:
    import pathlib
    ok("pathlib.resolve", str(pathlib.Path("/etc").resolve()) == "/etc")
except Exception as e:
    ok("pathlib.resolve", False, e)

# ---- tempfile（zng_fwd.c: mkstemp/mkostemp 家族）----
try:
    f, p = tempfile.mkstemp()
    ok("tempfile.mkstemp", os.path.exists(p) and p.startswith("/tmp"), p)
    os.write(f, b"x")
    os.close(f)
    os.unlink(p)
except Exception as e:
    ok("tempfile.mkstemp", False, e)

try:
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(b"data")
        nm = fh.name
    ok("NamedTemporaryFile", open(nm, "rb").read() == b"data")
    os.unlink(nm)
except Exception as e:
    ok("NamedTemporaryFile", False, e)

# ---- dlopen（zng_fwd.c: dlopen 绝对路径；无斜杠走 LD_LIBRARY_PATH）----
try:
    c = ctypes.CDLL("libc.musl-aarch64.so.1")
    ok("ctypes dlopen(soname)", c.getpid() > 0)
except Exception as e:
    ok("ctypes dlopen(soname)", False, e)

try:
    # 绝对路径必须经我们的 dlopen 钩子翻译，否则按真实根解析必然失败
    c2 = ctypes.CDLL("/usr/lib/libpython3.so")
    ok("ctypes dlopen(abs path)", c2 is not None)
except Exception as e:
    ok("ctypes dlopen(abs path)", False, e)

# ---- subprocess（exec 中继 + env 回注）----
try:
    r = subprocess.run(["/bin/echo", "ok"], capture_output=True, text=True)
    ok("subprocess", r.stdout.strip() == "ok", r.stderr[:80])
except Exception as e:
    ok("subprocess", False, e)

try:
    # 空 env：验证 execve 强制回注（gate3 等价场景）
    r = subprocess.run(["/bin/busybox", "echo", "ok"], env={}, capture_output=True, text=True)
    ok("subprocess empty-env", r.stdout.strip() == "ok", r.stderr[:80])
except Exception as e:
    ok("subprocess empty-env", False, e)

try:
    # PATH 搜索（无斜杠）
    r = subprocess.run(["echo", "ok"], capture_output=True, text=True)
    ok("subprocess PATH search", r.stdout.strip() == "ok", r.stderr[:80])
except Exception as e:
    ok("subprocess PATH search", False, e)

# ---- mmap / 大文件 ----
try:
    with open("/tmp/big.bin", "wb") as fh:
        fh.truncate(4 * 1024 * 1024)
    with open("/tmp/big.bin", "r+b") as fh:
        m = mmap.mmap(fh.fileno(), 4096)
        m[0:4] = b"ZNG!"
        ok("mmap rw", m[0:4] == b"ZNG!")
        m.close()
    ok("truncate size", os.path.getsize("/tmp/big.bin") == 4 * 1024 * 1024)
    os.unlink("/tmp/big.bin")
except Exception as e:
    ok("mmap", False, e)

# ---- 线程 / 进程 ----
try:
    res = []
    ths = [threading.Thread(target=lambda: res.append(1)) for _ in range(8)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    ok("threading x8", len(res) == 8)
except Exception as e:
    ok("threading", False, e)

try:
    pid = os.fork()
    if pid == 0:
        os._exit(7)
    _, st = os.waitpid(pid, 0)
    ok("fork+waitpid", os.WEXITSTATUS(st) == 7)
except Exception as e:
    ok("fork", False, e)

# ---- glob / scandir（zng_fwd.c: glob, scandir；opendir 在 hooks 里）----
try:
    import glob
    ok("glob /etc/host*", len(glob.glob("/etc/host*")) >= 1)
except Exception as e:
    ok("glob", False, e)

try:
    ok("os.listdir /etc", "passwd" in os.listdir("/etc"))
except Exception as e:
    ok("listdir", False, e)

try:
    ok("os.scandir /etc", any(e.name == "passwd" for e in os.scandir("/etc")))
except Exception as e:
    ok("scandir", False, e)

# ---- stat / statvfs ----
try:
    st = os.stat("/etc/passwd")
    ok("os.stat", st.st_size > 0)
except Exception as e:
    ok("os.stat", False, e)

try:
    ok("os.statvfs", os.statvfs("/").f_blocks > 0)
except Exception as e:
    ok("statvfs", False, e)

# ---- 读写 / 目录操作 ----
try:
    os.makedirs("/tmp/pytest/d1/d2", exist_ok=True)
    open("/tmp/pytest/f", "w").write("hello")
    ok("mkdir+write+read", open("/tmp/pytest/f").read() == "hello")
    os.rename("/tmp/pytest/f", "/tmp/pytest/f2")
    ok("rename", os.path.exists("/tmp/pytest/f2"))
    import shutil
    shutil.rmtree("/tmp/pytest")
except Exception as e:
    ok("fs ops", False, e)

print()
if fails:
    print("FAILED: %d -> %s" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("ALL PASS")
