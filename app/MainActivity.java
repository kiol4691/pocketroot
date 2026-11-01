/* SPDX-License-Identifier: MIT */
package com.pocketroot;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Log;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * pocketroot 测试终端。
 *
 * 与 zroot-lab 的关键差异：
 *
 *  1. 【设备端不再打 musl 补丁】
 *     zroot-lab 在每次解包后于设备上扫描并改写 libc（命中数 != 1 就不写盘，
 *     但上层继续跑 —— 0.1.3 为此多花了一整轮才定位到）。
 *     这里补丁在**构建期**由 tools/patch-musl.py 一次性完成并生成清单；
 *     设备端只做 SHA-256 校验，不匹配就明确报警。
 *     失败模式从"用户设备上的静默降级"变成"构建期的硬失败"。
 *
 *  2. 【日志不污染 stderr】
 *     zroot-lab 0.1.8 把 ZROOT_DEBUG 常开并打到 stderr，导致 shell 正常输出
 *     与 relay 日志混在一起。这里通过 ZNG_LOG 把 shim 日志写到独立文件，
 *     UI 上另有"查看 shim 日志"入口。
 *
 *  3. 其余沿用 zroot-lab 已验证的做法：targetSdk 28（W^X 豁免）、
 *     经 ldso 命令行模式启动 ash、LD_PRELOAD 注入、三门禁自检。
 */
public class MainActivity extends Activity {

    private static final String TAG = "pocketroot";

    /** 无 lambda：platform-28 的 android.jar 缺 LambdaMetafactory。 */
    private interface Act { void run(); }

    private TextView log;
    private EditText input;
    private Process proc;
    private OutputStream stdin;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private boolean selftest;
    /** 排障开关：am start ... --ez lddebug true —— 让 glibc 的 ld.so 打加载器日志。 */
    private boolean ldDebug;
    /** 排障开关：--ez noshim true —— 不注入 shim，用来区分"死在 glibc 自己"还是"死在 shim"。 */
    private boolean noShim;
    /** --ez stress true —— 启动后在 guest 里跑线程密集压测（tools/zthreads.c）。 */
    private boolean stress;
    /** --ez torch true —— 在 guest 里跑 torch 冒烟测试。 */
    private boolean torchTest;
    /** --es run <cmd> —— 启动 shell 后直接执行一条命令（通用测试入口）。 */
    private String runCmd;
    /** --ez rootfs <abs path> —— 用设备上已存在的 rootfs（免解包，供大 rootfs 测试）。 */
    private boolean externalRootfs;
    private File rootfs;
    private File logFile;
    private File shellLog;

    /*
     * rootfs 风味（musl / glibc）在运行时自动识别，而不是编译期写死：
     *   - 资源名决定解包哪个 tarball（build.sh --glibc 会改用 glibc-rootfs.tar.gz）；
     *   - 加载器名决定用哪个 ld.so 启动（内核解不了 rootfs 内的 PT_INTERP）。
     * 这样同一个 APK 源码既能出 Alpine 变体也能出 Alpaquita 变体，
     * 不需要生成 BuildConfig 之类的代码。
     */
    private static final String ASSET_MUSL  = "alpine-rootfs.tar.gz";
    private static final String ASSET_GLIBC = "glibc-rootfs.tar.gz";
    private static final String LD_MUSL     = "lib/ld-musl-aarch64.so.1";
    private static final String LD_GLIBC    = "lib/ld-linux-aarch64.so.1";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        rootfs = new File(getFilesDir(), "rootfs");
        logFile = new File(getFilesDir(), "zng.log");
        // shell 的完整输出落盘：部分 ROM 屏蔽三方 App 的 logcat，
        // 这是排障时能拿到 guest 侧实际输出的可靠通道。
        shellLog = new File(getFilesDir(), "shell.log");
        // adb 触发自检：am start ... --ez selftest true
        selftest = getIntent().getBooleanExtra("selftest", false);
        ldDebug = getIntent().getBooleanExtra("lddebug", false);
        noShim = getIntent().getBooleanExtra("noshim", false);
        stress = getIntent().getBooleanExtra("stress", false);
        torchTest = getIntent().getBooleanExtra("torch", false);
        runCmd = getIntent().getStringExtra("run");
        String ext = getIntent().getStringExtra("rootfs");
        if (ext != null && ext.length() > 0) {
            /*
             * 大 rootfs（如带 python+torch 的、150 MB+）不适合打进 APK：
             * 允许直接指向设备上已有的目录。此时 app 对它没有写权限，
             * 所以跳过解包、跳过 .zng-ready 与 assets 复制（见 isReady）。
             */
            rootfs = new File(ext);
            externalRootfs = true;
        }
        buildUi();

        String ver;
        try { ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName; }
        catch (Exception e) { ver = "?"; }

        append("[zng] pocketroot v" + ver + "\n");
        append("[zng] rootfs=" + rootfs.getAbsolutePath() + (externalRootfs ? "（外部）" : "") + "\n");

        if (getIntent().getBooleanExtra("probe", false)) {
            // 诊断入口：am start ... --ez probe true
            // 只需要 seccomp 环境，不需要 rootfs —— 尽早返回。
            runProbe();
            return;
        }

        if (isReady()) {
            append("[zng] rootfs 已就绪\n");
            // 幂等：每次启动都确保自检脚本在位。rootfs 只在首次运行时解包，
            // 若把复制只放在解包流程里，升级 APK 后旧数据里就没有新脚本。
            if (!externalRootfs) {              /* 外部 rootfs 对 app 只读 */
                copyAsset("guest-check.sh", new File(rootfs, "root/guest-check.sh"));
                copyStressBinary();
            }
            verifyMuslPatch();
            startShell();
        } else if (externalRootfs) {
            /* 外部 rootfs 不完整时**绝不能**回落到解包：那会把 APK 里的 rootfs
             * 解到用户指定的目录上，覆盖掉人家的树（实测踩过一次）。 */
            append("[zng] 外部 rootfs 不可用：找不到加载器（" + rootfs.getAbsolutePath() + "）\n");
            return;
        } else {
            append("[zng] 首次运行：解包 Alpine rootfs...\n");
            new Thread(new Runnable() {
                public void run() { setupRootfs(); }
            }).start();
        }
    }

    /* ---------------- UI ---------------- */

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF10141A);
        root.setPadding(dp(8), dp(8), dp(8), dp(8));

        TextView title = new TextView(this);
        title.setText("pocketroot  ·  rootfs sandbox  ·  zero-ptrace");
        title.setTextColor(0xFF7FDBCA);
        title.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        title.setPadding(dp(4), dp(6), dp(4), dp(6));
        root.addView(title);

        log = new TextView(this);
        log.setTextColor(0xFFD8E0E8);
        log.setTextSize(11.5f);
        log.setTypeface(Typeface.MONOSPACE);
        log.setMovementMethod(ScrollingMovementMethod.getInstance());
        log.setTextIsSelectable(true);
        ScrollView scroller = new ScrollView(this);
        scroller.addView(log, new ViewGroup.LayoutParams(-1, -2));
        root.addView(scroller, new LinearLayout.LayoutParams(-1, 0, 1f));

        LinearLayout inRow = new LinearLayout(this);
        inRow.setOrientation(LinearLayout.HORIZONTAL);
        input = new EditText(this);
        input.setHint("输入 shell 命令…");
        input.setSingleLine(true);
        input.setTextColor(0xFFD8E0E8);
        input.setTextSize(12);
        input.setTypeface(Typeface.MONOSPACE);
        inRow.addView(input, new LinearLayout.LayoutParams(0, -2, 1f));
        inRow.addView(mkBtn("发送", 0xFF2A6F6A, new Act() {
            public void run() { sendInput(); }
        }));
        root.addView(inRow);

        root.addView(row(
                mkBtn("▶ 启动shell", 0xFF245A7A, new Act() {
                    public void run() { startShell(); }
                }),
                mkBtn("三门禁自检", 0xFF7A5A24, new Act() {
                    public void run() { runGates(); }
                }),
                mkBtn("重置rootfs", 0xFF5A2A2A, new Act() {
                    public void run() { resetRootfs(); }
                })));
        root.addView(row(
                mkBtn("ls /", 0xFF22303A, "ls /"),
                mkBtn("cat os-release", 0xFF22303A, "cat /etc/os-release"),
                mkBtn("uname -a", 0xFF22303A, "uname -a"),
                mkBtn("apk --version", 0xFF22303A, "/sbin/apk --version")));
        root.addView(row(
                mkBtn("env -i 穿透", 0xFF22303A, "env -i /bin/ls /; echo rc=$?"),
                mkBtn("shebang", 0xFF22303A,
                        "printf '#!/bin/sh\\necho shebang-ok $0\\n' > /tmp/s.sh; chmod +x /tmp/s.sh; /tmp/s.sh"),
                mkBtn("readlink exe", 0xFF22303A, "readlink /proc/self/exe"),
                mkBtn("pwd -P", 0xFF22303A, "pwd -P")));
        root.addView(row(
                mkBtn("写文件+读回", 0xFF22303A,
                        "echo zng-$(date +%s) > /tmp/f && cat /tmp/f && ls -l /tmp/f"),
                mkBtn("shim 日志", 0xFF3A3A22, new Act() {
                    public void run() { showShimLog(); }
                }),
                mkBtn("校验补丁", 0xFF4A2A4A, new Act() {
                    public void run() { verifyMuslPatch(); }
                }),
                mkBtn("清屏", 0xFF22303A, new Act() {
                    public void run() { log.setText(""); }
                })));

        setContentView(root);
    }

    private LinearLayout row(Button... btns) {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.HORIZONTAL);
        for (Button b : btns) l.addView(b, new LinearLayout.LayoutParams(0, -2, 1f));
        return l;
    }

    private Button mkBtn(String text, int color, final String cmd) {
        return mkBtn(text, color, new Act() {
            public void run() { sendLine(cmd); }
        });
    }

    private Button mkBtn(String text, int color, final Act a) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextSize(11);
        b.setTextColor(0xFFE8E8E8);
        b.setBackgroundColor(color);
        b.setPadding(dp(6), dp(2), dp(6), dp(2));
        b.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { a.run(); }
        });
        return b;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private void append(final String s) {
        // 同时输出到 logcat：UI 上的内容无法从 adb 侧读取，而真机排障
        // （尤其是 exit=159/SIGSYS 这类）必须有可观测的输出通道。
        Log.d(TAG, stripAnsi(s));
        runOnUiThread(new Runnable() {
            public void run() {
                String cur = log.getText().toString();
                String next = cur + stripAnsi(s);
                if (next.length() > 200000) next = next.substring(next.length() - 150000);
                log.setText(next);
            }
        });
    }

    private static String stripAnsi(String s) {
        return s.replaceAll("\u001B\\[[0-9;?]*[A-Za-z]", "")
                .replaceAll("\r\n", "\n").replace('\r', '\n');
    }

    /* ---------------- musl 补丁校验（构建期已打好，这里只验） ---------------- */

    /**
     * 校验 assets 里的 patch-manifest.json 与实际文件哈希是否一致。
     * 只有不一致才报警 —— 正常情况下这里是零成本的（只读一次清单）。
     */
    private void verifyMuslPatch() {
        // glibc rootfs 不走构建期 musl 补丁（补丁目标是 musl 的 libc.so 里
        // 直接发 syscall 的机器码，glibc 没有这段），因此清单不存在是正常的。
        if (!hasAsset("patch-manifest.json")) {
            append("[zng] 无 patch-manifest.json —— 该变体未做构建期 seccomp 补丁\n");
            return;
        }
        append("[zng] 校验构建期 seccomp 补丁...\n");
        InputStream in = null;
        try {
            in = getAssets().open("patch-manifest.json");
            byte[] buf = new byte[in.available()];
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n < 0) break;
                off += n;
            }
            String json = new String(buf, 0, off, StandardCharsets.UTF_8);

            // 极简 JSON 提取：只取 "real" 与 "sha256_after"（避免引入依赖）
            int i = 0;
            boolean allOk = true;
            int checked = 0;
            while ((i = json.indexOf("\"real\"", i)) >= 0) {
                String real = jsonValue(json, i + 6);
                int j = json.indexOf("\"sha256_after\"", i);
                if (j < 0) break;
                String want = jsonValue(json, j + 14);
                if (real == null || want == null) break;

                File f = new File(rootfs, real);
                String got = sha256(f);
                checked++;
                if (got == null) {
                    append("[zng] ⚠ 补丁目标缺失: " + real + "\n");
                    allOk = false;
                } else if (!got.equalsIgnoreCase(want)) {
                    append("[zng] ⚠ 补丁哈希不匹配: " + real
                            + "\n[zng]   期望 " + want.substring(0, 16)
                            + "…\n[zng]   实际 " + got.substring(0, 16) + "…\n");
                    allOk = false;
                }
                i = j + 14;
            }
            if (checked == 0) {
                append("[zng] ⚠ 清单中无可用条目（构建期补丁是否执行过？）\n");
            } else if (allOk) {
                append("[zng] 补丁校验通过 ✓（" + checked + " 个目标）\n");
            } else {
                append("[zng] ⚠⚠ 补丁未生效：musl 内部 faccessat2/statx 会触发 SIGSYS(159)\n");
            }
        } catch (IOException e) {
            append("[zng] ⚠ 未找到 patch-manifest.json —— 构建期补丁可能未执行\n");
        } finally {
            closeQuietly(in);
        }
    }

    /** 从 JSON 的 `:"..."` 形式中取出字符串值；返回 null 表示解析失败。 */
    private static String jsonValue(String s, int from) {
        int c = s.indexOf(':', from);
        if (c < 0) return null;
        int q1 = s.indexOf('"', c);
        if (q1 < 0) return null;
        int q2 = s.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return s.substring(q1 + 1, q2);
    }

    private static String sha256(File f) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            java.io.FileInputStream fi = new java.io.FileInputStream(f);
            try {
                byte[] b = new byte[1 << 16];
                int n;
                while ((n = fi.read(b)) > 0) md.update(b, 0, n);
            } finally {
                fi.close();
            }
            byte[] d = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte x : d) sb.append(String.format("%02x", x));
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private void showShimLog() {
        if (!logFile.exists()) { append("[zng] 尚无 shim 日志\n"); return; }
        append("\n[zng] ===== shim 日志（" + logFile + "） =====\n");
        try {
            byte[] b = readAll(logFile);
            String s = new String(b, StandardCharsets.UTF_8);
            if (s.length() > 8000) s = "…" + s.substring(s.length() - 8000);
            append(s + "\n");
        } catch (Exception e) {
            append("[zng] 读取失败: " + e + "\n");
        }
    }

    /* ---------------- 压测 ---------------- */

    /** 把 assets/zthreads 放进 rootfs（guest 里可直接执行）。musl 变体不含此资产。 */
    private void copyStressBinary() {
        if (!hasAsset("zthreads")) return;
        File dst = new File(rootfs, "root/zthreads");
        copyAsset("zthreads", dst);
        dst.setExecutable(true, false);
    }

    /**
     * 线程密集压测：刻意压 clone3->clone 回退、rseq 关闭后的 TLS、
     * set_robust_list 被伪装成功这三条被补丁改过的路径。
     */
    private void scheduleStress() {
        new Thread(new Runnable() {
            public void run() {
                try { Thread.sleep(3000); } catch (InterruptedException ignored) { }
                sendLine("echo '###### STRESS BEGIN ######'");
                sendLine("chmod +x /root/zthreads");
                sendLine("/root/zthreads 32 100; echo \"rc=$?\"");
                sendLine("/root/zthreads 64 200; echo \"rc=$?\"");
                sendLine("echo '###### STRESS END ######'");
            }
        }).start();
    }

    /* ---------------- torch ---------------- */

    /**
     * PyTorch 冒烟测试：矩阵乘 / autograd / conv2d。
     * 脚本由调用方放在 rootfs 的 /root/torch_smoke.py（rootfs 可能对 app 只读）。
     */
    private void scheduleTorch() {
        new Thread(new Runnable() {
            public void run() {
                try { Thread.sleep(3000); } catch (InterruptedException ignored) { }
                sendLine("echo '###### TORCH BEGIN ######'");
                sendLine("OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 /usr/bin/python3 -u -c \"print('A',flush=True); import torch; print('B', torch.__version__, flush=True)\"; echo rc=$?");
                sendLine("cd /root && LD_DEBUG=libs /usr/bin/python3 -u torch_smoke.py >/tmp/t.out 2>/tmp/t.err; echo \"rc=$?\"");
                sendLine("echo '--- t.out ---'; tail -6 /tmp/t.out 2>&1");
                sendLine("echo '--- t.err ---'; tail -8 /tmp/t.err 2>&1");
                sendLine("echo '###### TORCH END ######'");
            }
        }).start();
    }

    /* ---------------- zprobe ---------------- */

    /**
     * 在 **App 进程**（带 zygote seccomp 过滤器）里逐条探测 syscall。
     * 子进程由 App fork+exec，因此继承同一套过滤器 —— 这正是 adb shell
     * 无法复现的条件（shell 的 Seccomp=0）。
     */
    private void runProbe() {
        append("[zng] zprobe：本进程 seccomp 下的 syscall 探测\n");
        new Thread(new Runnable() {
            public void run() {
                File exe = new File(getFilesDir(), "zprobe");
                try {
                    copyAsset("zprobe", exe);
                    exe.setExecutable(true, false);
                    /* --es probearg range 走全量扫描（只打印被拦的），否则用精选表。 */
                    String pa = getIntent().getStringExtra("probearg");
                    ProcessBuilder pb = (pa != null && pa.length() > 0)
                            ? new ProcessBuilder(exe.getAbsolutePath(), pa)
                            : new ProcessBuilder(exe.getAbsolutePath());
                    pb.redirectErrorStream(true);
                    Process p = pb.start();
                    StringBuilder sb = new StringBuilder();
                    InputStream in = p.getInputStream();
                    byte[] b = new byte[4096];
                    int n;
                    while ((n = in.read(b)) > 0) {
                        sb.append(new String(b, 0, n, StandardCharsets.UTF_8));
                    }
                    p.waitFor();
                    String s = sb.toString();
                    writeFile(new File(getFilesDir(), "probe.log"), s);
                    append(s);
                    append("[zng] probe exit=" + p.exitValue() + "\n");
                } catch (Exception e) {
                    append("[zng] probe 失败：" + e + "\n");
                }
            }
        }).start();
    }

    /* ---------------- rootfs ---------------- */

    private boolean isReady() {
        File ldso = ldso();
        if (ldso == null || !ldso.canExecute()) return false;
        if (externalRootfs) return true;        /* 外部 rootfs 没有 .zng-ready */
        return new File(rootfs, ".zng-ready").exists();
    }

    /** 当前 rootfs 的加载器（glibc 优先探测，两者不会同时存在）。未就绪时返回 null。 */
    private File ldso() {
        for (String p : new String[] { LD_GLIBC, LD_MUSL }) {
            File f = new File(rootfs, p);
            if (f.exists()) return f;
        }
        return null;
    }

    private boolean isGlibc() {
        File l = ldso();
        return l != null && l.getName().startsWith("ld-linux");
    }

    /**
     * rootfs 的发行版名（只用于 UI/提示文案）。按内容判断，不写死：
     * Debian 系把运行时库放在 multiarch 子目录里，busybox 系没有这个目录。
     */
    private String distroName() {
        if (new File(rootfs, "usr/lib/aarch64-linux-gnu").isDirectory())
            return "Debian/Ubuntu (glibc)";
        return rootfsAsset().equals(ASSET_GLIBC) ? "Alpaquita (glibc)" : "Alpine (musl)";
    }

    /** APK 里实际打包的 rootfs 资源名。 */
    private String rootfsAsset() {
        return hasAsset(ASSET_MUSL) ? ASSET_MUSL : ASSET_GLIBC;
    }

    /** assets 里是否存在该文件（用打开试探，比列目录可靠，且 OOM 无关）。 */
    private boolean hasAsset(String name) {
        InputStream in = null;
        try {
            in = getAssets().open(name);
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            closeQuietly(in);
        }
    }

    private void setupRootfs() {
        try {
            rootfs.mkdirs();
            InputStream in = getAssets().open(rootfsAsset());
            java.util.zip.GZIPInputStream gz =
                    new java.util.zip.GZIPInputStream(in, 1 << 16);
            TarExtractor tx = new TarExtractor(rootfs, new TarExtractor.Progress() {
                public void onEntry(String name, long total, long count) {
                    if (count % 64 == 0) append("  …" + name + "\n");
                }
            });
            tx.extract(gz);
            gz.close();
            append("[zng] symlink 改写 " + tx.rewrittenCount() + " 个\n");

            // 构建期已打过补丁，这里只校验
            verifyMuslPatch();

            writeFile(new File(rootfs, "etc/resolv.conf"),
                    "nameserver 8.8.8.8\nnameserver 1.1.1.1\n");
            writeFile(new File(rootfs, "etc/motd"),
                    "Welcome to pocketroot\n"
                  + (distroName() + " aarch64 inside an Android app")
                  + ", via LD_PRELOAD path translation.\n"
                  + "Zero ptrace. Use the buttons above for the three gates.\n");

            // guest 端自检脚本：App 环境里可直接 `sh /root/guest-check.sh`，
            // 无需从 adb push（rootfs 是 App 私有目录，adb 侧写不进去）。
            copyAsset("guest-check.sh", new File(rootfs, "root/guest-check.sh"));
            copyStressBinary();

            new File(rootfs, ".zng-ready").createNewFile();
            append("[zng] rootfs 解包完成 ✓\n");
            startShell();
        } catch (Exception e) {
            append("[zng] 解包失败：" + e + "\n");
        }
    }

    private void resetRootfs() {
        stopShell();
        new Thread(new Runnable() {
            public void run() {
                append("[zng] 删除旧 rootfs...\n");
                rmrf(rootfs);
                setupRootfs();
            }
        }).start();
    }

    private static void rmrf(File f) {
        File[] ls = f.listFiles();
        if (ls != null) for (File c : ls) rmrf(c);
        f.delete();
    }

    /** 把 APK assets 里的文件复制到 rootfs 内（rootfs 是 App 私有目录，adb 侧写不进去）。 */
    private void copyAsset(String name, File dst) {
        InputStream in = null;
        FileOutputStream out = null;
        try {
            File parent = dst.getParentFile();
            if (parent != null) parent.mkdirs();
            in = getAssets().open(name);
            out = new FileOutputStream(dst);
            byte[] b = new byte[1 << 16];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
        } catch (IOException e) {
            append("[zng] 复制 " + name + " 失败：" + e + "\n");
        } finally {
            closeQuietly(in);
            closeQuietly(out);
        }
    }

    private static void writeFile(File f, String s) throws IOException {
        Writer w = new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8);
        try { w.write(s); } finally { w.close(); }
    }

    private static byte[] readAll(File f) throws IOException {
        java.io.FileInputStream fi = new java.io.FileInputStream(f);
        try {
            byte[] b = new byte[(int) f.length()];
            int off = 0;
            while (off < b.length) {
                int n = fi.read(b, off, b.length - off);
                if (n < 0) break;
                off += n;
            }
            return b;
        } finally {
            fi.close();
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c == null) return;
        try { c.close(); } catch (IOException ignored) { }
    }

    /* ---------------- shell ---------------- */

    private void startShell() {
        stopShell();
        if (!isReady()) { append("[zng] rootfs 未就绪\n"); return; }

        File ld = ldso();
        if (ld == null) { append("[zng] 未找到加载器（musl/glibc 都没有）\n"); return; }
        File lib = new File(getApplicationInfo().nativeLibraryDir, "libzng.so");

        if (!lib.canExecute()) {
            append("[zng] 未找到 " + lib + "（extractNativeLibs 未生效？）\n");
            return;
        }
        /*
         * 不再写死 ash/busybox：Alpine 用 busybox，Alpaquita 用 busybox，
         * Ubuntu/Debian 只有 bash 与 dash(/bin/sh)。按可用性挑一个。
         * File.exists() 跟随符号链接，链断即为 false —— 顺带覆盖了
         * "悬空 symlink" 的自检（busybox rootfs 解包失败时的典型症状）。
         */
        File shell = null;
        for (String c : new String[] { "bin/ash", "bin/bash", "bin/sh" }) {
            File f = new File(rootfs, c);
            if (f.exists()) { shell = f; break; }
        }
        if (shell == null) {
            append("[zng] rootfs 里没有可用的 shell（ash/bash/sh 都不可解析）\n"
                 + "[zng] 请点「重置rootfs」重新解包\n");
            return;
        }

        try {
            /* 不带 -l：login shell 只在交互场景有意义，这里 stdin 是管道，
             * 且 PATH/HOME 等都由下面显式注入。dash 也不支持 -l。 */
            ProcessBuilder pb = new ProcessBuilder(
                    ld.getAbsolutePath(), shell.getAbsolutePath());
            java.util.Map<String, String> e = pb.environment();

            if (!noShim) {
                e.put("LD_PRELOAD", lib.getAbsolutePath());
                e.put("ZNG_PRELOAD", lib.getAbsolutePath());
                e.put("ZNG_ROOT", rootfs.getAbsolutePath());
            }
            /*
             * glibc 与 musl 的库搜索路径必须分开：
             * glibc rootfs 的 /usr/lib 里放的是**编译期**的 GNU ld script
             * （libm.so 是文本），进去会让 ld.so 报 "bad ELF magic"；
             * 运行时库都在 /lib 与 /lib64。musl 没有这个区分。
             */
            String libPath;
            if (isGlibc()) {
                libPath = rootfs.getAbsolutePath() + "/lib:" + rootfs.getAbsolutePath() + "/lib64";
                // Debian/Ubuntu 把运行时库放在 multiarch 子目录里（Alpaquita 没有）。
                File multi = new File(rootfs, "usr/lib/aarch64-linux-gnu");
                if (multi.isDirectory()) libPath += ":" + multi.getAbsolutePath();
            } else {
                libPath = rootfs.getAbsolutePath() + "/lib:" + rootfs.getAbsolutePath() + "/usr/lib";
            }
            e.put("LD_LIBRARY_PATH", libPath);
            /*
             * App 进程带着 zygote 的 seccomp 过滤器（adb shell 没有）。
             * glibc 2.35+ 启动时会给主线程注册 rseq(334) 做 TLS 快速路径，
             * 该 syscall 不在 app 白名单里 -> 直接 SIGSYS(159)，连 ENOSYS 都
             * 拿不到，也就没有 fallback。用 tunable 关掉即可（退化为普通 TLS）。
             * 实测：不开这个，glibc rootfs 在 app 里启动即 exit=159。
             */
            if (isGlibc()) e.put("GLIBC_TUNABLES", "glibc.pthread.rseq=0");
            // 定位 SIGSYS 用：LD_DEBUG 会在死前把加载器进展打到 stderr，
            // 由 pump 落进 shell.log，能看出死在哪个阶段。
            if (isGlibc() && ldDebug) e.put("LD_DEBUG", "all");
            /*
             * /dev /proc /sys 必须 bind 到宿主，否则 guest 里的工具
             * （ps、mount、读取 /proc/self/*）会指向 rootfs 内的空目录。
             * 格式："host\tguest\n" 多条，与 shim 的 parse_binds 一致。
             */
            e.put("ZNG_BINDS", "/dev\t/dev\n/proc\t/proc\n/sys\t/sys");
            e.put("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
            e.put("HOME", "/root");
            e.put("TERM", "xterm");
            e.put("LANG", "C");
            e.put("SHELL", "/bin/sh");
            e.put("USER", "root");
            e.put("LOGNAME", "root");
            e.put("TMPDIR", "/tmp");

            /*
             * 关键差异：shim 日志写文件而不是 stderr。
             * zroot-lab 0.1.8 把 debug 常开打到 stderr，shell 输出与 relay
             * 日志混在一起；这里两者分离，需要取证时点「shim 日志」即可。
             */
            e.put("ZNG_DEBUG", "1");
            e.put("ZNG_LOG", logFile.getAbsolutePath());

            pb.directory(rootfs);               // 初始 cwd = rootfs（即 guest "/"）
            pb.redirectErrorStream(true);
            proc = pb.start();
            stdin = proc.getOutputStream();
            running.set(true);

            append("[zng] shell 启动: flavor=" + (isGlibc() ? "glibc" : "musl")
                    + " ldso=" + ld + " preload=" + lib + "\n");
            // 每次重启截断 shell.log，避免多轮日志混在一起难以定位
            try { new FileOutputStream(shellLog).close(); } catch (IOException ignored) { }
            pump(proc.getInputStream(), proc);
            sendLine("cat /etc/motd 2>/dev/null");
            if (selftest) scheduleSelfTest();
            if (stress) scheduleStress();
            if (torchTest) scheduleTorch();
            if (runCmd != null && runCmd.length() > 0) {
                final String cmd = runCmd;
                new Thread(new Runnable() {
                    public void run() {
                        try { Thread.sleep(2000); } catch (InterruptedException ignored) { }
                        sendLine("echo \"###### RUN BEGIN ######\"");
                        sendLine(cmd);
                        sendLine("echo \"rc=$?\"");
                        sendLine("echo \"###### RUN END ######\"");
                    }
                }).start();
            }
        } catch (IOException ex) {
            append("[zng] 启动失败：" + ex + "（W^X 门禁？需 targetSdk≤28）\n");
        }
    }

    private void pump(final InputStream in, final Process p) {
        new Thread(new Runnable() {
            public void run() {
                byte[] buf = new byte[4096];
                FileOutputStream dump = null;
                try {
                    dump = new FileOutputStream(shellLog, true);
                } catch (IOException ignored) { }
                try {
                    int n;
                    while (running.get() && (n = in.read(buf)) > 0) {
                        append(new String(buf, 0, n, StandardCharsets.UTF_8));
                        if (dump != null) {
                            try {
                                dump.write(buf, 0, n);
                                dump.flush();
                            } catch (IOException ignored) { }
                        }
                    }
                } catch (IOException ignored) { }
                closeQuietly(dump);

                running.set(false);
                int code = -1;
                try { code = p.exitValue(); } catch (Exception ignored) { }

                if (proc == p) {
                    append("\n[zng] shell 已退出（exit=" + code + "）\n");
                    if (code == 159) {
                        append("[zng] ⚠ SIGSYS 检出。可能原因：\n"
                             + "[zng]   1) musl 补丁未生效 —— 点「校验补丁」\n"
                             + "[zng]   2) shim 自身发起了被禁 syscall —— 查看 shim 日志\n"
                             + "[zng]   3) 新的 seccomp 限制 —— 用 zprobe 逐项探测\n");
                    }
                }
            }
        }).start();
    }

    /*
     * 完整自检（对应 tests/guest-check.sh 的核心项）。
     * 由 `adb shell am start -n com.pocketroot/.MainActivity --ez selftest true`
     * 触发。UI 上的输出无法从 adb 侧读取，所以这里的结果落在 shell.log，
     * 便于脚本化验证与回归。
     */
    private void scheduleSelfTest() {
        new Thread(new Runnable() {
            public void run() {
                try { Thread.sleep(3000); } catch (InterruptedException ignored) { }
                sendLine("echo '###### SELFTEST BEGIN ######'");
                /* 门禁一的本质是"能在 app 私有目录 exec 一个动态链接的 ELF"，
                 * 不绑定具体包管理器：Alpine/Alpaquita 有 apk，Ubuntu 有 dpkg。 */
                sendLine("echo '--- gate1: W^X exec (pkg) ---'; "
                        + "{ command -v apk >/dev/null 2>&1 && apk --version; } "
                        + "|| { command -v dpkg >/dev/null 2>&1 && dpkg --version | head -1; } "
                        + "|| echo '(无包管理器，改用 ls)'; ls / >/dev/null; echo rc=$?");
                sendLine("echo '--- gate2: /proc/self/exe ---'; readlink /proc/self/exe; echo rc=$?");
                /* gate3 需要一个真实可执行文件：busybox 发行版有 /bin/busybox，
                 * Debian/Ubuntu 只有 coreutils 的 /usr/bin/true（shell 内建 true 不算）。 */
                sendLine("echo '--- gate3: env -i 自净对抗 ---'; "
                        + "T=/bin/busybox; [ -x $T ] || T=/usr/bin/true; [ -x $T ] || T=/bin/true; "
                        + "env -i \"$T\" true; echo rc=$?");
                // 注意 $0 前不要加反斜杠：printf 不认识 "\$"，会把反斜杠
                // 一并写进脚本，导致 $0 变成字面量而不展开。
                sendLine("echo '--- shebang ---'; printf '#!/bin/sh\\necho sb-ok 0=$0\\n' > /tmp/s.sh; chmod +x /tmp/s.sh; /tmp/s.sh; echo rc=$?");
                sendLine("echo '--- write+read ---'; echo w-ok > /tmp/w.txt; cat /tmp/w.txt; echo rc=$?");
                sendLine("echo '--- PATH exec ---'; uname -a; echo rc=$?");
                sendLine("echo '--- /proc bind ---'; ls /proc/self/ 2>&1 | head -3; echo rc=$?");
                sendLine("echo '--- 隔离性(不应看到 /system) ---'; ls /system 2>&1 | head -1; echo rc=$?");
                sendLine("echo '--- 包管理器索引 ---'; "
                        + "if [ -x /sbin/apk ]; then /sbin/apk info 2>&1 | head -3; "
                        + "elif command -v dpkg >/dev/null 2>&1; then dpkg -l 2>&1 | head -3; "
                        + "else echo '(无)'; fi; echo rc=$?");
                /*
                 * 先 apk update 再 apk add：仓库索引（APKINDEX）不在 rootfs 里，
                 * 不 update 会直接报 "python3 (no such package)"。
                 * 有网时这会真正覆盖下面的 Python 组；无网时该组 SKIP ——
                 * SKIP 表示未覆盖，不是通过。
                 */
                /* 只在 apk 系统上跑（Ubuntu 有 apt，但装包要网络且很慢，自检里不做）。 */
                sendLine("echo '--- apk update（需网络，仅 apk 系统）---'; "
                        + "[ -x /sbin/apk ] && /sbin/apk update 2>&1 | tail -3 || echo '无 apk，跳过'");
                sendLine("echo '--- 安装 python3 ---'; "
                        + "command -v python3 >/dev/null 2>&1 && echo 'python3 已安装' "
                        + "|| { [ -x /sbin/apk ] && /sbin/apk add --no-cache python3 2>&1 | tail -5; } "
                        + "|| echo '无 apk，跳过'");
                // 完整 guest 自检（含 Python 组）
                sendLine("echo '--- guest-check.sh ---'; sh /root/guest-check.sh 2>&1");
                sendLine("echo '###### SELFTEST END ######'");
            }
        }).start();
    }

    private void sendInput() {
        sendLine(input.getText().toString());
        input.setText("");
    }

    private void sendLine(String line) {
        if (stdin == null || !running.get()) { append("[zng] 先启动 shell\n"); return; }
        try {
            stdin.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            stdin.flush();
        } catch (IOException e) {
            append("[zng] 写入失败：" + e + "\n");
        }
    }

    private void stopShell() {
        running.set(false);
        if (proc != null) { proc.destroy(); proc = null; stdin = null; }
    }

    @Override
    protected void onDestroy() { stopShell(); super.onDestroy(); }

    /* ---------------- 三门禁 ---------------- */

    private void runGates() {
        if (!running.get()) { append("[zng] 先启动 shell\n"); return; }
        append("\n[zng] ===== 三门禁自检开始 =====\n");

        // 门禁一：W^X exec —— 能在 app 数据目录 exec 动态链接 ELF
        sendLine("case \"$(/sbin/apk --version 2>/dev/null)\" in "
                + "apk-tools*) echo '[gate1] PASS';; *) echo '[gate1] FAIL';; esac");

        // 门禁二：/proc/self/exe 不泄漏真实路径
        sendLine("v=$(readlink /proc/self/exe); echo \"[gate2] /proc/self/exe = $v\"; "
                + "case \"$v\" in /data/*) echo '[gate2] FAIL（真实路径泄漏）';; "
                + "/bin/*|/usr/*|/lib/*|/sbin/*) echo '[gate2] PASS';; "
                + "*) echo '[gate2] WARN';; esac");

        // 门禁三：env -i 清空环境后 exec 仍被强制回注
        sendLine("env /bin/busybox true; ra=$?; echo \"[g3a] inherited-env rc=$ra\"; "
                + "env -i /bin/busybox true; rb=$?; echo \"[g3b] empty-env rc=$rb\"; "
                + "env -i LD_PRELOAD=\"$LD_PRELOAD\" ZNG_PRELOAD=\"$ZNG_PRELOAD\" "
                + "ZNG_ROOT=\"$ZNG_ROOT\" /bin/busybox true; rcc=$?; "
                + "echo \"[g3c] manual-reinject rc=$rcc\"; "
                + "if [ \"$rb\" = 0 ] && [ \"$rcc\" = 0 ]; "
                + "then echo '[gate3] PASS'; else echo '[gate3] FAIL'; fi");

        // 附加：shebang / pwd / 根目录视图
        sendLine("printf '#!/bin/sh\\necho shebang-ok $0\\n' > /tmp/g.sh; "
                + "chmod +x /tmp/g.sh; "
                + "echo \"[x1] shebang: $(/tmp/g.sh)\"; "
                + "echo \"[x2] pwd -P: $(pwd -P)\"; "
                + "echo \"[x3] ls /: $(ls / | tr '\\n' ' ')\"");

        Toast.makeText(this, "自检命令已发送", Toast.LENGTH_SHORT).show();
    }
}
