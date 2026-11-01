/* SPDX-License-Identifier: MIT */
package com.pocketroot;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * 极简 tar 解包器（GNU/ustar，只处理本 rootfs 需要的条目类型）。
 *
 * 关键行为 —— symlink 改写：
 *
 *   tar 内的符号链接（Alpine 有 300+ 个绝对链接，如 /bin/ash -> /bin/busybox）
 *   指向 rootfs **内部**的绝对路径。而内核/ldso 解析它们是按真实根来的，
 *   于是 /bin/ash 会指向宿主的 /bin/busybox —— 在 Android 上不存在。
 *
 *   zroot-lab 0.1.1 的教训：原实现带"目标已存在才改写"的判断，而 tar 中
 *   symlink **恒先于**目标出现（busybox 排在最后），所以判断必为 false，
 *   306 个绝对链接全部原样保留，真机上报
 *   "cannot load /rootfs/bin/ash: No such file or directory"。
 *   修复方式是：非 passthrough 的绝对目标**无条件改写**。
 *
 *   这里沿用该修复，并把改写计数暴露出来（rewrittenCount），
 *   便于与构建期期望值对照 —— 计数不对就是解包出了问题。
 */
public class TarExtractor {

    public interface Progress {
        void onEntry(String name, long total, long count);
    }

    private final File dest;
    private final Progress progress;
    private int rewritten = 0;

    /** 不属于 rootfs 内部的前缀（这些目标不应被改写）。 */
    private static final String[] PASSTHROUGH = {
        "/proc", "/sys", "/dev", "/system", "/apex", "/vendor", "/data"
    };

    public TarExtractor(File dest, Progress progress) {
        this.dest = dest;
        this.progress = progress;
    }

    public int rewrittenCount() { return rewritten; }

    public void extract(InputStream in) throws IOException {
        byte[] buf = new byte[512];
        long count = 0;
        long total = 0;

        while (true) {
            if (!readFully(in, buf, 512)) break;

            // 两个连续全零块 = 归档结束
            if (isZero(buf)) break;

            String name = str(buf, 0, 100);
            if (name.isEmpty()) { total++; continue; }

            char type = (char) buf[156];
            long size = parseOctal(buf, 124, 12);
            String link = str(buf, 157, 100);

            // 跳过 pax/GNU 长名扩展头
            if (type == 'x' || type == 'g' || type == 'L' || type == 'K') {
                skip(in, size);
                continue;
            }

            File out = new File(dest, safe(name));
            File parent = out.getParentFile();
            if (parent != null) parent.mkdirs();

            if (type == '2') {                    // symlink
                String target = rewrite(link);
                createSymlink(target, out);
            } else if (type == '5') {             // directory
                out.mkdirs();
            } else if (type == '1') {             // hard link
                File src = new File(dest, safe(link));
                if (src.exists()) link(src, out);
            } else if (type == '0' || type == 0 || type == '7') {
                writeFile(in, size, out);
                setMode(out, (int) parseOctal(buf, 100, 8));
            } else {
                skip(in, size);
            }

            count++;
            total++;
            if (progress != null) progress.onEntry(name, total, count);
        }
    }

    /**
     * 把 rootfs 内部的绝对 symlink 目标改写为解包后的真实路径。
     * 注意：无条件改写（不判断目标是否已存在）。
     */
    private String rewrite(String target) {
        if (target == null || !target.startsWith("/")) return target;
        for (String p : PASSTHROUGH) {
            if (target.equals(p) || target.startsWith(p + "/")) return target;
        }
        rewritten++;
        return dest.getAbsolutePath() + target;
    }

    /** 归一化为相对路径字符串（去掉前导 "./"、"/" 与 ".."，防止逃出目标目录）。 */
    private static String safe(String name) {
        String n = name;
        while (n.startsWith("./")) n = n.substring(2);
        while (n.startsWith("/")) n = n.substring(1);
        if (n.contains("..")) n = n.replace("..", "");
        return n;
    }

    private void createSymlink(String target, File out) throws IOException {
        out.delete();
        try {
            java.nio.file.Files.createSymbolicLink(out.toPath(),
                    new File(target).toPath());
        } catch (Exception e) {
            /*
             * Android 的 Files.createSymbolicLink 在某些 API 级别上不可用。
             * 降级：写入一个普通文件保存目标串。
             * 关键：这里必须**显式报告**，不能静默跳过 ——
             * 静默降级正是 zroot-lab 花了好几个版本才摆脱的模式。
             */
            java.io.FileOutputStream fo = new java.io.FileOutputStream(out);
            try { fo.write(target.getBytes("UTF-8")); }
            finally { fo.close(); }
            throw new IOException("symlink 不可用，已降级为普通文件: " + out
                    + " (" + e + ")");
        }
    }

    private static void link(File src, File out) throws IOException {
        out.delete();
        try {
            java.nio.file.Files.createLink(out.toPath(), src.toPath());
        } catch (Exception e) {
            copyFile(src, out);       // 硬链接不可用则退化为复制
        }
    }

    private static void copyFile(File src, File out) throws IOException {
        java.io.FileInputStream fi = new java.io.FileInputStream(src);
        try {
            FileOutputStream fo = new FileOutputStream(out);
            try {
                byte[] b = new byte[1 << 16];
                int n;
                while ((n = fi.read(b)) > 0) fo.write(b, 0, n);
            } finally { fo.close(); }
        } finally { fi.close(); }
    }

    private static void writeFile(InputStream in, long size, File out) throws IOException {
        FileOutputStream fo = new FileOutputStream(out);
        try {
            byte[] b = new byte[1 << 16];
            long left = size;
            while (left > 0) {
                int want = (int) Math.min(left, b.length);
                if (!readFully(in, b, want)) break;
                fo.write(b, 0, want);
                left -= want;
            }
        } finally { fo.close(); }

        /*
         * 关键：tar 每个条目的数据后面都有 padding，补齐到 512 字节边界。
         *
         * 【真机实测的 bug】原先写完 size 字节就返回，没有跳过 padding，
         * 于是流停在一个未对齐的位置，下一个 512 字节的 header 从数据
         * 中间开始读 —— 结果是把文件内容当成条目名，rootfs 被解成一堆
         * 乱码文件名（ls rootfs/ 看到的是 "e nsswitch.conf file to
         * determine what" 这类内容，目录名也被截断成 "h" / "in"）。
         */
        long pad = ((size + 511) / 512) * 512 - size;
        if (pad > 0) {
            byte[] b = new byte[512];
            while (pad > 0) {
                int want = (int) Math.min(pad, b.length);
                if (!readFully(in, b, want)) break;
                pad -= want;
            }
        }
    }

    private static void skip(InputStream in, long size) throws IOException {
        long left = ((size + 511) / 512) * 512;
        byte[] b = new byte[1 << 16];
        while (left > 0) {
            int want = (int) Math.min(left, b.length);
            if (!readFully(in, b, want)) break;
            left -= want;
        }
    }

    private static void setMode(File f, int mode) {
        if (mode <= 0) return;
        try {
            // 仅处理可执行位（Android 上 chmod 需要 File 权限，失败可容忍）
            if ((mode & 0111) != 0) f.setExecutable(true, (mode & 0001) == 0);
        } catch (Exception ignored) { }
    }

    private static boolean readFully(InputStream in, byte[] b, int n) throws IOException {
        int off = 0;
        while (off < n) {
            int r = in.read(b, off, n - off);
            if (r < 0) return false;
            off += r;
        }
        return true;
    }

    private static boolean isZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    private static String str(byte[] b, int off, int len) {
        int end = off;
        while (end < off + len && b[end] != 0) end++;
        if (end == off) return "";
        return new String(b, off, end - off, java.nio.charset.Charset.forName("UTF-8"));
    }

    private static long parseOctal(byte[] b, int off, int len) {
        long v = 0;
        boolean started = false;
        for (int i = off; i < off + len; i++) {
            byte c = b[i];
            if (c == 0 || c == ' ') { if (started) break; continue; }
            v = (v << 3) | (c - '0');
            started = true;
        }
        return v;
    }
}
