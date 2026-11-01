# zng 核心逻辑单元测试
#
# 设计意图：核心算法必须与 syscall / Android / rootfs 解耦，从而能在开发机
# 上直接验证。【A】和【B】都做不到这一点 —— 它们的核心逻辑只能在真机或
# qemu 上"跑一遍看看"，异常路径从未被覆盖。
#
#   make        —— 普通构建
#   make asan   —— ASan + UBSan（推荐：能抓出 use-after-free / 越界写）
#   make check  —— 构建并运行（默认带 sanitizer）

CC      ?= cc
CFLAGS   = -DZNG_HOST_TEST -I../shim -std=gnu11 -Wall -Wextra -g -O1
SAN      = -fsanitize=address,undefined -fno-omit-frame-pointer
SRC      = test_main.c ../shim/zng_core.c

all: test_main

test_main: $(SRC) ../shim/zng.h ../shim/zng_sys.h
	$(CC) $(CFLAGS) -o $@ $(SRC)

asan: $(SRC) ../shim/zng.h ../shim/zng_sys.h
	$(CC) $(CFLAGS) $(SAN) -o test_main-asan $(SRC)

check: asan
	./test_main-asan


# 热路径微基准（-O2，不带 sanitizer —— 量的是翻译本身，不是插桩）
bench: bench_translate
bench_translate: bench_translate.c ../shim/zng_core.c ../shim/zng.h ../shim/zng_sys.h
	$(CC) -I../shim -std=gnu11 -O2 -Wall -Wextra -o $@ bench_translate.c ../shim/zng_core.c

clean:
	rm -f test_main test_main-asan bench_translate

.PHONY: all asan check clean bench
