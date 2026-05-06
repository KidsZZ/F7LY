# GDB 配置文件用于调试 LoongArch 内核
# 使用前先运行：make debug ARCH=loongarch
file kernel-la
target remote localhost:1234
break main
layout split
