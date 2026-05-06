# RISC-V 内核调试配置。
# 使用前先运行：make debug ARCH=riscv
file kernel-qemu
set architecture riscv:rv64
target remote localhost:1234
break main
layout split
