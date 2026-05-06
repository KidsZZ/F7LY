# GDB 配置文件用于调试 LoongArch 内核
# 该文件保留为参考配置，适合旧版 QEMU/GDB 会话手动调整。
file kernel-la
target remote localhost:1234
break _entry
break main
layout split
