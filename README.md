# F7LY OS

F7LY OS 是一个面向操作系统课程、系统能力训练和 OS 比赛场景的 C++ 教学内核项目。项目参考 xv6 的教学内核思想，从启动、异常、中断、内存、进程、文件系统到系统调用逐步扩展，目标是在 RISC-V 与 LoongArch 两套架构上提供结构清晰、可调试、可继续演进的宏内核实现。

![F7LY OS architecture](docs/assets/architecture-overview.png)

## 项目亮点

- 双架构支持：支持 RISC-V 与 LoongArch，按架构拆分 boot、trap、hal、mem、link、proc、devs 等目录，通用内核逻辑尽量复用。
- C++ 内核实现：使用 C++23 freestanding 环境组织内核模块，引入 EASTL 支撑部分容器需求，并实现必要的 C++ runtime/ABI 支持。
- 模块化宏内核：将启动、中断、进程、内存、设备、文件系统、网络、时间和系统调用拆成明确模块，便于阅读、调试和扩展。
- 内存管理：包含物理页管理、伙伴系统、堆分配器、slab 分配器、VMA 管理、mmap 懒分配和用户地址空间管理。
- 文件系统：通过 VFS 层统一普通文件、目录、设备文件、管道、socket 和虚拟文件；底层集成 lwext4，并保留 FAT32 支持。
- Linux 兼容接口：系统调用表已绑定 220+ 个 syscall，覆盖进程、文件、内存、信号、时间、IPC、socket 等主要类别。
- 网络能力：移植 Open-NPStack，并通过 VirtIO Net 适配层接入内核，向用户态提供 BSD Socket 风格接口。

## 技术栈

- 语言：C++23、C、Assembly
- 架构：RISC-V64、LoongArch64
- 构建：GNU Make、交叉编译工具链
- 虚拟化：QEMU
- 文件系统：VFS、lwext4、FAT32
- 网络：VirtIO Net、Open-NPStack、BSD Socket API
- 测试与分析：BusyBox、LTP、GDB、QEMU user/static 工具

## 目录结构

```text
F7LY
├── kernel/                 # 内核源码
│   ├── boot/               # 架构相关启动入口与 main 初始化流程
│   ├── devs/               # 字符设备、块设备、VirtIO、AHCI、Loop 等设备抽象
│   ├── fs/                 # VFS、lwext4、FAT32、文件对象与块缓存
│   ├── hal/                # CPU、CSR、上下文等硬件抽象
│   ├── libs/               # 内核基础库、打印、分配器、C++ runtime 支持
│   ├── mem/                # 物理内存、虚拟内存、VMA、heap、slab
│   ├── net/                # VirtIO Net、Open-NPStack 适配与 socket 文件
│   ├── proc/               # 进程、线程、调度、信号、futex、pipe
│   ├── shm/                # System V 共享内存
│   ├── sys/                # 系统调用号与分发表
│   ├── tm/                 # 时间与定时器
│   └── trap/               # 中断、异常、系统调用陷入与返回
├── user/                   # 用户态 initcode、系统调用封装和测试程序
├── busybox/                # RISC-V/LoongArch 下的 BusyBox 二进制材料
├── rootfs/                 # 默认 initrd/rootfs 备份
├── thirdparty/             # 第三方依赖，目前包含 EASTL
├── tools/                  # LTP 判题、榜单解析等辅助工具
├── scripts/                # 镜像挂载、QEMU user、GDB 等脚本
└── docs/                   # 设计文档、答辩材料、Typst 文档工程与开发记录
```

## 环境要求

推荐环境：

- Ubuntu 24.04
- GNU Make
- RISC-V 工具链：`riscv64-linux-gnu-*`
- LoongArch 工具链：`loongarch64-linux-gnu-*`
- QEMU 9.2.1 或更新版本，需支持 `qemu-system-riscv64` 和 `qemu-system-loongarch64`
- GDB：`gdb-multiarch`、`riscv64-unknown-elf-gdb` 或 `loongarch64-linux-gnu-gdb`

LoongArch 工具链可参考：

- [LoongsonLab/oscomp-toolchains-for-oskernel](https://github.com/LoongsonLab/oscomp-toolchains-for-oskernel/releases)
- [LoongsonLab/2k1000-materials](https://github.com/LoongsonLab/2k1000-materials/releases)

## 构建与运行

构建 RISC-V：

```bash
make riscv
```

构建 LoongArch：

```bash
make loongarch
```

运行 RISC-V：

```bash
make run ARCH=riscv
```

运行 LoongArch：

```bash
make run ARCH=loongarch
```

清理构建产物：

```bash
make clean
```

## 调试

启动 RISC-V GDB stub：

```bash
make debug ARCH=riscv
```

另开终端连接：

```bash
gdb-multiarch -x scripts/gdb/kernel-riscv.gdb
```

启动 LoongArch GDB stub：

```bash
make debug ARCH=loongarch
```

另开终端连接：

```bash
loongarch64-linux-gnu-gdb -x scripts/gdb/kernel-loongarch.gdb
```

用户态 BusyBox 调试配置位于 `scripts/gdb/user-riscv.gdb` 和 `scripts/gdb/user-loongarch.gdb`。

## 文档

- [决赛设计文档](docs/F7LY-OS决赛设计文档.pdf)
- [现场赛文档](docs/F7LY现场赛文档.pdf)
- [答辩 PPT](docs/F7LY答辩ppt-武汉大学.pdf)
- Typst 文档工程：`docs/typst/main.typ`、`docs/typst/onsite.typ`
- 开发记录：`docs/dev-notes/`

## 参考与致谢

F7LY OS 的实现过程中参考或移植了多个优秀项目和组件：

- [xv6-riscv](https://github.com/mit-pdos/xv6-riscv)：教学 OS 结构和部分基础设计思想。
- [XN6 / OSKernel2024-2k1000la-xv6](https://gitlab.eduxiji.net/T202410486992576/OSKernel2024-2k1000la-xv6)：LoongArch 支持相关参考。
- [EASTL](https://github.com/electronicarts/EASTL)：内核 C++ 容器支持。
- [lwext4](https://github.com/gkostka/lwext4)：ext4 文件系统实现。
- [Open-NPStack](https://gitee.com/Neo-T/open-npstack)：网络协议栈。
- [oskernel2023-avx](https://gitlab.eduxiji.net/202310487101114/oskernel2023-avx)：VisionFive2/SD 卡驱动相关参考。