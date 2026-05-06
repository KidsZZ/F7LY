#!/bin/sh

# 一次性挂载常用比赛镜像，便于本地检查 rootfs 与 libc 依赖。
set -e

sudo mount -o loop sdcard-rv.img /mnt/sdcard-rv
sudo mount -o loop sdcard-la.img /mnt/sdcard-la
sudo mount -o loop sdcard-rv-final.img /mnt/sdcard-rv-final
sudo mount -o loop sdcard-la-final.img /mnt/sdcard-la-final
sudo ln -sf /mnt/sdcard-rv/musl/lib/libc.so /lib/ld-musl-riscv64.so.1
sudo mount -o loop sdcard-rv-onsite.img /mnt/sdcard-rv-onsite
sudo mount -o loop sdcard-la-onsite.img /mnt/sdcard-la-onsite
