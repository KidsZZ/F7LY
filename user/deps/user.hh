#pragma once

#include <stddef.h>
// #include <unistd.h>

#include <stdarg.h>
#include "types.hh"

int openat(int dirfd, const char *path, int flags);
int close(int fd);
ssize_t read(int fd, void *buf, size_t len);
ssize_t write(int fd, const void *buf, size_t len);
pid_t getpid(void);
pid_t getppid(void);
int sched_yield(void);
pid_t clone(int (*fn)(void *arg), void *arg, void *stack, size_t stack_size, unsigned long flags);
void exit(int code);
int waitpid(int pid, int *code, int options);
int exec(char *name);
int execve(const char *name, char *const argv[], char *const argp[]);
clock_t times(void *mytimes);
int munmap(void *start, size_t len);
int wait(int *code);
int sys_linkat(int olddirfd, char *oldpath, int newdirfd, char *newpath, unsigned int flags);
int sys_unlinkat(int dirfd, char *path, unsigned int flags);
int uname(void *buf);
int brk(void *addr);
int chdir(const char *path);
int getdents64(int fd, struct linux_dirent64 *dirp64, unsigned long len);
int pipe(int fd[2]);
int dup(int fd);
int mount(const char *special, const char *dir, const char *fstype, unsigned long flags, const void *data);
int umount(const char *special);
int fork(void);
char *getcwd(char *buf, size_t size);
// proc
int shutdown();

// add
int sleep(unsigned int seconds);



// 打印到指定文件描述符，支持%d, %x, %p, %s, %c, %%
void vprintf(int fd, const char *fmt, va_list ap);
void fprintf(int fd, const char *fmt, ...);
void printf(const char *fmt, ...);

// test函数
int run_test(char *test_list);
int basic_test(void);
int start_shell(void);