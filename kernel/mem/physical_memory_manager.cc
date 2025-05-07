#include "physical_memory_manager.hh"
#include "types.hh"
#include "platform.hh"
#include "devs/spinlock.hh"
#include "buddysystem.hh"
#include "printer.hh"
#include "klib.hh"
#include "slab.hh"
#include "platform.hh"
extern "C" char end[]; // 来自链接脚本

namespace mem
{
    PhysicalMemoryManager k_pmm;
    uint64 PhysicalMemoryManager::pa_start;
    SpinLock PhysicalMemoryManager::memlock;

    uint64 PhysicalMemoryManager::pa2pgnm(void *pa)
    {
        auto addr = reinterpret_cast<uint64>(pa);
        if (addr % PGSIZE != 0)
        {
            panic("kfree!");
        }
        return (addr - pa_start) / PGSIZE;
    }

    void *PhysicalMemoryManager::pgnm2pa(int pgnm)
    {
        return reinterpret_cast<void *>(static_cast<uint64>(pgnm) * PGSIZE + pa_start);
    }

    int PhysicalMemoryManager::size_to_page_num(uint64 size)
    {
        return static_cast<int>(size / PGSIZE + (size % PGSIZE != 0));
    }

    void PhysicalMemoryManager::init()
    {
        // 多核情况下应该加锁
        memlock.init("memlock");
        //把原本Buddy的初始化放在这里，Buddy变成pmm的一个成员

        /*pa_start是buddy系统在物理内存中的起始地址,加上一个Sizeof(BuddySystem)后后面存的东西是tree,
        然后tree存完了之后才是buddy系统管理的那块内存。加上的BSSIZE是预留来放BuddySystem的大小和tree的大小，
        在这之后才是buddy系统管理的那块内存，这时pa_start指向的就是buddy系统管理的那块内存的开始地址，
        再被初始化为buddy的基址。*/
        pa_start = reinterpret_cast<uint64_t>(end);
        pa_start = (pa_start + PGSIZE - 1) & ~(PGSIZE - 1); //将pa_start向高地址对齐到PGSIZE的整数倍

        _buddy = reinterpret_cast<BuddySystem*>(pa_start);
        pa_start += BSSIZE * PGSIZE;
        memset(_buddy, 0, BSSIZE * PGSIZE);
        _buddy->Initialize(pa_start);
        printf("PhysicalMemoryManager init success\n");
    }

    void *PhysicalMemoryManager::alloc_page()
    {
        int x ;
        if(x= _buddy->Alloc(0) == -1)
        {
            panic("[pmm] alloc_page failed");
        }
        void *pa = pgnm2pa(x);
        memset(pa, 0, PGSIZE);
        return pa;
    }

    void PhysicalMemoryManager::free_page(void *pa)
    {
        _buddy->Free(pa2pgnm(pa));
    }

    void PhysicalMemoryManager::clear_page(void *pa)
    {
        uint64 *p = (uint64 *)pa;
        const uint cnt = PGSIZE >> 3;
        for (uint i = 0; i < cnt; i++)
            p[i] = 0;
    }

    void *PhysicalMemoryManager::kmalloc(size_t size)
    {
        if(size >= PGSIZE)
        {
            int x = _buddy->Alloc(size_to_page_num(size));
            void *pa = pgnm2pa(x);
            memset(pa, 0, PGSIZE);
            return pa;
        }
        else if(size < PGSIZE)
        {
            //there maybe some bugs to be fixed
            return SlabAllocator::alloc(size);
        }
        else
        {
            panic("kmalloc: size is too large");
            return nullptr; // 永远不会执行到这里，但必须有返回值
        }
    }

    void *PhysicalMemoryManager::kcalloc(uint n, size_t size)
    {
        void* pa = kmalloc(n * size);
        memset(pa, 0, n * size);
        return pa;
    }

    
}