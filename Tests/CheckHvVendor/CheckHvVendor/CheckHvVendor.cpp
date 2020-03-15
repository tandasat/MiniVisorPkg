//
// This program executes CPUID(0x40000000) on all logical processors.
//
#include <stdio.h>
#include <string.h>

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define WINDOWS

#include <intrin.h>
#include <Windows.h>

#elif defined(__linux__)
#define LINUX

#include <sys/sysinfo.h>
#include <sched.h>
#include <cpuid.h>

#endif

static
void
cpuid (
    int* regs,
    int leaf
    )
{
#if defined(WINDOWS)
    __cpuid(regs, leaf);
#elif defined(LINUX)
    __cpuid(leaf, regs[0], regs[1], regs[2], regs[3]);
#endif
}

static
unsigned long
get_logical_processor_count (
    )
{
#if defined(WINDOWS)
    return GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
#elif defined(LINUX)
    return get_nprocs();
#endif
}

static
int
get_current_processor_number (
    )
{
#if defined(WINDOWS)
    return GetCurrentProcessorNumber();
#elif defined(LINUX)
    return sched_getcpu();
#endif
}

static
bool
set_affinity (
    int processor_number
    )
{
#if defined(WINDOWS)
    return (SetProcessAffinityMask(GetCurrentProcess(), ((DWORD_PTR)1) << processor_number) != FALSE);
#elif defined(LINUX)
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(processor_number, &mask);
    return (sched_setaffinity(0, sizeof(mask), &mask) != -1);
#endif
}

static
void
run_cpuid (
    )
{
    int registers[4] = {};   // EAX, EBX, ECX, and EDX
    char vendorId[13];

    printf("Executing CPUID(0x40000000) on CPU %d\n", get_current_processor_number());
    cpuid(registers, 0x40000000);
    memcpy(vendorId + 0, &registers[1], sizeof(registers[1]));
    memcpy(vendorId + 4, &registers[2], sizeof(registers[2]));
    memcpy(vendorId + 8, &registers[3], sizeof(registers[3]));
    vendorId[12] = '\0';
    printf("Result: %s\n", vendorId);
}


static
void
test_cpuid_on_all_processors (
    )
{
    unsigned long cpuCount = get_logical_processor_count();

    for (unsigned long i = 0; i < cpuCount; ++i)
    {
        if (!set_affinity(i))
        {
            printf("set_affinity failed\n");
            return;
        }

        run_cpuid();
    }
}

int
main (
    )
{
    test_cpuid_on_all_processors();
}
