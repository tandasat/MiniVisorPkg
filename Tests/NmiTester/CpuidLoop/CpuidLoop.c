#include <Windows.h>
#include <intrin.h>
#include <crtdbg.h>
#include <stdio.h>

#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS   ((UINT32)0x40000000)

static
DWORD
WINAPI
ThreadEntryPoint (
    PVOID Context
    )
{
    int registers[4];

    while (TRUE)
    {
        __cpuid(registers, CPUID_HV_VENDOR_AND_MAX_FUNCTIONS);
    }
    return 0;
}

int
main (
    )
{
    DWORD processorCount;

    //
    // Spawn threads that run CPUID in the infinite loop.
    //
    processorCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    for (DWORD i = 0; i < processorCount; ++i)
    {
        HANDLE threadHandle;

        threadHandle = CreateThread(NULL, 0, ThreadEntryPoint, NULL, 0, NULL);
        if (threadHandle == NULL)
        {
            return EXIT_FAILURE;
        }
        CloseHandle(threadHandle);
    }

    printf("%lu CPUID loop threads started. Press the ENTER key to terminate the program.\n",
           processorCount);
    (void)getchar();
    return EXIT_SUCCESS;
}
