/*!
    @file WinHostInitialization.c

    @brief Windows specific implementation of host environment initialization.

    @details On Windows, no special set up is done because the host shares the
        System process CR3 and IDTR for ease of debugging, and other interactions
        with the guest as demanded.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "WinHostInitialization.h"

//
// The host CR3 and IDTR on Windows are the same as that of the System process.
// This allows the host to be debugged with Windbg.
//
static CR3 g_HostCr3;
static IDTR g_HostIdtr;

VOID
InitializeHostEnvironment (
    )
{
    MV_ASSERT(PsGetCurrentProcess() == PsInitialSystemProcess);

    g_HostCr3.Flags = __readcr3();
    __sidt(&g_HostIdtr);
}

CR3
GetHostCr3 (
    )
{
    return g_HostCr3;
}

CONST IDTR*
GetHostIdtr (
    )
{
    return &g_HostIdtr;
}

VOID
InitializeGdt (
    TASK_STATE_SEGMENT_64* NewTss,
    SEGMENT_DESCRIPTOR_64* NewGdt,
    UINT64 NewGdtSize,
    GDTR* OriginalGdtr
    )
{
    UNREFERENCED_PARAMETER(NewTss);
    UNREFERENCED_PARAMETER(NewGdt);
    UNREFERENCED_PARAMETER(NewGdtSize);
    UNREFERENCED_PARAMETER(OriginalGdtr);
}

VOID
CleanupGdt (
    CONST GDTR* OriginalGdtr
    )
{
    UNREFERENCED_PARAMETER(OriginalGdtr);
}
