/*!
    @file Public.h

    @brief Interfaces to communicate with the hypervisor.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

//
// The VMCALL numbers our hypervisor provides.
//
#define MV_VMCALL_SIGNATURE_MASK    (UINT64)('MinV')

#define MV_VMCALL_INVALID_MIN       (UINT64)((MV_VMCALL_SIGNATURE_MASK << 32) | 0)
#define MV_VMCALL_UNINSTALL         (UINT64)((MV_VMCALL_SIGNATURE_MASK << 32) | 1)
#define MV_VMCALL_INVALID_MAX       (UINT64)((MV_VMCALL_SIGNATURE_MASK << 32) | 2)

//
// The arbitrary collection of data passed to our hypervisor from kernel-mode
// code through stack of the hypervisor.
//
// The structure must be 16-byte aligned so that hypervisor's stack pointer is
// always 16-byte aligned and SSE instructions can be used to save XMM registers.
// See Asm.asm for relevant code.
//
typedef struct _HYPERVISOR_CONTEXT
{
    //
    // The processor number associated with this context. 0 for BSP.
    //
    UINT32 ProcessorNumber;
    UINT32 Padding1;

    //
    // The pointer to the MSR bitmaps that are shared across processor.
    //
    struct _MSR_BITMAPS* SharedMsrBitmaps;

    //
    // A pointer to the shared processor context. This value is not used by the
    // hypervisor, and the hypervisor doe not know its layout. It is stored here
    // so that it can be returned and freed when hypervisor is being disabled.
    //
    struct _SHARED_PROCESSOR_CONTEXT* SharedProcessorContext;

    //
    // A pointer to the EPT context. Needed to handle EPT violation VM-exit.
    //
    struct _EPT_CONTEXT* EptContext;

    //
    // A pointer to the memory access context. Used to access guest's memory.
    //
    struct _MEMORY_ACCESS_CONTEXT* MemoryAccessContext;

    //
    // The state of the nested hypervisor if any.
    //
    struct _NEXTED_VMX_CONTEXT* NestedVmxContext;
} HYPERVISOR_CONTEXT;
C_ASSERT((sizeof(HYPERVISOR_CONTEXT) % 0x10) == 0);
