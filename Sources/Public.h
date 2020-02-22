/*!
    @file Public.h

    @brief Interfaces to communicate with our hypervisor.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

//
// The VMCALL numbers our hypervisor provides.
//
typedef enum _HYPERVISOR_VMCALL_NUMBER
{
    //
    // Uninstall the hypervisor.
    //
    VmcallUninstall,

    //
    // The maximum valid VMCALL number (exclusive).
    //
    VmcallInvalid,
} HYPERVISOR_VMCALL_NUMBER;

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
    UINT64 Padding2;

    //
    // A pointer to the all-processors context. This value is not used by the
    // hypervisor, and the hypervisor doe not know its layout. It is stored here
    // so that it can be returned and freed when hypervisor is being disabled.
    //
    struct _SHARED_PROCESSOR_CONTEXT* VpContexts;

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
