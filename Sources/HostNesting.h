/*!
    @file HostNesting.h

    @brief Incomplete nesting related code. Do not study.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"
#include "Ia32.h"
#include "HostUtils.h"
#include "ExtendedPageTables.h"

typedef enum _VMX_OPERATION
{
    VmxOperationNotInVmxOperation,
    VmxOperationRoot,
    VmxOperationNonRoot,
} VMX_OPERATION;

typedef enum _VMCS_LAUNCH_STATE
{
    LaunchStateUnintialized,
    LaunchStateClear,
    LaunchStateLaunched,
} VMCS_LAUNCH_STATE;

typedef struct _NEXTED_VMX_CONTEXT
{
    VMX_OPERATION VmxOperation;
    VMCS_LAUNCH_STATE VmcsLaunchState;

    //
    // The physical address of the VMXON region (used by L1 for L2)
    //
    UINT64 Vmxon12Pa;

    //
    // The physical addresses of VMCSs (used by L0 for L1 and L2)
    //
    UINT64 Vmcs01Pa;
    UINT64 Vmcs02Pa;

    //
    // Current VMCS from the point of view of the nested VMM (used by L1 for L2)
    //
    UINT64 Vmcs12Pa;

    //
    // EPT related data (used by L0 for L2)
    //
    EPT_CONTEXT Ept02Context;
    EPT_PML4* EptPml4_02;

    //
    // VMCS (used by L0 for L2).
    //
    DECLSPEC_ALIGN(PAGE_SIZE) VMCS Vmcs02;
} NEXTED_VMX_CONTEXT;

VOID
HandleVmx (
    _Inout_ GUEST_CONTEXT* GuestContext,
    _In_ UINT32 ExitReason
    );

VOID
EmulateVmExitForL1Vmm (
    _Inout_ GUEST_CONTEXT* GuestContext,
    _In_ UINT32 ExitReason
    );

BOOLEAN
IsVmExitForL1 (
    CONST GUEST_CONTEXT* GuestContext,
    VMX_VMEXIT_REASON VmExitReason
    );
