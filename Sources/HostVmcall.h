/*!
    @file HostVmcall.h

    @brief Implementation of hypercall functions.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"
#include "HostUtils.h"
#include "Public.h"

//
// The VMCALL handler type.
//
typedef
VOID
VMCALL_HANDLER (
    _Inout_ GUEST_CONTEXT* GuestContext
    );

/*!
    @brief Handles hypercall for uninstalling the hypervisor.

    @param[in,out] GuestContext - The pointer to the guest context.
 */
VMCALL_HANDLER HandleVmcallUninstall;

//
// VMCALL handlers and mapping.
//
static VMCALL_HANDLER* k_VmcallHandlers[] =
{
    HandleVmcallUninstall,
};
C_ASSERT(RTL_NUMBER_OF(k_VmcallHandlers) == VmcallInvalid);
