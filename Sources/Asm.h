/*!
    @file Asm.h

    @brief MASM-written functions.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

#if defined(NTDDI_VERSION)
#include "Platform/Windows/WinAsm.h"
#else
#include "Platform/EFI/EfiAsm.h"
#endif

/*!
    @brief An entry point for the hypervisor.

    @details See x64.asm.
 */
VOID
AsmHypervisorEntryPoint (
    VOID
    );

/*!
    @brief Invalidate translations derived from EPT.

    @param[in] InvEptType - A type of invalidation.

    @param[in] InvEptDescriptor - A description of translations to invalidate.

    @return An appropriate VMX_RESULT value.
 */
VMX_RESULT
AsmInvept (
    _In_ INVEPT_TYPE InvEptType,
    _In_ CONST INVEPT_DESCRIPTOR* InvEptDescriptor
    );

/*!
    @brief Invalidate translations based on VPID.

    @param[in] InvVpidType - A type of invalidation.

    @param[in] InvVpidDescriptor - A description of translations to invalidate.

    @return An appropriate VMX_RESULT value.
 */
VMX_RESULT
AsmInvvpid (
    _In_ INVVPID_TYPE InvVpidType,
    _In_ CONST INVVPID_DESCRIPTOR* InvVpidDescriptor
    );


/*!
    @brief Reads the access rights byte of the segment.

    @details See: LAR-Load Access Rights Byte

    @param[in] SegmentSelector - The selector of the segment to read.

    @return The access rights byte of the segment, or 0 on failure.
 */
UINT32
AsmLoadAccessRightsByte (
    _In_ UINT16 SegmentSelector
    );

/*!
    @brief Issues hypercall.

    @param[in] HyperCallNumber - The hypercall number.

    @param[in] Parameter1 - The arbitrary 64bit parameter 1.

    @param[in] Parameter2 - The arbitrary 64bit parameter 2.

    @param[in] Parameter3 - The arbitrary 64bit parameter 3.

    @return The 64bit return value. Meaning is depends on HyperCallNumber.
 */
UINT64
AsmVmxCall (
    _In_ UINT64 HyperCallNumber,
    _In_ UINT64 Parameter1,
    _In_ UINT64 Parameter2,
    _In_ UINT64 Parameter3
    );

/*!
    @brief Returns the address of the return address from this function.

    @return The address of the return address from this function.
 */
UINT64
AsmGetCurrentInstructionPointer (
    VOID
    );

/*!
    @brief Returns the current value of RSP.

    @return The current value of RSP.
 */
UINT64
AsmGetCurrentStackPointer (
    VOID
    );
