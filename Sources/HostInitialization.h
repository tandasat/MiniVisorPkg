/*!
    @file HostInitialization.h

    @brief Functions for host environment initialization.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"

/*!
    @brief Initializes the host environment.
 */
VOID
InitializeHostEnvironment (
    );

/*!
    @brief Returns the host CR3.

    @return The host CR3.
 */
CR3
GetHostCr3 (
    );

/*!
    @brief Returns the pointer to the host IDTR.

    @return The pointer to the host IDTR.
 */
CONST IDTR*
GetHostIdtr (
    );

/*!
    @brief Sets up the task state segment (TSS) and the TR register.

    @details On EFI, this functions takes a copy of the existing GDT into NewGdt,
        adds a new entry into it, which points to NewTss, then, updates the GDTR
        and TR to point to the NewGdt and the newly added entry. Those updated
        GDTR and TR may be used as both host and guest GDTR/TR.

        On Windows, this function is no-op.

    @param[in,out] NewTss - The pointer to buffer to be used as the task state
        segment.

    @param[out] NewGdt - The pointer to the buffet to be used as the new GDT.
        This will be initialized with the contents of the current GDT with the
        new entry for TSS.

    @param[in] NewGdtSize - The size of NewGdt in bytes.

    @param[out] OriginalGdtr - The pointer to the GDTR to receive the value before
        this function updates.
 */
VOID
InitializeGdt (
    _Inout_ TASK_STATE_SEGMENT_64* NewTss,
    _Out_writes_bytes_(NewGdtSize) SEGMENT_DESCRIPTOR_64* NewGdt,
    _In_ UINT64 NewGdtSize,
    _Out_ GDTR* OriginalGdtr
    );

/*!
    @brief Restores the GDTR to the specified value.

    @details On EFI, this function updates the current GDTR, however, does not
        restore the TR to the original value. This is because the original value
        is expected to be zero, which cannot write to TR anymore (causes #GP).
        Because of this, TR will point to an invalid entry in the restored GDT.
        This is an unsolvable issue unless we reuse the existing GDT instead of
        creating a copy, which does not work on VMware Workstation due to the
        physical address hosting the GDT is not modifiable. The only sane
        workaround would be to disallow unloading of the MiniVisor module.

        On Windows, this function is no-op.

    @param[in] OriginalGdtr - The pointer to the GDTR to restore to.
 */
VOID
CleanupGdt (
    _In_ CONST GDTR* OriginalGdtr
    );
