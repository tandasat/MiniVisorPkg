/*!
    @file HostUtils.h

    @brief Utility functions and structures for the host.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#pragma once
#include "Common.h"
#include "Public.h"

//
// 128bit XMM register (ie, equivalent to __m128 on MSVC).
//
typedef struct _XMM
{
    UINT8 Value[16];
} XMM;

//
// Guest General Purpose Registers (GPRs) created on VM-exit from the guest
// state and write back to the guest on VM-entry.
//
typedef struct _GUEST_REGISTERS
{
    XMM Xmm[6];
    VOID* Alignment;
    UINT64 R15;
    UINT64 R14;
    UINT64 R13;
    UINT64 R12;
    UINT64 R11;
    UINT64 R10;
    UINT64 R9;
    UINT64 R8;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 Rbp;
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rcx;
    UINT64 Rax;
} GUEST_REGISTERS;

//
// The guest registers that are stored in the VMCS as opposed to stack like
// ones in the GUEST_REGISTERS structure.
//
typedef struct _VMCS_BASED_REGISTERS
{
    UINT64 Rip;
    UINT64 Rsp;
    RFLAGS Rflags;
} VMCS_BASED_REGISTERS;

//
// State of the guest.
//
typedef struct _GUEST_CONTEXT
{
    //
    // Indicates that the processor should continue virtualization. FALSE of
    // results in disablement of hypervisor with the VMXOFF instruction. See
    // x64.asm. This value is used as a return value of the HandleVmExit function.
    //
    BOOLEAN ContinueVm;

    //
    // Collection of pointers passed from the kernel via the host stack.
    //
    HYPERVISOR_CONTEXT* Contexts;

    //
    // The guest states stored in hypervisor stack.
    //
    GUEST_REGISTERS* StackBasedRegisters;

    //
    // The guest states stored in the VMCS.
    //
    VMCS_BASED_REGISTERS VmcsBasedRegisters;
} GUEST_CONTEXT;

/*!
    @brief Dumps host state VMCS fields.
 */
VOID
DumpHostState (
    );

/*!
    @brief Dumps guest state VMCS fields.
 */
VOID
DumpGuestState (
    );

/*!
    @brief Dumps control VMCS fields.
 */
VOID
DumpControl (
    );

/*!
    @brief Writes the value to the VMCS.

    @param[in] Field - The VMCS field to write the value to.

    @param[in] FieldValue - The value to write.
 */
VOID
VmxWrite (
    _In_ VMCS_FIELD Field,
    _In_ UINT64 FieldValue
    );

/*!
    @brief Read a value from the VMCS.

    @param[in] Field - The VMCS field to read a value from.

    @return A value read from the VMCS. 0 is returned when a non-existent VMCS
        field is requested for read.
 */
UINT64
VmxRead (
    _In_ VMCS_FIELD Field
    );

/*!
    @brief Advances the guest's RIP to the address of the next instruction. This
        implies that the hypervisor completed emulation of the instruction.

    @param[in,out] GuestContext - The pointer to the guest context.
 */
VOID
AdvanceGuestInstructionPointer (
    _Inout_ GUEST_CONTEXT* GuestContext
    );

/*!
    @brief Tests whether the guest was at the CPL 0 (kernel-mode) when VM-exit
        happened.

    @return TRUE when the guest was at the CPL 0, otherwise FALSE.
 */
_Must_inspect_result_
BOOLEAN
IsGuestInKernelMode (
    );

/*!
    @brief Queues interrupt to occur to the VMCS.

    @details Generally, this interrupt fires on VM-entry and the guests runs a
        corresponding exception handler before executing the instruction pointed
        by Rip.

    @param[in] InterruptionType - The type of interrupt to inject.

    @param[in] Vector - The vector number of interrupt to inject.

    @param[in] DeliverErrorCode - TRUE when the interrupt should have an error
        code. Whether the interrupt should have an error code is defined by the
        Intel SDM. See comments in the EXCEPTION_VECTOR definitions for a quick
        reference.

    @param[in] ErrorCode - The error code. Not used when DeliverErrorCode is FALSE.
 */
VOID
InjectInterruption (
    _In_ INTERRUPTION_TYPE InterruptionType,
    _In_ EXCEPTION_VECTOR Vector,
    _In_ BOOLEAN DeliverErrorCode,
    _In_ UINT32 ErrorCode
    );

/*!
    @brief Switches the guest paging mode between 32 and 64bit modes according
        with CR0 and EFER.

    @param[in] NewGuestCr0 - The guest CR0 value to check the mode to switch to.
 */
VOID
SwitchGuestPagingMode (
    _In_ CR0 NewGuestCr0
    );

/*!
    @brief Returns the CR0 value after the FIXED0 and FIXED1 MSR values are applied
        for the guest.

    @param[in] Cr0 - The CR0 value to apply the FIXED0 and FIXED1 MSR values.

    @return The CR0 value where the FIXED0 and FIXED1 MSR values are applied.
 */
CR0
AdjustGuestCr0 (
    _In_ CR0 Cr0
    );

/*!
    @brief Returns the CR4 value after the FIXED0 and FIXED1 MSR values are applied
        for the guest.

    @param[in] Cr4 - The CR4 value to apply the FIXED0 and FIXED1 MSR values.

    @return The CR4 value where the FIXED0 and FIXED1 MSR values are applied.
 */
CR4
AdjustGuestCr4 (
    _In_ CR4 Cr4
    );

/*!
    @brief Finds the base address of the image to which the specified address belongs.

    @param[in] GuestContext - The pointer to the guest context.

    @param[in] GuestVirtualAddress - The guest virtual address to find its image
        base.

    @return The base address of the image to which GuestVirtualAddress belongs, or
        0 on error.
 */
UINT64
FindImageBase (
    _In_ GUEST_CONTEXT* GuestContext,
    _In_ UINT64 GuestVirtualAddress
    );

/*!
    @brief Updates the MSR bitmap as specified.

    @param[in] Bitmaps - The pointer to the MSR bitmaps.

    @param[in,out] Msr - The MSR to change configurations. Must be in the range of
        0x0 - 0x1fff or 0xc0000000 - 0xc0001fff.

    @param[in] InterOperation - The type of operation to change configurations.

    @param[in] Intercept - TRUE if the hypervisor should intercept the specified
        type of access.
 */
VOID
UpdateMsrBitmaps (
    _Inout_ MSR_BITMAPS* Bitmaps,
    _In_ IA32_MSR_ADDRESS Msr,
    _In_ OPERATION_TYPE InterOperation,
    _In_ BOOLEAN Intercept
    );

/*!
    @brief Enables or disables NMI window exiting.

    @param[in] Enable - Whether NMI window exiting should be enabled.
 */
VOID
SetNmiWindowExiting (
    _In_ BOOLEAN Enable
    );
