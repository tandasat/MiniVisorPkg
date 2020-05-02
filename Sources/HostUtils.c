/*!
    @file HostUtils.c

    @brief Utility functions and structures for the host.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "HostUtils.h"
#include "Logger.h"
#include "ExtendedPageTables.h"
#include "Ia32Utils.h"
#include "MemoryAccess.h"

/*!
    @brief Dumps the segment access rights value.

    @param[in] AccessRights - The segment access rights value to dump.
 */
static
VOID
DumpAccessRights (
    _In_ UINT64 AccessRights
    )
{
    VMX_SEGMENT_ACCESS_RIGHTS rights;

    rights.Flags = (UINT32)AccessRights;
    LOG_ERROR(" - Type      = %u", rights.Type);
    LOG_ERROR(" - S         = %u", rights.DescriptorType);
    LOG_ERROR(" - DPL       = %u", rights.DescriptorPrivilegeLevel);
    LOG_ERROR(" - P         = %u", rights.Present);
    LOG_ERROR(" - Reserved1 = %u", rights.Reserved1);
    LOG_ERROR(" - Available = %u", rights.AvailableBit);
    LOG_ERROR(" - L         = %u", rights.LongMode);
    LOG_ERROR(" - D/B       = %u", rights.DefaultBig);
    LOG_ERROR(" - G         = %u", rights.Granularity);
    LOG_ERROR(" - Unusable  = %u", rights.Unusable);
    LOG_ERROR(" - Reserved2 = %u", rights.Reserved2);
}

VOID
DumpHostState (
    )
{
    //
    // 16-Bit Host-State Fields
    //
    LOG_ERROR("Host ES Selector              = %016llx", VmxRead(VMCS_HOST_ES_SELECTOR));
    LOG_ERROR("Host CS Selector              = %016llx", VmxRead(VMCS_HOST_CS_SELECTOR));
    LOG_ERROR("Host SS Selector              = %016llx", VmxRead(VMCS_HOST_SS_SELECTOR));
    LOG_ERROR("Host DS Selector              = %016llx", VmxRead(VMCS_HOST_DS_SELECTOR));
    LOG_ERROR("Host FS Selector              = %016llx", VmxRead(VMCS_HOST_FS_SELECTOR));
    LOG_ERROR("Host GS Selector              = %016llx", VmxRead(VMCS_HOST_GS_SELECTOR));
    LOG_ERROR("Host TR Selector              = %016llx", VmxRead(VMCS_HOST_TR_SELECTOR));

    //
    // 64-Bit Host-State Fields
    //
    LOG_ERROR("Host IA32_PAT                 = %016llx", VmxRead(VMCS_HOST_PAT));
    LOG_ERROR("Host IA32_EFER                = %016llx", VmxRead(VMCS_HOST_EFER));
    LOG_ERROR("Host IA32_PERF_GLOBAL_CTRL    = %016llx", VmxRead(VMCS_HOST_PERF_GLOBAL_CTRL));

    //
    // 32-Bit Host-State Fields
    //
    LOG_ERROR("Host IA32_SYSENTER_CS         = %016llx", VmxRead(VMCS_HOST_SYSENTER_CS));

    //
    // Natural-Width Host-State Fields
    //
    LOG_ERROR("Host CR0                      = %016llx", VmxRead(VMCS_HOST_CR0));
    LOG_ERROR("Host CR3                      = %016llx", VmxRead(VMCS_HOST_CR3));
    LOG_ERROR("Host CR4                      = %016llx", VmxRead(VMCS_HOST_CR4));
    LOG_ERROR("Host FS Base                  = %016llx", VmxRead(VMCS_HOST_FS_BASE));
    LOG_ERROR("Host GS Base                  = %016llx", VmxRead(VMCS_HOST_GS_BASE));
    LOG_ERROR("Host TR base                  = %016llx", VmxRead(VMCS_HOST_TR_BASE));
    LOG_ERROR("Host GDTR base                = %016llx", VmxRead(VMCS_HOST_GDTR_BASE));
    LOG_ERROR("Host IDTR base                = %016llx", VmxRead(VMCS_HOST_IDTR_BASE));
    LOG_ERROR("Host IA32_SYSENTER_ESP        = %016llx", VmxRead(VMCS_HOST_SYSENTER_ESP));
    LOG_ERROR("Host IA32_SYSENTER_EIP        = %016llx", VmxRead(VMCS_HOST_SYSENTER_EIP));
    LOG_ERROR("Host RSP                      = %016llx", VmxRead(VMCS_HOST_RSP));
    LOG_ERROR("Host RIP                      = %016llx", VmxRead(VMCS_HOST_RIP));
}

VOID
DumpGuestState (
    )
{
    //
    // 16-Bit Guest-State Fields
    //
    LOG_ERROR("Guest ES Selector              = %016llx", VmxRead(VMCS_GUEST_ES_SELECTOR));
    LOG_ERROR("Guest CS Selector              = %016llx", VmxRead(VMCS_GUEST_CS_SELECTOR));
    LOG_ERROR("Guest SS Selector              = %016llx", VmxRead(VMCS_GUEST_SS_SELECTOR));
    LOG_ERROR("Guest DS Selector              = %016llx", VmxRead(VMCS_GUEST_DS_SELECTOR));
    LOG_ERROR("Guest FS Selector              = %016llx", VmxRead(VMCS_GUEST_FS_SELECTOR));
    LOG_ERROR("Guest GS Selector              = %016llx", VmxRead(VMCS_GUEST_GS_SELECTOR));
    LOG_ERROR("Guest LDTR Selector            = %016llx", VmxRead(VMCS_GUEST_LDTR_SELECTOR));
    LOG_ERROR("Guest TR Selector              = %016llx", VmxRead(VMCS_GUEST_TR_SELECTOR));
    LOG_ERROR("Guest interrupt status         = %016llx", VmxRead(VMCS_GUEST_INTERRUPT_STATUS));
    LOG_ERROR("PML index                      = %016llx", VmxRead(VMCS_GUEST_PML_INDEX));

    //
    // 64-Bit Guest-State Fields
    //
    LOG_ERROR("VMCS link pointer              = %016llx", VmxRead(VMCS_GUEST_VMCS_LINK_POINTER));
    LOG_ERROR("Guest IA32_DEBUGCTL            = %016llx", VmxRead(VMCS_GUEST_DEBUGCTL));
    LOG_ERROR("Guest IA32_PAT                 = %016llx", VmxRead(VMCS_GUEST_PAT));
    LOG_ERROR("Guest IA32_EFER                = %016llx", VmxRead(VMCS_GUEST_EFER));
    LOG_ERROR("Guest IA32_PERF_GLOBAL_CTRL    = %016llx", VmxRead(VMCS_GUEST_PERF_GLOBAL_CTRL));
    LOG_ERROR("Guest PDPTE0                   = %016llx", VmxRead(VMCS_GUEST_PDPTE0));
    LOG_ERROR("Guest PDPTE1                   = %016llx", VmxRead(VMCS_GUEST_PDPTE1));
    LOG_ERROR("Guest PDPTE2                   = %016llx", VmxRead(VMCS_GUEST_PDPTE2));
    LOG_ERROR("Guest PDPTE3                   = %016llx", VmxRead(VMCS_GUEST_PDPTE3));
    LOG_ERROR("Guest IA32_BNDCFGS             = %016llx", VmxRead(VMCS_GUEST_BNDCFGS));
    LOG_ERROR("Guest IA32_RTIT_CTL            = %016llx", VmxRead(VMCS_GUEST_RTIT_CTL));

    //
    // 32-Bit Guest-State Fields
    //
    LOG_ERROR("Guest ES Limit                 = %016llx", VmxRead(VMCS_GUEST_ES_LIMIT));
    LOG_ERROR("Guest CS Limit                 = %016llx", VmxRead(VMCS_GUEST_CS_LIMIT));
    LOG_ERROR("Guest SS Limit                 = %016llx", VmxRead(VMCS_GUEST_SS_LIMIT));
    LOG_ERROR("Guest DS Limit                 = %016llx", VmxRead(VMCS_GUEST_DS_LIMIT));
    LOG_ERROR("Guest FS Limit                 = %016llx", VmxRead(VMCS_GUEST_FS_LIMIT));
    LOG_ERROR("Guest GS Limit                 = %016llx", VmxRead(VMCS_GUEST_GS_LIMIT));
    LOG_ERROR("Guest LDTR Limit               = %016llx", VmxRead(VMCS_GUEST_LDTR_LIMIT));
    LOG_ERROR("Guest TR Limit                 = %016llx", VmxRead(VMCS_GUEST_TR_LIMIT));
    LOG_ERROR("Guest GDTR limit               = %016llx", VmxRead(VMCS_GUEST_GDTR_LIMIT));
    LOG_ERROR("Guest IDTR limit               = %016llx", VmxRead(VMCS_GUEST_IDTR_LIMIT));
    LOG_ERROR("Guest ES access rights         = %016llx", VmxRead(VMCS_GUEST_ES_ACCESS_RIGHTS));
    LOG_ERROR("Guest CS access rights         = %016llx", VmxRead(VMCS_GUEST_CS_ACCESS_RIGHTS));
    LOG_ERROR("Guest SS access rights         = %016llx", VmxRead(VMCS_GUEST_SS_ACCESS_RIGHTS));
    LOG_ERROR("Guest DS access rights         = %016llx", VmxRead(VMCS_GUEST_DS_ACCESS_RIGHTS));
    LOG_ERROR("Guest FS access rights         = %016llx", VmxRead(VMCS_GUEST_FS_ACCESS_RIGHTS));
    LOG_ERROR("Guest GS access rights         = %016llx", VmxRead(VMCS_GUEST_GS_ACCESS_RIGHTS));
    LOG_ERROR("Guest LDTR access rights       = %016llx", VmxRead(VMCS_GUEST_LDTR_ACCESS_RIGHTS));
    LOG_ERROR("Guest TR access rights         = %016llx", VmxRead(VMCS_GUEST_TR_ACCESS_RIGHTS));
    LOG_ERROR("Guest interruptibility state   = %016llx", VmxRead(VMCS_GUEST_INTERRUPTIBILITY_STATE));
    LOG_ERROR("Guest activity state           = %016llx", VmxRead(VMCS_GUEST_ACTIVITY_STATE));
    LOG_ERROR("Guest SMBASE                   = %016llx", VmxRead(VMCS_GUEST_SMBASE));
    LOG_ERROR("Guest IA32_SYSENTER_CS         = %016llx", VmxRead(VMCS_GUEST_SYSENTER_CS));
    LOG_ERROR("VMX-preemption timer value     = %016llx", VmxRead(VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE));

    //
    // Natural-Width Guest-State Fields
    //
    LOG_ERROR("Guest CR0                      = %016llx", VmxRead(VMCS_GUEST_CR0));
    LOG_ERROR("Guest CR3                      = %016llx", VmxRead(VMCS_GUEST_CR3));
    LOG_ERROR("Guest CR4                      = %016llx", VmxRead(VMCS_GUEST_CR4));
    LOG_ERROR("Guest ES Base                  = %016llx", VmxRead(VMCS_GUEST_ES_BASE));
    LOG_ERROR("Guest CS Base                  = %016llx", VmxRead(VMCS_GUEST_CS_BASE));
    LOG_ERROR("Guest SS Base                  = %016llx", VmxRead(VMCS_GUEST_SS_BASE));
    LOG_ERROR("Guest DS Base                  = %016llx", VmxRead(VMCS_GUEST_DS_BASE));
    LOG_ERROR("Guest FS Base                  = %016llx", VmxRead(VMCS_GUEST_FS_BASE));
    LOG_ERROR("Guest GS Base                  = %016llx", VmxRead(VMCS_GUEST_GS_BASE));
    LOG_ERROR("Guest LDTR base                = %016llx", VmxRead(VMCS_GUEST_LDTR_BASE));
    LOG_ERROR("Guest TR base                  = %016llx", VmxRead(VMCS_GUEST_TR_BASE));
    LOG_ERROR("Guest GDTR base                = %016llx", VmxRead(VMCS_GUEST_GDTR_BASE));
    LOG_ERROR("Guest IDTR base                = %016llx", VmxRead(VMCS_GUEST_IDTR_BASE));
    LOG_ERROR("Guest DR7                      = %016llx", VmxRead(VMCS_GUEST_DR7));
    LOG_ERROR("Guest RSP                      = %016llx", VmxRead(VMCS_GUEST_RSP));
    LOG_ERROR("Guest RIP                      = %016llx", VmxRead(VMCS_GUEST_RIP));
    LOG_ERROR("Guest RFLAGS                   = %016llx", VmxRead(VMCS_GUEST_RFLAGS));
    LOG_ERROR("Guest pending debug exceptions = %016llx", VmxRead(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS));
    LOG_ERROR("Guest IA32_SYSENTER_ESP        = %016llx", VmxRead(VMCS_GUEST_SYSENTER_ESP));
    LOG_ERROR("Guest IA32_SYSENTER_EIP        = %016llx", VmxRead(VMCS_GUEST_SYSENTER_EIP));
}

VOID
DumpControl (
    )
{
    //
    // 16-Bit Control Fields
    //
    LOG_ERROR("Virtual-processor identifier   = %016llx", VmxRead(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER));
    LOG_ERROR("Posted-interrupt notification vector = %016llx", VmxRead(VMCS_CTRL_POSTED_INTERRUPT_NOTIFICATION_VECTOR));
    LOG_ERROR("EPTP index                     = %016llx", VmxRead(VMCS_CTRL_EPTP_INDEX));

    //
    // 64-Bit Control Fields
    //
    LOG_ERROR("Address of I/O bitmap A        = %016llx", VmxRead(VMCS_CTRL_IO_BITMAP_A_ADDRESS));
    LOG_ERROR("Address of I/O bitmap B        = %016llx", VmxRead(VMCS_CTRL_IO_BITMAP_B_ADDRESS));
    LOG_ERROR("Address of MSR bitmaps         = %016llx", VmxRead(VMCS_CTRL_MSR_BITMAP_ADDRESS));
    LOG_ERROR("VM-exit MSR-store address      = %016llx", VmxRead(VMCS_CTRL_VMEXIT_MSR_STORE_ADDRESS));
    LOG_ERROR("VM-exit MSR-load address       = %016llx", VmxRead(VMCS_CTRL_VMEXIT_MSR_LOAD_ADDRESS));
    LOG_ERROR("VM-entry MSR-load address      = %016llx", VmxRead(VMCS_CTRL_VMENTRY_MSR_LOAD_ADDRESS));
    LOG_ERROR("Executive-VMCS pointer         = %016llx", VmxRead(VMCS_CTRL_EXECUTIVE_VMCS_POINTER));
    LOG_ERROR("PML address                    = %016llx", VmxRead(VMCS_CTRL_PML_ADDRESS));
    LOG_ERROR("TSC offset                     = %016llx", VmxRead(VMCS_CTRL_TSC_OFFSET));
    LOG_ERROR("Virtual-APIC address           = %016llx", VmxRead(VMCS_CTRL_VIRTUAL_APIC_ADDRESS));
    LOG_ERROR("APIC-access address            = %016llx", VmxRead(VMCS_CTRL_APIC_ACCESS_ADDRESS));
    LOG_ERROR("Posted-interrupt descriptor address = %016llx", VmxRead(VMCS_CTRL_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS));
    LOG_ERROR("VM-function controls           = %016llx", VmxRead(VMCS_CTRL_VMFUNC_CONTROLS));
    LOG_ERROR("EPT pointer                    = %016llx", VmxRead(VMCS_CTRL_EPT_POINTER));
    LOG_ERROR("EOI-exit bitmap 0              = %016llx", VmxRead(VMCS_CTRL_EOI_EXIT_BITMAP_0));
    LOG_ERROR("EOI-exit bitmap 1              = %016llx", VmxRead(VMCS_CTRL_EOI_EXIT_BITMAP_1));
    LOG_ERROR("EOI-exit bitmap 2              = %016llx", VmxRead(VMCS_CTRL_EOI_EXIT_BITMAP_2));
    LOG_ERROR("EOI-exit bitmap 3              = %016llx", VmxRead(VMCS_CTRL_EOI_EXIT_BITMAP_3));
    LOG_ERROR("EPTP-list address              = %016llx", VmxRead(VMCS_CTRL_EPT_POINTER_LIST_ADDRESS));
    LOG_ERROR("VMREAD-bitmap address          = %016llx", VmxRead(VMCS_CTRL_VMREAD_BITMAP_ADDRESS));
    LOG_ERROR("VMWRITE-bitmap address         = %016llx", VmxRead(VMCS_CTRL_VMWRITE_BITMAP_ADDRESS));
    LOG_ERROR("Virtualization-exception information address = %016llx", VmxRead(VMCS_CTRL_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS));
    LOG_ERROR("XSS-exiting bitmap             = %016llx", VmxRead(VMCS_CTRL_XSS_EXITING_BITMAP));
    LOG_ERROR("ENCLS-exiting bitmap           = %016llx", VmxRead(VMCS_CTRL_ENCLS_EXITING_BITMAP));
    LOG_ERROR("TSC multiplier                 = %016llx", VmxRead(VMCS_CTRL_TSC_MULTIPLIER));

    //
    // 32-Bit Control Fields
    //
    LOG_ERROR("Pin-based VM-execution controls = %016llx", VmxRead(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS));
    LOG_ERROR("Primary processor-based VM-execution controls = %016llx", VmxRead(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS));
    LOG_ERROR("Exception bitmap               = %016llx", VmxRead(VMCS_CTRL_EXCEPTION_BITMAP));
    LOG_ERROR("Page-fault error-code mask     = %016llx", VmxRead(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK));
    LOG_ERROR("Page-fault error-code match    = %016llx", VmxRead(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH));
    LOG_ERROR("CR3-target count               = %016llx", VmxRead(VMCS_CTRL_CR3_TARGET_COUNT));
    LOG_ERROR("VM-exit controls               = %016llx", VmxRead(VMCS_CTRL_VMEXIT_CONTROLS));
    LOG_ERROR("VM-exit MSR-store count        = %016llx", VmxRead(VMCS_CTRL_VMEXIT_MSR_STORE_COUNT));
    LOG_ERROR("VM-exit MSR-load count         = %016llx", VmxRead(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT));
    LOG_ERROR("VM-entry controls              = %016llx", VmxRead(VMCS_CTRL_VMENTRY_CONTROLS));
    LOG_ERROR("VM-entry MSR-load count        = %016llx", VmxRead(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT));
    LOG_ERROR("VM-entry interruption-information field = %016llx", VmxRead(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD));
    LOG_ERROR("VM-entry exception error code  = %016llx", VmxRead(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE));
    LOG_ERROR("VM-entry instruction length    = %016llx", VmxRead(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH));
    LOG_ERROR("TPR threshold                  = %016llx", VmxRead(VMCS_CTRL_TPR_THRESHOLD));
    LOG_ERROR("Secondary processor-based VM-execution controls = %016llx", VmxRead(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS));
    LOG_ERROR("PLE_Gap                        = %016llx", VmxRead(VMCS_CTRL_PLE_GAP));
    LOG_ERROR("PLE_Window                     = %016llx", VmxRead(VMCS_CTRL_PLE_WINDOW));

    //
    // Natural-Width Control Fields
    //
    LOG_ERROR("CR0 guest/host mask            = %016llx", VmxRead(VMCS_CTRL_CR0_GUEST_HOST_MASK));
    LOG_ERROR("CR4 guest/host mask            = %016llx", VmxRead(VMCS_CTRL_CR4_GUEST_HOST_MASK));
    LOG_ERROR("CR0 read shadow                = %016llx", VmxRead(VMCS_CTRL_CR0_READ_SHADOW));
    LOG_ERROR("CR4 read shadow                = %016llx", VmxRead(VMCS_CTRL_CR4_READ_SHADOW));
    LOG_ERROR("CR3-target value 0             = %016llx", VmxRead(VMCS_CTRL_CR3_TARGET_VALUE_0));
    LOG_ERROR("CR3-target value 1             = %016llx", VmxRead(VMCS_CTRL_CR3_TARGET_VALUE_1));
    LOG_ERROR("CR3-target value 2             = %016llx", VmxRead(VMCS_CTRL_CR3_TARGET_VALUE_2));
    LOG_ERROR("CR3-target value 3             = %016llx", VmxRead(VMCS_CTRL_CR3_TARGET_VALUE_3));
}

_Use_decl_annotations_
VOID
VmxWrite (
    VMCS_FIELD Field,
    UINT64 FieldValue
    )
{
    VMX_RESULT result;

    result = __vmx_vmwrite(Field, FieldValue);
    if (result != VmxResultOk)
    {
        VMX_ERROR_NUMBER vmxErrorStatus;

        vmxErrorStatus = (result == VmxResultErrorWithStatus) ?
            (VMX_ERROR_NUMBER)VmxRead(VMCS_VM_INSTRUCTION_ERROR) : 0;
        if (vmxErrorStatus != VMX_ERROR_VMREAD_VMWRITE_INVALID_COMPONENT)
        {
            MV_PANIC();
        }
    }
}

_Use_decl_annotations_
UINT64
VmxRead (
    VMCS_FIELD Field
    )
{
    VMX_RESULT result;
    UINT64 fieldValue;

    result = __vmx_vmread(Field, &fieldValue);
    if (result != VmxResultOk)
    {
        VMX_ERROR_NUMBER vmxErrorStatus;

        vmxErrorStatus = (result == VmxResultErrorWithStatus) ?
            (VMX_ERROR_NUMBER)VmxRead(VMCS_VM_INSTRUCTION_ERROR) : 0;
        if (vmxErrorStatus != VMX_ERROR_VMREAD_VMWRITE_INVALID_COMPONENT)
        {
            MV_PANIC();
        }
        fieldValue = 0;
    }
    return fieldValue;
}

_Use_decl_annotations_
VOID
AdvanceGuestInstructionPointer (
    GUEST_CONTEXT* GuestContext
    )
{
    UINT64 exitInstructionLength;

    exitInstructionLength = VmxRead(VMCS_VMEXIT_INSTRUCTION_LENGTH);
    GuestContext->VmcsBasedRegisters.Rip += exitInstructionLength;
    VmxWrite(VMCS_GUEST_RIP, GuestContext->VmcsBasedRegisters.Rip);
}

_Use_decl_annotations_
BOOLEAN
IsGuestInKernelMode (
    )
{
    VMX_SEGMENT_ACCESS_RIGHTS accessRight;

    accessRight.Flags = (UINT32)VmxRead(VMCS_GUEST_SS_ACCESS_RIGHTS);
    return (accessRight.DescriptorPrivilegeLevel == 0);
}

_Use_decl_annotations_
VOID
InjectInterruption (
    INTERRUPTION_TYPE InterruptionType,
    EXCEPTION_VECTOR Vector,
    BOOLEAN DeliverErrorCode,
    UINT32 ErrorCode
    )
{
    VMENTRY_INTERRUPT_INFORMATION interruptToInject;

    interruptToInject.Flags = 0;
    interruptToInject.Valid = TRUE;
    interruptToInject.InterruptionType = (UINT32)InterruptionType;
    interruptToInject.Vector = (UINT32)Vector;
    interruptToInject.DeliverErrorCode = DeliverErrorCode;
    VmxWrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, interruptToInject.Flags);

    if (DeliverErrorCode != FALSE)
    {
        VmxWrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, ErrorCode);
    }
}

_Use_decl_annotations_
VOID
SwitchGuestPagingMode (
    CR0 NewGuestCr0
    )
{
    IA32_EFER_REGISTER guestEfer;
    IA32_VMX_ENTRY_CTLS_REGISTER vmEntryControls;

    //
    // "Enable paging by setting CR0.PG = 1. This causes the processor to set the
    //  IA32_EFER.LMA bit to 1."
    // See: 9.8.5 Initializing IA-32e Mode
    //
    // "The processor always sets IA32_EFER.LMA to CR0.PG & IA32_EFER.LME.
    //  Software cannot directly modify IA32_EFER.LMA; an execution of WRMSR to
    //  the IA32_EFER MSR ignores bit 10 of its source operand."
    // See: 4.1.1 Three Paging Modes
    //
    guestEfer.Flags = VmxRead(VMCS_GUEST_EFER);
    guestEfer.Ia32EModeActive = (NewGuestCr0.PagingEnable & guestEfer.Ia32EModeEnable);
    VmxWrite(VMCS_GUEST_EFER, guestEfer.Flags);

    //
    // Apply the paging mode change in the VM-entry control VMCS field too.
    //
    vmEntryControls.Flags = VmxRead(VMCS_CTRL_VMENTRY_CONTROLS);
    vmEntryControls.Ia32EModeGuest = guestEfer.Ia32EModeActive;
    VmxWrite(VMCS_CTRL_VMENTRY_CONTROLS, vmEntryControls.Flags);

    //
    // Changing the paging mode results in invalidating TLB. Emulate this by
    // invalidating combined caches (GVA to HPA translation caches).
    //
    InvalidateVpidDerivedCache((UINT16)VmxRead(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER));
}

_Use_decl_annotations_
CR0
AdjustGuestCr0 (
    CR0 Cr0
    )
{
    CR0 newCr0;
    IA32_VMX_PROCBASED_CTLS2_REGISTER secondaryProcBasedControls;

    newCr0 = AdjustCr0(Cr0);

    //
    // When the UnrestrictedGuest bit is set, ProtectionEnable and PagingEnable
    // bits are allowed to be zero. Make this adjustment, by setting them 1 only
    // when the guest did indeed requested them to be 1 (ie,
    // Cr0.ProtectionEnable == 1) and the FIXED0 MSR indicated them to be 1 (ie,
    // newCr0.ProtectionEnable == 1).
    //
    secondaryProcBasedControls.Flags = VmxRead(
                    VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    if (secondaryProcBasedControls.UnrestrictedGuest != FALSE)
    {
        newCr0.ProtectionEnable &= Cr0.ProtectionEnable;
        newCr0.PagingEnable &= Cr0.PagingEnable;
    }
    return newCr0;
}

_Use_decl_annotations_
CR4
AdjustGuestCr4 (
    CR4 Cr4
    )
{
    return AdjustCr4(Cr4);
}

_Use_decl_annotations_
UINT64
FindImageBase (
    GUEST_CONTEXT* GuestContext,
    UINT64 GuestVirtualAddress
    )
{
    UINT64 imageBase;

    //
    // Starting with the page aligned address, and search up IMAGE_DOS_SIGNATURE
    // every page up to 16MB (0x1000000). Ntoskrnl.exe can be mapped at the page
    // boundary and not the 64KB boundary unlike other images.
    //
    imageBase = (GuestVirtualAddress & ~(PAGE_SIZE - 1));

    for (int i = 0; i < 0x1000; i++, imageBase -= PAGE_SIZE)
    {
        BOOLEAN ok;
        UINT16 contents;
        MEMORY_ACCESS_ERROR_INFORMATION errorInfo;

        ok = ReadGuestVirtualAddress(GuestContext->Contexts->MemoryAccessContext,
                                     TRUE,
                                     imageBase,
                                     &contents,
                                     sizeof(contents),
                                     &errorInfo);
        if (ok == FALSE)
        {
            continue;
        }

        if (contents == 0x5A4D)
        {
            goto Exit;
        }
    }

    imageBase = 0;

Exit:
    return imageBase;
}

_Use_decl_annotations_
VOID
UpdateMsrBitmaps (
    MSR_BITMAPS* Bitmaps,
    IA32_MSR_ADDRESS Msr,
    OPERATION_TYPE InterOperation,
    BOOLEAN Intercept
    )
{
    IA32_MSR_ADDRESS msrTemp;
    BOOLEAN highValue;
    UINT64 byteOffset;
    UINT64 bitMask;
    UINT8* msrBitmap;

    //
    // MSR must be within either 0x0 - 0x1fff or 0xc0000000 - 0xc0001fff
    // inclusive, and at least read or write intercept must be specified.
    //
    MV_ASSERT((Msr <= 0x1fff) ||
              ((Msr >= 0xc0000000) && (Msr <= 0xc0001fff)));

    //
    // Check if the MSR belongs to high bitmaps.
    //
    highValue = BooleanFlagOn(Msr, 0xc0000000);

    //
    // Computes offsets and bitmaps to update the bitmaps.
    //
    msrTemp = (Msr & ~0xc0000000);
    byteOffset = (msrTemp / CHAR_BIT);
    bitMask = (1ull << (msrTemp % CHAR_BIT));

    //
    // Select the bitmap to work on.
    //
    if (InterOperation == OperationRead)
    {
        if (highValue == FALSE)
        {
            msrBitmap = Bitmaps->ReadBitmapLow;
        }
        else
        {
            msrBitmap = Bitmaps->ReadBitmapHigh;
        }
    }
    else
    {
        if (highValue == FALSE)
        {
            msrBitmap = Bitmaps->WriteBitmapLow;
        }
        else
        {
            msrBitmap = Bitmaps->WriteBitmapHigh;
        }
    }

    //
    // Set of clear the bit.
    //
    if (Intercept != FALSE)
    {
        SetFlag(msrBitmap[byteOffset], bitMask);
    }
    else
    {
        ClearFlag(msrBitmap[byteOffset], bitMask);
    }
}

_Use_decl_annotations_
VOID
SetNmiWindowExiting (
    BOOLEAN Enable
    )
{
    IA32_VMX_PROCBASED_CTLS_REGISTER primaryProcBasedControls;

    primaryProcBasedControls.Flags = VmxRead(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS);
    primaryProcBasedControls.NmiWindowExiting = Enable;
    VmxWrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, primaryProcBasedControls.Flags);
}
