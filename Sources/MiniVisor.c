/*!
    @file MiniVisor.c

    @brief MiniVisor initialization.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "MiniVisor.h"
#include "Asm.h"
#include "HostInitialization.h"
#include "ExtendedPageTables.h"
#include "Platform.h"
#include "MemoryManager.h"
#include "Logger.h"
#include "Public.h"
#include "MemoryType.h"
#include "HostNesting.h"
#include "Ia32Utils.h"
#include "MemoryAccess.h"

//
// Memory layout of hypervisor stack which is constructed by the kernel-mode
// code.
//
typedef struct _HYPERVISOR_INITIAL_STACK_DATA
{
    union
    {
        //
        //  Low     StackLimit[0]                        StackLimit
        //  ^       ...
        //  ^       ...                                  Layout.Context (StackBase)
        //  ^       ...
        //  ^       StackLimit[KERNEL_STACK_SIZE - 2]
        //  High    StackLimit[KERNEL_STACK_SIZE - 1]
        //
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 StackLimit[KERNEL_STACK_SIZE];
        struct
        {
            //
            // Available for the hypervisor to freely use.
            //
            UINT8 AvailableAsStack[KERNEL_STACK_SIZE - sizeof(HYPERVISOR_CONTEXT)];

            //
            // Set up by the kernel-mode code before starting the hypervisor.
            // The hypervisor never overwrites this contents.
            //
            HYPERVISOR_CONTEXT Context;
        } Layout;
    } u;
} HYPERVISOR_INITIAL_STACK_DATA;
C_ASSERT(sizeof(HYPERVISOR_INITIAL_STACK_DATA) == KERNEL_STACK_SIZE);

//
// Data structure used for virtualizing a processor. Allocated one for each
// processor on the system within the ALL_PROCESSORS_CONTEXTS structure.
// This structure is freed after virtualization is terminated because many of
// those data is used by the hypervisor or the processors indirectly. For example,
// th VmcsRegion member must be valid for the processor to perform VMX operations,
// and HypervisorStack too for the hypervisor to run.
//
typedef struct _PER_PROCESSOR_CONTEXT
{
    //
    // Indicates a result of the EnableHypervisor function.
    //
    MV_STATUS Status;

    //
    // The initial RSP value used for the guest (i.e., the initial value set
    // right after VMLAUNCH).
    //
    UINT64 GuestStackPointer;

    //
    // The initial RIP value used for the guest (i.e., the initial value set
    // right after VMLAUNCH).
    //
    UINT64 GuestInstructionPointer;

    //
    // The EPT related context for this processor.
    //
    EPT_CONTEXT EptContext;

    //
    // The context structure used to track state related to accessing guest
    // virtual memory address space from the hypervisor.
    //
    MEMORY_ACCESS_CONTEXT MemoryAccessContext;

    //
    // The context structure used to track state of the nested hypervisor.
    //
    NEXTED_VMX_CONTEXT NestedVmxContext;

    //
    // The global descriptor table (GDT) for the host. The size (16 entries) is
    // just a large enough size for systems seen during development. One could
    // dynamically allocate this table according with the Limit field of the GDTR
    // if wish to do so.
    //
    SEGMENT_DESCRIPTOR_64 HostGuestGdt[16];

    //
    // The task state segment (TSS) used for both the guest and the host if the
    // system does not configure it. This is the case on EFI environment.
    //
    TASK_STATE_SEGMENT_64 HostGuestTss;

    //
    // The copy of GDTR taken before MiniVisor is installed. Used during unload
    // to restore the value to original.
    //
    GDTR OriginalGdtr;

    //
    // The page-aligned, 4KB-size region used for the VMXON instruction.
    //
    DECLSPEC_ALIGN(PAGE_SIZE) VMXON VmxOnRegion;

    //
    // The page-aligned, 4KB size region used for the VMX operations such as
    // VMREAD, VM-exits and -entry.
    //
    DECLSPEC_ALIGN(PAGE_SIZE) VMCS VmcsRegion;

    //
    // The page-aligned region used as a hypervisor's stack. Some data is
    // populated by set up code before hypervisor starts.
    //
    DECLSPEC_ALIGN(PAGE_SIZE) HYPERVISOR_INITIAL_STACK_DATA HypervisorStack;
} PER_PROCESSOR_CONTEXT;

//
// Data shared across all processors during virtualization of them and execution
// of the hypervisor. Allocated once in the EnableHypervisorOnAllProcessors
// function and freed in the DisableHypervisorOnAllProcessors function.
//
typedef struct _SHARED_PROCESSOR_CONTEXT
{
    //
    // The number of the PER_PROCESSOR_CONTEXT data in the Contexts member. It
    // equals to the number of logical processors on the system.
    //
    UINT32 NumberOfContexts;

    //
    // The MSR bitmap used across all processors.
    //
    DECLSPEC_ALIGN(PAGE_SIZE) MSR_BITMAPS MsrBitmaps;

    //
    // An array of PER_PROCESSOR_CONTEXTs. Each context is associated with and
    // used by one logical processor exclusively.
    //
    PER_PROCESSOR_CONTEXT Contexts[ANYSIZE_ARRAY];
} SHARED_PROCESSOR_CONTEXT;

/*!
    @brief Returns the VM control value that is adjusted in consideration with
        the VMX capability MSR.

    @param[in] VmxCapabilityMsr - The VMX capability MSR to consult to adjust the
        RequestedValue,

    @param[in] RequestedValue - The VM control value that needs adjustment.

    @return The adjusted control value.
 */
static
UINT32
AdjustControlValue (
    _In_ IA32_MSR_ADDRESS VmxCapabilityMsr,
    _In_ UINT32 RequestedValue
    )
{
    IA32_VMX_TRUE_CTLS_REGISTER capabilities;
    UINT32 effectiveValue;

    MV_ASSERT((VmxCapabilityMsr == IA32_VMX_PINBASED_CTLS) ||
              (VmxCapabilityMsr == IA32_VMX_PROCBASED_CTLS) ||
              (VmxCapabilityMsr == IA32_VMX_EXIT_CTLS) ||
              (VmxCapabilityMsr == IA32_VMX_ENTRY_CTLS) ||
              (VmxCapabilityMsr == IA32_VMX_TRUE_PINBASED_CTLS) ||
              (VmxCapabilityMsr == IA32_VMX_TRUE_PROCBASED_CTLS) ||
              (VmxCapabilityMsr == IA32_VMX_TRUE_EXIT_CTLS) ||
              (VmxCapabilityMsr == IA32_VMX_TRUE_ENTRY_CTLS) ||
              (VmxCapabilityMsr == IA32_VMX_PROCBASED_CTLS2));

    capabilities.Flags = __readmsr(VmxCapabilityMsr);
    effectiveValue = RequestedValue;

    //
    // Each bit of the following VMCS values might have to be set or cleared
    // according with the value indicated by the VMX capability MSRs.
    //  - pin-based VM-execution controls,
    //  - primary processor-based VM-execution controls,
    //  - secondary processor-based VM-execution controls.
    //
    // The VMX capability MSR is composed of two 32bit values, the lower 32bits
    // indicate bits can be 0, and the higher 32bits indicates bits can be 1.
    // In other words, they indicate bits MUST BE 1 and MUST BE 0 respectively.
    // The following logic enforces this logic by setting bits that must be 1,
    // and clearing bits that must be 0.
    //
    // See: A.3.1 Pin-Based VM-Execution Controls
    // See: A.3.2 Primary Processor-Based VM-Execution Controls
    // See: A.3.3 Secondary Processor-Based VM-Execution Controls
    //
    effectiveValue |= capabilities.Allowed0Settings;
    effectiveValue &= capabilities.Allowed1Settings;
    return effectiveValue;
}

/*!
    @brief Adjusts a pin-based control value in consideration with the VMX
        capability MSR.

    @param[in,out] PinBasedControls - The pointer to the pin-based control value
        to adjust.
 */
static
VOID
AdjustPinBasedControls (
    _Inout_ IA32_VMX_PINBASED_CTLS_REGISTER* PinBasedControls
    )
{
    IA32_MSR_ADDRESS vmxCapabilityMsr;
    IA32_VMX_BASIC_REGISTER vmxBasicMsr;

    //
    // This determines the right VMX capability MSR based on the value of
    // IA32_VMX_BASIC. With the right VMX capability MSR, the
    // AdjustControlValue function implements the logic described as below.
    // "It is necessary for software to consult only one of the capability MSRs
    //  to determine the allowed settings of the pin based VM-execution controls:"
    // See: A.3.1 Pin-Based VM-Execution Controls
    //
    vmxBasicMsr.Flags = __readmsr(IA32_VMX_BASIC);
    vmxCapabilityMsr = (vmxBasicMsr.VmxControls != FALSE) ?
        IA32_VMX_TRUE_PINBASED_CTLS : IA32_VMX_PINBASED_CTLS;

    PinBasedControls->Flags = AdjustControlValue(vmxCapabilityMsr,
                                                 (UINT32)PinBasedControls->Flags);
}

/*!
    @brief Adjusts a processor-based control value in consideration with the VMX
        capability MSR.

    @param[in,out] PrimaryProcBasedControls - The pointer to the processor-based
        control value to adjust.
 */
static
VOID
AdjustProcessorBasedControls (
    _Inout_ IA32_VMX_PROCBASED_CTLS_REGISTER* PrimaryProcBasedControls
    )
{
    IA32_MSR_ADDRESS vmxCapabilityMsr;
    IA32_VMX_BASIC_REGISTER vmxBasicMsr;

    //
    // See AdjustPinBasedControls for the details of the below logic.
    //
    vmxBasicMsr.Flags = __readmsr(IA32_VMX_BASIC);
    vmxCapabilityMsr = (vmxBasicMsr.VmxControls != FALSE) ?
        IA32_VMX_TRUE_PROCBASED_CTLS : IA32_VMX_PROCBASED_CTLS;

    PrimaryProcBasedControls->Flags = AdjustControlValue(
                                        vmxCapabilityMsr,
                                        (UINT32)PrimaryProcBasedControls->Flags);
}

/*!
    @brief Adjusts a VM-exit control value in consideration with the VMX
        capability MSR.

    @param[in,out] VmExitControls - The pointer to the VM-exit control value to
        adjust.
 */
static
VOID
AdjustVmExitControls (
    _Inout_ IA32_VMX_EXIT_CTLS_REGISTER* VmExitControls
    )
{
    IA32_MSR_ADDRESS vmxCapabilityMsr;
    IA32_VMX_BASIC_REGISTER vmxBasicMsr;

    //
    // See AdjustPinBasedControls for the details of the below logic.
    //
    vmxBasicMsr.Flags = __readmsr(IA32_VMX_BASIC);
    vmxCapabilityMsr = (vmxBasicMsr.VmxControls != FALSE) ?
        IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS;

    VmExitControls->Flags = AdjustControlValue(vmxCapabilityMsr,
                                               (UINT32)VmExitControls->Flags);
}

/*!
    @brief Adjusts a VM-entry control value in consideration with the VMX
        capability MSR.

    @param[in,out] VmEntryControls - The pointer to the VM-entry control value to
        adjust.
 */
static
VOID
AdjustVmEntryControls (
    _Inout_ IA32_VMX_ENTRY_CTLS_REGISTER* VmEntryControls
    )
{
    IA32_MSR_ADDRESS vmxCapabilityMsr;
    IA32_VMX_BASIC_REGISTER vmxBasicMsr;

    //
    // See AdjustPinBasedControls for the details of the below logic.
    //
    vmxBasicMsr.Flags = __readmsr(IA32_VMX_BASIC);
    vmxCapabilityMsr = (vmxBasicMsr.VmxControls != FALSE) ?
        IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;

    VmEntryControls->Flags = AdjustControlValue(vmxCapabilityMsr,
                                                (UINT32)VmEntryControls->Flags);
}

/*!
    @brief Adjusts a secondary processor-based control value in consideration
        with the VMX capability MSR.

    @param[in,out] SecondaryProcBasedControls - The pointer to the secondary
        processor-based control value to adjust.
 */
static
VOID
AdjustSecondaryProcessorBasedControls (
    _Inout_ IA32_VMX_PROCBASED_CTLS2_REGISTER* SecondaryProcBasedControls
    )
{
    //
    // There is no TRUE MSR for IA32_VMX_PROCBASED_CTLS2. Just use
    // IA32_VMX_PROCBASED_CTLS2 unconditionally.
    //
    SecondaryProcBasedControls->Flags = AdjustControlValue(
                                        IA32_VMX_PROCBASED_CTLS2,
                                        (UINT32)SecondaryProcBasedControls->Flags);
}

/*!
    @brief Tests whether our hypervisor is installed on the system.

    @return TRUE when our hypervisor is installed on the system; otherwise FALSE.
 */
static
_Must_inspect_result_
BOOLEAN
IsMiniVisorInstalled (
    )
{
    int registers[4];   // EAX, EBX, ECX, and EDX
    char vendorId[13];

    //
    // When our hypervisor is installed, CPUID leaf 40000000h will return
    // "MiniVisor   " as the vendor name.
    //
    __cpuid(registers, CPUID_HV_VENDOR_AND_MAX_FUNCTIONS);
    RtlCopyMemory(vendorId + 0, &registers[1], sizeof(registers[1]));
    RtlCopyMemory(vendorId + 4, &registers[2], sizeof(registers[2]));
    RtlCopyMemory(vendorId + 8, &registers[3], sizeof(registers[3]));
    vendorId[12] = ANSI_NULL;

    return (strcmp(vendorId, "MiniVisor   ") == 0);
}

/*!
    @brief Disables the hypervisor on the current processor.

    @param[in,out] Context - The pointer to the location to receive the address of
        the shared processor context.
 */
MV_SECTION_PAGED
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
DisableHypervisor (
    _Inout_ VOID* Context
    )
{
    SHARED_PROCESSOR_CONTEXT* returnedAddress;
    SHARED_PROCESSOR_CONTEXT** sharedProcessorContextsAddress;
    PER_PROCESSOR_CONTEXT* processorContext;

    PAGED_CODE();

    if (IsMiniVisorInstalled() == FALSE)
    {
        goto Exit;
    }

    //
    // Issues the hypercall to uninstall the hypervisor. This hypercall returns
    // the address of the shared processor context on success.
    //
    returnedAddress = (SHARED_PROCESSOR_CONTEXT*)AsmVmxCall(VmcallUninstall, 0, 0, 0);
    MV_ASSERT(returnedAddress != NULL);

    //
    // Context here is shared across all processors and could already be set the
    // address of the shared processor context by the other processors. This assert
    // says the address specified by the Context is either not updated yet (== NULL)
    // or updated by the same value as this processor has received (== returnedAddress
    // == the address of the shared processor context).
    //
    sharedProcessorContextsAddress = Context;
    MV_ASSERT((*sharedProcessorContextsAddress == NULL) ||
              (*sharedProcessorContextsAddress == returnedAddress));
    *sharedProcessorContextsAddress = returnedAddress;

    //
    // Clean up the per-processor data structures.
    //
    processorContext = &(*sharedProcessorContextsAddress)->Contexts[GetCurrentProcessorNumber()];
    CleanupExtendedPageTables(&processorContext->EptContext);
    CleanupMemoryAccess(&processorContext->MemoryAccessContext);
    CleanupGdt(&processorContext->OriginalGdtr);

Exit:
    MV_ASSERT(IsMiniVisorInstalled() == FALSE);
}

/*!
    @brief Disables the hypervisor on the all processors.
 */
MV_SECTION_PAGED
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
DisableHypervisorOnAllProcessors (
    )
{
    SHARED_PROCESSOR_CONTEXT* sharedProcessorContext;

    PAGED_CODE();

    sharedProcessorContext = NULL;
    RunOnAllProcessors(DisableHypervisor, &sharedProcessorContext);
    if (sharedProcessorContext != NULL)
    {
        MmFreePages(sharedProcessorContext);
    }
}

/*!
    @brief Tests whether VT-x is available with required capabilities for this
        hypervisor.

    @return TRUE when VT-x is available for this hypervisor; otherwise FALSE.
 */
static
_Must_inspect_result_
BOOLEAN
IsVmxAvailable (
    )
{
    BOOLEAN vmxAvailable;
    int registers[4];
    CPUID_EAX_01 cpuidVersionInfo;
    IA32_VMX_BASIC_REGISTER vmxBasicMsr;
    IA32_FEATURE_CONTROL_REGISTER vmxFeatureControlMsr;
    IA32_VMX_EPT_VPID_CAP_REGISTER eptVpidCapabilityMsr;

    vmxAvailable = FALSE;

    //
    // "If CPUID.1:ECX.VMX[bit 5] = 1, then VMX operation is supported."
    // See: 23.6 DISCOVERING SUPPORT FOR VMX
    //
    __cpuid(registers, CPUID_VERSION_INFORMATION);
    cpuidVersionInfo.CpuidFeatureInformationEcx.Flags = (UINT32)registers[2];
    if (cpuidVersionInfo.CpuidFeatureInformationEcx.VirtualMachineExtensions == FALSE)
    {
        LOG_ERROR("VT-x is not available.");
        goto Exit;
    }

    //
    // Check the processor support the write-back type for VMCS. We do not
    // support the processor that does not support the write-back type for
    // simplicity. It is practically not an issue since
    // "As of this writing, all processors that support VMX operation indicate
    //  the write-back type."
    //
    // Note that supporting the write-back type means we can access virtual
    // memory holding VMCS as Windows allocates, as the write-back is the default
    // memory type Windows uses.
    //
    // See: A.1 BASIC VMX INFORMATION
    //
    vmxBasicMsr.Flags = __readmsr(IA32_VMX_BASIC);
    if (vmxBasicMsr.MemoryType != MEMORY_TYPE_WRITE_BACK)
    {
        LOG_ERROR("The write-back type is not supported on this processor.");
        goto Exit;
    }

    //
    // Check that:
    //  - the lock bit is set
    //  - the VMXON outside SMX operation bit is set
    //
    // "To enable VMX support in a platform, BIOS must set bit 1, bit 2, or both
    //  (see below), as well as the lock bit."
    // See: 23.7 ENABLING AND ENTERING VMX OPERATION
    //
    vmxFeatureControlMsr.Flags = __readmsr(IA32_FEATURE_CONTROL);
    if ((vmxFeatureControlMsr.LockBit == FALSE) ||
        (vmxFeatureControlMsr.EnableVmxOutsideSmx == FALSE))
    {
        LOG_ERROR("The lock bit is not set, or VMXON outside SMX is unsupported.");
        goto Exit;
    }

    //
    // Check the followings to confirm availability of EPT related capabilities.
    //
    eptVpidCapabilityMsr.Flags = __readmsr(IA32_VMX_EPT_VPID_CAP);
    if ((eptVpidCapabilityMsr.PageWalkLength4 == FALSE) ||
        (eptVpidCapabilityMsr.MemoryTypeWriteBack == FALSE) ||
        (eptVpidCapabilityMsr.Pde2MbPages == FALSE) ||
        (eptVpidCapabilityMsr.Invept == FALSE) ||
        (eptVpidCapabilityMsr.InveptSingleContext == FALSE) ||
        (eptVpidCapabilityMsr.InveptAllContexts == FALSE) ||
        (eptVpidCapabilityMsr.Invvpid == FALSE) ||
        (eptVpidCapabilityMsr.InvvpidSingleContext == FALSE) ||
        (eptVpidCapabilityMsr.InvvpidAllContexts == FALSE))
    {
        LOG_ERROR("EPT is not supported.");
        goto Exit;
    }

    vmxAvailable = TRUE;

Exit:
    return vmxAvailable;
}

/*!
    @brief Sets up a VMCS and initial hypervisor stack values.

    @details This function roughly follows the sequence stated in the Intel SDM
        to set up hypervisor.
        See: 31.5 VMM SETUP & TEAR DOWN
        See: 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE

    @param[in] SharedProcessorContext - The pointer to the shared processor context.

    @param[in,out] ProcessorContext - The pointer to the per-processor context
        for this processor.

    @return MV_STATUS_SUCCESS on success, or an appropriate status code on error.
 */
static
_Must_inspect_result_
MV_STATUS
SetupVmcs (
    _In_ SHARED_PROCESSOR_CONTEXT* SharedProcessorContext,
    _Inout_ PER_PROCESSOR_CONTEXT* ProcessorContext
    )
{
    //
    // Masks RPL (bits 1:0) and the TI flag (bit 2) of segment selectors.
    //
    static const UINT32 hostSegmentSelectorMask = 0x7;

    MV_STATUS status;
    CR0 newCr0;
    CR4 newCr4;
    IA32_VMX_BASIC_REGISTER vmxBasicMsr;
    UINT64 vmxOnPa, vmcsPa;
    BOOLEAN vmxOn, eptInitialized;
    GDTR gdtr;
    IDTR idtr;
    IA32_VMX_ENTRY_CTLS_REGISTER vmEntryControls;
    IA32_VMX_EXIT_CTLS_REGISTER vmExitControls;
    IA32_VMX_PINBASED_CTLS_REGISTER pinBasedControls;
    IA32_VMX_PROCBASED_CTLS_REGISTER primaryProcBasedControls;
    IA32_VMX_PROCBASED_CTLS2_REGISTER secondaryProcBasedControls;
    UINT64 hypervisorStackPointer;
    UINT32 exceptionBitmap;

    vmxOn = FALSE;
    eptInitialized = FALSE;

    //
    // First things first. Check the availability of VT-x to run MiniVisor.
    //
    // "Check VMX support in processor using CPUID."
    // "Determine the VMX capabilities supported by the processor through the
    //  VMX capability MSRs."
    // See: 31.5 VMM SETUP & TEAR DOWN
    //
    if (IsVmxAvailable() == FALSE)
    {
        LOG_ERROR("IsVmxAvailable failed.");
        status = MV_STATUS_HV_OPERATION_FAILED;
        goto Exit;
    }

    //
    // VMX requires TR to be configured properly (ie, non zero). This requirement
    // is not satisfied yet in case of EFI environment. Set it up by updating
    // GDT as necessary.
    //
    // "The selector fields for CS and TR cannot be 0000H."
    // See: 26.2.3 Checks on Host Segment and Descriptor-Table Registers
    //
    // "TR. The different sub-fields are considered separately:"
    // See: 26.3.1.2 Checks on Guest Segment Registers
    //
    InitializeGdt(&ProcessorContext->HostGuestTss,
                  ProcessorContext->HostGuestGdt,
                  sizeof(ProcessorContext->HostGuestGdt),
                  &ProcessorContext->OriginalGdtr);
    MV_ASSERT(AsmReadTr() != 0);

    //
    // The per-processor context contains the VMXON region that is aligned to a
    // 4-KByte boundary. We also made sure that VMXON region can be accessed
    // through the write-back memory type in the IsVmxAvailable function.
    //
    // "Create a VMXON region in non-pageable memory of a size specified by
    //  IA32_VMX_BASIC MSR and aligned to a 4-KByte boundary. (...) Also,
    //  software must ensure that the VMXON region is hosted in cache-coherent
    //  memory."
    // See: 31.5 VMM SETUP & TEAR DOWN
    //
    MV_ASSERT(PAGE_ALIGN(&ProcessorContext->VmxOnRegion) == &ProcessorContext->VmxOnRegion);

    //
    // "Initialize the version identifier in the VMXON region (the first 31 bits)
    //  with the VMCS revision identifier reported by capability MSRs. Clear bit
    //  31 of the first 4 bytes of the VMXON region"
    // See: 31.5 VMM SETUP & TEAR DOWN
    //
    vmxBasicMsr.Flags = __readmsr(IA32_VMX_BASIC);
    ProcessorContext->VmxOnRegion.RevisionId = (UINT32)vmxBasicMsr.VmcsRevisionId;
    MV_ASSERT(ProcessorContext->VmxOnRegion.MustBeZero == 0);

    //
    // In order to enter the VMX-mode, the bits in CR0 and CR4 have to be
    // certain values as indicated by the FIXED0 and FIXED1 MSRs. The rule is
    // summarized as below:
    //
    //        IA32_VMX_CRx_FIXED0 IA32_VMX_CRx_FIXED1 Meaning
    // Bit X  1                   (Always 1)          The bit X of CRx is fixed to 1
    // Bit X  0                   1                   The bit X of CRx is flexible
    // Bit X  (Always 0)          0                   The bit X of CRx is fixed to 0
    //
    // See: A.7 VMX-FIXED BITS IN CR0
    //
    // "Ensure the current processor operating mode meets the required CR0 fixed
    //  bits (...). Other required CR0 fixed bits can be detected through the
    //  IA32_VMX_CR0_FIXED0 and IA32_VMX_CR0_FIXED1 MSRs."
    // See: 31.5 VMM SETUP & TEAR DOWN
    //
    newCr0.Flags = __readcr0();
    newCr0 = AdjustCr0(newCr0);
    __writecr0(newCr0.Flags);
    MV_ASSERT(newCr0.PagingEnable != FALSE);
    MV_ASSERT(newCr0.ProtectionEnable != FALSE);

    //
    // "Enable VMX operation by setting CR4.VMXE = 1. Ensure the resultant CR4
    //  value supports all the CR4 fixed bits reported in the IA32_VMX_CR4_FIXED0
    //  and IA32_VMX_CR4_FIXED1 MSRs".
    // See: 31.5 VMM SETUP & TEAR DOWN
    //
    newCr4.Flags = __readcr4();
    newCr4 = AdjustCr4(newCr4);
    __writecr4(newCr4.Flags);
    MV_ASSERT(newCr4.VmxEnable != FALSE);

    //
    // The below has been made sure with the IsVmxAvailable function.
    //
    // "Ensure that the IA32_FEATURE_CONTROL MSR (MSR index 3AH) has been
    //  properly programmed and that its lock bit is set (Bit 0 = 1)."
    // See: 31.5 VMM SETUP & TEAR DOWN
    //

    //
    // Enter VMX root operation.
    //
    // "Execute VMXON with the physical address of the VMXON region as the
    //  operand."
    // See: 31.5 VMM SETUP & TEAR DOWN
    //
    vmxOnPa = GetPhysicalAddress(&ProcessorContext->VmxOnRegion);
    if (__vmx_on(&vmxOnPa) != VmxResultOk)
    {
        LOG_ERROR("__vmx_on failed");
        status = MV_STATUS_HV_OPERATION_FAILED;
        goto Exit;
    }
    vmxOn = TRUE;

    //
    // Clear stale cache that potentially exists.
    //
    // "Software can use the INVVPID instruction with the "all-context" INVVPID
    //  type immediately after execution of the VMXON instruction (...)."
    // "Software can use the INVEPT instruction with the "all-context" INVEPT
    //  type immediately after execution of the VMXON instruction (...)."
    // See: 28.3.3.3 Guidelines for Use of the INVVPID Instruction
    // See: 28.3.3.4 Guidelines for Use of the INVEPT Instruction
    //
    InvalidateEptDerivedCache(0);
    InvalidateVpidDerivedCache(0);

    //
    // The per-processor context contains the VMCS region that is aligned to a
    // 4-KByte boundary.
    //
    // "Create a VMCS region in non-pageable memory of size specified by the VMX
    //  capability MSR IA32_VMX_BASIC and aligned to 4-KBytes.
    // See: 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
    //
    MV_ASSERT(PAGE_ALIGN(&ProcessorContext->VmcsRegion) == &ProcessorContext->VmcsRegion);

    //
    // "Initialize the version identifier in the VMCS (first 31 bits) with the
    //  VMCS revision identifier reported by the VMX capability MSR
    //  IA32_VMX_BASIC. Clear bit 31 of the first 4 bytes of the VMCS region."
    // See: 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
    //
    ProcessorContext->VmcsRegion.RevisionId = (UINT32)vmxBasicMsr.VmcsRevisionId;
    MV_ASSERT(ProcessorContext->VmcsRegion.ShadowVmcsIndicator == FALSE);

    //
    // "The term "guest-VMCS address" refers to the physical address of the new
    //  VMCS region for the following steps.
    // "Execute the VMCLEAR instruction by supplying the guest-VMCS address."
    // "Execute the VMPTRLD instruction by supplying the guest-VMCS address."
    // See: 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
    //
    vmcsPa = GetPhysicalAddress(&ProcessorContext->VmcsRegion);
    if ((__vmx_vmclear(&vmcsPa) != VmxResultOk) ||
        (__vmx_vmptrld(&vmcsPa) != VmxResultOk))
    {
        LOG_ERROR("__vmx_vmclear or __vmx_vmptrld failed");
        status = MV_STATUS_HV_OPERATION_FAILED;
        goto Exit;
    }

    //
    // The processor is in VMX root operation now. This means that the processor
    // can execute VMREAD, VMWRITE to configure VMCS and VMLAUNCH to start a VM.
    // Before start issuing VMWRITE, let us prepare data to write.
    //

    //
    // Initialize EPT specific data structures.
    //
    status = InitializeExtendedPageTables(&ProcessorContext->EptContext);
    if (MV_ERROR(status))
    {
        LOG_ERROR("InitializeExtendedPageTables failed : %08x", status);
        goto Exit;
    }
    eptInitialized = TRUE;

    //
    // Take the address of the initial stack pointer for hypervisor.
    //
    hypervisorStackPointer = (UINT64)&ProcessorContext->HypervisorStack.u.Layout.Context;
    MV_ASSERT((hypervisorStackPointer % 0x10) == 0);

    //
    // Capture the current GDTR and IDTR.
    //
    _sgdt(&gdtr);
    __sidt(&idtr);

    //
    // Intercept #DB. This is purely for demonstration and can be removed.
    //
    exceptionBitmap = (1 << DivideError);

    //
    // VM-entry and -exit controls define how processor should operate on
    // VM-entry and exit. The following configurations are to achieve that:
    //  - Host always runs on the 64bit mode by setting vmExitControls.LoadIa32Efer
    //    and vmExitControls.HostAddressSpaceSize.
    //  - Guest always runs with IA32_EFER as it writes to it.
    //  - Guest starts as on the 64bit mode as the system is currently so.
    //
    vmEntryControls.Flags = 0;
    vmEntryControls.Ia32EModeGuest = TRUE;
    vmEntryControls.LoadIa32Efer = TRUE;
    AdjustVmEntryControls(&vmEntryControls);

    vmExitControls.Flags = 0;
    vmExitControls.HostAddressSpaceSize = TRUE;
    vmExitControls.LoadIa32Efer = TRUE;
    vmExitControls.SaveIa32Efer = TRUE;
    AdjustVmExitControls(&vmExitControls);

    //
    // The pin-based VM-execution controls governs the handling of asynchronous
    // events (for example: interrupts). We do not need any of them.
    //
    pinBasedControls.Flags = 0;
    AdjustPinBasedControls(&pinBasedControls);

    //
    // The processor-based VM-execution controls govern the handling of
    // synchronous events, mainly those caused by the execution of specific
    // instructions.
    //
    // - MSR bitmaps are used; this is not to cause VM-exit as much as possible.
    //   We are setting the MSR bitmaps that are mostly cleared below (see
    //   InitializeMsrBitmaps). This prevents VM-exits from occurring when
    //   0x0 - 0x1fff and 0xc0000000 - 0xc0001fff are accessed. VM-exit still
    //   occurs if outside the range is accessed, and it is not possible to
    //   prevent this.
    //
    // - The secondary processor-based controls are used; this is to let the
    //   guest (Windows) executes RDTSCP, INVPCID and the XSAVE/XRSTORS family
    //   instructions. Those instructions are used in Windows 10. If those are
    //   not set, attempt to execute them causes #UD, which results in a bug
    //   check. VPID is enabled, which could lead to better performance for free
    //   by not flushing all TLB on every VM-exit and VM-entry. Finally, enabling
    //   EPT and unrestricted guest which are required for the UEFI hypervisor to
    //   handle the real-mode guest.
    //
    primaryProcBasedControls.Flags = 0;
    primaryProcBasedControls.UseMsrBitmaps = TRUE;
    primaryProcBasedControls.ActivateSecondaryControls = TRUE;
    AdjustProcessorBasedControls(&primaryProcBasedControls);

    secondaryProcBasedControls.Flags = 0;
    secondaryProcBasedControls.EnableEpt = TRUE;
    secondaryProcBasedControls.EnableVpid = TRUE;
    secondaryProcBasedControls.EnableRdtscp = TRUE;
    secondaryProcBasedControls.UnrestrictedGuest = TRUE;
    secondaryProcBasedControls.EnableInvpcid = TRUE;
    secondaryProcBasedControls.EnableXsaves = TRUE;
    AdjustSecondaryProcessorBasedControls(&secondaryProcBasedControls);

    //
    // "Issue a sequence of VMWRITEs to initialize various host-state area
    //  fields in the working VMCS."
    // See: 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
    //

    /* 16-Bit Host-State Fields */
    //
    // "In the selector field for each of CS, SS, DS, ES, FS, GS and TR, the
    //  RPL (bits 1:0) and the TI flag (bit 2) must be 0"
    // See: 26.2.3 Checks on Host Segment and Descriptor-Table Registers
    //
    VmxWrite(VMCS_HOST_ES_SELECTOR, AsmReadEs() & ~hostSegmentSelectorMask);
    VmxWrite(VMCS_HOST_CS_SELECTOR, AsmReadCs() & ~hostSegmentSelectorMask);
    VmxWrite(VMCS_HOST_SS_SELECTOR, AsmReadSs() & ~hostSegmentSelectorMask);
    VmxWrite(VMCS_HOST_DS_SELECTOR, AsmReadDs() & ~hostSegmentSelectorMask);
    VmxWrite(VMCS_HOST_FS_SELECTOR, AsmReadFs() & ~hostSegmentSelectorMask);
    VmxWrite(VMCS_HOST_GS_SELECTOR, AsmReadGs() & ~hostSegmentSelectorMask);
    VmxWrite(VMCS_HOST_TR_SELECTOR, AsmReadTr() & ~hostSegmentSelectorMask);

    /* 64-Bit Host-State Fields */
    VmxWrite(VMCS_HOST_EFER, __readmsr(IA32_EFER));

    /* 32-Bit Host-State Field */
    VmxWrite(VMCS_HOST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));

    /* Natural-Width Host-State Fields */
    VmxWrite(VMCS_HOST_CR0, newCr0.Flags);
    VmxWrite(VMCS_HOST_CR3, GetHostCr3().Flags);
    VmxWrite(VMCS_HOST_CR4, newCr4.Flags);
    VmxWrite(VMCS_HOST_FS_BASE, __readmsr((IA32_MSR_ADDRESS)IA32_FS_BASE));
    VmxWrite(VMCS_HOST_GS_BASE, __readmsr((IA32_MSR_ADDRESS)IA32_GS_BASE));
    VmxWrite(VMCS_HOST_TR_BASE, GetSegmentBase(gdtr.BaseAddress, AsmReadTr()));
    VmxWrite(VMCS_HOST_GDTR_BASE, gdtr.BaseAddress);
    VmxWrite(VMCS_HOST_IDTR_BASE, GetHostIdtr()->BaseAddress);
    VmxWrite(VMCS_HOST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    VmxWrite(VMCS_HOST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));
    VmxWrite(VMCS_HOST_RSP, hypervisorStackPointer);
    VmxWrite(VMCS_HOST_RIP, (UINT64)AsmHypervisorEntryPoint);

    //
    // "Use VMWRITEs to set up the various VM-exit control fields, VM-entry
    //  control fields, and VM-execution control fields in the VMCS."
    // See: 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
    //

    /* 16-Bit Control Field */
    VmxWrite(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER, 1);

    /* 64-Bit Control Fields */
    VmxWrite(VMCS_CTRL_MSR_BITMAP_ADDRESS, GetPhysicalAddress(&SharedProcessorContext->MsrBitmaps));
    VmxWrite(VMCS_CTRL_EPT_POINTER, ProcessorContext->EptContext.EptPointer.Flags);

    /* 32-Bit Control Fields */
    VmxWrite(VMCS_CTRL_EXCEPTION_BITMAP, exceptionBitmap);
    VmxWrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, pinBasedControls.Flags);
    VmxWrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, primaryProcBasedControls.Flags);
    VmxWrite(VMCS_CTRL_VMEXIT_CONTROLS, vmExitControls.Flags);
    VmxWrite(VMCS_CTRL_VMENTRY_CONTROLS, vmEntryControls.Flags);
    VmxWrite(VMCS_CTRL_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS,
             secondaryProcBasedControls.Flags);

    /* Natural-Width Control Fields */
    VmxWrite(VMCS_CTRL_CR0_GUEST_HOST_MASK, CR0_NUMERIC_ERROR_FLAG | CR0_PAGING_ENABLE_FLAG);
    VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, newCr0.Flags);
    VmxWrite(VMCS_CTRL_CR4_GUEST_HOST_MASK, CR4_VMX_ENABLE_FLAG);
    VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, newCr4.Flags);

    //
    // "Use VMWRITE to initialize various guest-state area fields in the working
    //  VMCS."
    // See: 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
    //

    /* 16-Bit Guest-State Fields */
    VmxWrite(VMCS_GUEST_ES_SELECTOR, AsmReadEs());
    VmxWrite(VMCS_GUEST_CS_SELECTOR, AsmReadCs());
    VmxWrite(VMCS_GUEST_SS_SELECTOR, AsmReadSs());
    VmxWrite(VMCS_GUEST_DS_SELECTOR, AsmReadDs());
    VmxWrite(VMCS_GUEST_FS_SELECTOR, AsmReadFs());
    VmxWrite(VMCS_GUEST_GS_SELECTOR, AsmReadGs());
    VmxWrite(VMCS_GUEST_LDTR_SELECTOR, AsmReadLdtr());
    VmxWrite(VMCS_GUEST_TR_SELECTOR, AsmReadTr());

    /* 64-Bit Guest-State Fields */
    //
    // "If the “VMCS shadowing” VM-execution control is 1, (...). Otherwise,
    //  software should set this field to FFFFFFFF_FFFFFFFFH to avoid VM-entry
    //  failures."
    // See: 24.4.2 Guest Non-Register State
    //
    VmxWrite(VMCS_GUEST_VMCS_LINK_POINTER, MAXUINT64);
    VmxWrite(VMCS_GUEST_EFER, __readmsr(IA32_EFER));

    /* 32-Bit Guest-State Fields */
    VmxWrite(VMCS_GUEST_ES_LIMIT, __segmentlimit(AsmReadEs()));
    VmxWrite(VMCS_GUEST_CS_LIMIT, __segmentlimit(AsmReadCs()));
    VmxWrite(VMCS_GUEST_SS_LIMIT, __segmentlimit(AsmReadSs()));
    VmxWrite(VMCS_GUEST_DS_LIMIT, __segmentlimit(AsmReadDs()));
    VmxWrite(VMCS_GUEST_FS_LIMIT, __segmentlimit(AsmReadFs()));
    VmxWrite(VMCS_GUEST_GS_LIMIT, __segmentlimit(AsmReadGs()));
    VmxWrite(VMCS_GUEST_LDTR_LIMIT, __segmentlimit(AsmReadLdtr()));
    VmxWrite(VMCS_GUEST_TR_LIMIT, __segmentlimit(AsmReadTr()));
    VmxWrite(VMCS_GUEST_GDTR_LIMIT, gdtr.Limit);
    VmxWrite(VMCS_GUEST_IDTR_LIMIT, idtr.Limit);
    VmxWrite(VMCS_GUEST_ES_ACCESS_RIGHTS, GetSegmentAccessRight(AsmReadEs()));
    VmxWrite(VMCS_GUEST_CS_ACCESS_RIGHTS, GetSegmentAccessRight(AsmReadCs()));
    VmxWrite(VMCS_GUEST_SS_ACCESS_RIGHTS, GetSegmentAccessRight(AsmReadSs()));
    VmxWrite(VMCS_GUEST_DS_ACCESS_RIGHTS, GetSegmentAccessRight(AsmReadDs()));
    VmxWrite(VMCS_GUEST_FS_ACCESS_RIGHTS, GetSegmentAccessRight(AsmReadFs()));
    VmxWrite(VMCS_GUEST_GS_ACCESS_RIGHTS, GetSegmentAccessRight(AsmReadGs()));
    VmxWrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, GetSegmentAccessRight(AsmReadLdtr()));
    VmxWrite(VMCS_GUEST_TR_ACCESS_RIGHTS, GetSegmentAccessRight(AsmReadTr()));
    VmxWrite(VMCS_GUEST_SYSENTER_CS, __readmsr(IA32_SYSENTER_CS));

    /* Natural-Width Guest-State Fields */
    VmxWrite(VMCS_GUEST_CR0, newCr0.Flags);
    VmxWrite(VMCS_GUEST_CR3, __readcr3());
    VmxWrite(VMCS_GUEST_CR4, newCr4.Flags);
    VmxWrite(VMCS_GUEST_FS_BASE, __readmsr((IA32_MSR_ADDRESS)IA32_FS_BASE));
    VmxWrite(VMCS_GUEST_GS_BASE, __readmsr((IA32_MSR_ADDRESS)IA32_GS_BASE));
    VmxWrite(VMCS_GUEST_LDTR_BASE, GetSegmentBase(gdtr.BaseAddress, AsmReadLdtr()));
    VmxWrite(VMCS_GUEST_TR_BASE, GetSegmentBase(gdtr.BaseAddress, AsmReadTr()));
    VmxWrite(VMCS_GUEST_GDTR_BASE, gdtr.BaseAddress);
    VmxWrite(VMCS_GUEST_IDTR_BASE, idtr.BaseAddress);
    VmxWrite(VMCS_GUEST_RSP, ProcessorContext->GuestStackPointer);
    VmxWrite(VMCS_GUEST_RIP, ProcessorContext->GuestInstructionPointer);
    VmxWrite(VMCS_GUEST_RFLAGS, __readeflags());
    VmxWrite(VMCS_GUEST_SYSENTER_ESP, __readmsr(IA32_SYSENTER_ESP));
    VmxWrite(VMCS_GUEST_SYSENTER_EIP, __readmsr(IA32_SYSENTER_EIP));

    //
    // Finally, place necessary data for hypervisor into the hypervisor stack.
    //
    ProcessorContext->HypervisorStack.u.Layout.Context.ProcessorNumber = GetCurrentProcessorNumber();
    ProcessorContext->HypervisorStack.u.Layout.Context.SharedMsrBitmaps = &SharedProcessorContext->MsrBitmaps;
    ProcessorContext->HypervisorStack.u.Layout.Context.SharedProcessorContext = SharedProcessorContext;
    ProcessorContext->HypervisorStack.u.Layout.Context.EptContext = &ProcessorContext->EptContext;
    ProcessorContext->HypervisorStack.u.Layout.Context.MemoryAccessContext = &ProcessorContext->MemoryAccessContext;
    ProcessorContext->HypervisorStack.u.Layout.Context.NestedVmxContext = &ProcessorContext->NestedVmxContext;
    status = MV_STATUS_SUCCESS;

Exit:
    if (MV_ERROR(status))
    {
        if (eptInitialized != FALSE)
        {
            CleanupExtendedPageTables(&ProcessorContext->EptContext);
        }
        if (vmxOn != FALSE)
        {
            __vmx_off();
        }
        if (ProcessorContext->OriginalGdtr.BaseAddress != 0)
        {
            CleanupGdt(&ProcessorContext->OriginalGdtr);
        }
    }
    return status;
}

/*!
    @brief Enables hypervisor on the current processor.

    @param[in,out] Context - The pointer to the shared processor context.
 */
MV_SECTION_PAGED
static
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
EnableHypervisor (
    _Inout_ VOID* Context
    )
{
    UINT32 processorNumber;
    SHARED_PROCESSOR_CONTEXT* sharedProcessorContext;
    PER_PROCESSOR_CONTEXT* processorContext;
    UINT64 guestRsp;
    UINT64 guestRip;
    BOOLEAN maCtxInitialized;

    PAGED_CODE();

    maCtxInitialized = FALSE;

    sharedProcessorContext = Context;
    processorNumber = GetCurrentProcessorNumber();
    MV_ASSERT(processorNumber < sharedProcessorContext->NumberOfContexts);
    processorContext = &sharedProcessorContext->Contexts[processorNumber];

    //
    // Initialize the context of API to access guest virtual address from the
    // host.
    //
    processorContext->Status = InitializeMemoryAccess(&processorContext->MemoryAccessContext,
                                                      GetHostCr3());
    if (MV_ERROR(processorContext->Status))
    {
        LOG_ERROR("InitializeMemoryAccess failed : %08x", processorContext->Status);
        goto Exit;
    }
    maCtxInitialized = TRUE;

    //
    // Save the current stack and instruction pointers. When the processor
    // successfully runs VMLAUNCH, it sets the stack and instruction pointers to
    // those values since we will set them to the guest state in the VMCS as we
    // see in the SetupVmcs function. This means, after VMLAUNCH, the
    // processor starts running at right after those function calls with the same
    // stack pointer value again.
    //
    guestRsp = AsmGetCurrentStackPointer();
    guestRip = AsmGetCurrentInstructionPointer();

    //
    // Check whether our hypervisor is already installed. At the first time, it
    // should not, and so, we will enable hypervisor ending with VMLAUNCH. After
    // successful VMLAUNCH, the processor starts running at here. At that time,
    // hypervisor is already installed, so the below block is skipped and this
    // function returns MV_STATUS_SUCCESS.
    //
    // Comment in the below debug break if you would like to see that this place
    // is executed twice.
    //
    //MV_DEBUG_BREAK();

    if (IsMiniVisorInstalled() == FALSE)
    {
        VMX_RESULT result;
        VMX_ERROR_NUMBER vmxErrorStatus;

        processorContext->GuestStackPointer = guestRsp;
        processorContext->GuestInstructionPointer = guestRip;
        processorContext->Status = SetupVmcs(sharedProcessorContext, processorContext);
        if (MV_ERROR(processorContext->Status))
        {
            LOG_ERROR("SetupVmcs failed : %08x", processorContext->Status);
            goto Exit;
        }

        //
        // It is important to be aware of that several registers are not saved
        // to and loaded from VMCS on VMLAUNCH, and the current register values
        // are used. This means that such register values must be the same between
        // when VMLAUNCH is executed and when RIP and RSP are captured. Otherwise,
        // when RIP and RSP are loaded from VMCS with VMLAUNCH, code running
        // after that will operate with unexpected register values. Think the
        // situation when you step through a program with a Windbg and just
        // overwrite RIP to rerun the same code again, but without paying
        // attention to the general purpose registers. The code will not run
        // proper if one of general purpose registers used in the code has stale
        // values.
        //
        // We avoid this issue by trying not to change any register values
        // between when RIP and RSP are captured and when VMLAUNCH is executed
        // in a way that breaks execution after successful VMLAUNCH. That is,
        // 1) executing VMLAUNCH in the same function, which ensures that all
        // non-volatile registers remain unchanged, and 2) avoiding dependency
        // on volatile registers in the code path after successful VMLAUNCH
        // (notice that it only calls a function without parameters and return).
        //
        // "The VMM may need to initialize additional guest execution state that is
        //  not captured in the VMCS guest state area by loading them directly on
        //  the respective processor registers. Examples include general purpose
        //  registers, the CR2 control register, debug registers, floating point
        //  registers and so forth."
        // See: 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
        //

        //
        // Enable hypervisor. If it is successful, this call does not return and
        // the processor starts running at the above point.
        //
        // "Execute VMLAUNCH to launch the guest VM."
        // See: 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
        //
        result = __vmx_vmlaunch();

        //
        // We have failed to run VMLAUNCH. Retrieve and log the error number.
        // See: Table 30-1. VM-Instruction Error Numbers
        //
        MV_ASSERT(result != VmxResultOk);
        vmxErrorStatus = (result == VmxResultErrorWithStatus) ?
            (VMX_ERROR_NUMBER)VmxRead(VMCS_VM_INSTRUCTION_ERROR) : 0;
        LOG_ERROR("__vmx_vmlaunch failed : %u", vmxErrorStatus);

        processorContext->Status = MV_STATUS_HV_OPERATION_FAILED;
        CleanupExtendedPageTables(&processorContext->EptContext);
        __vmx_off();
        CleanupGdt(&processorContext->OriginalGdtr);
        goto Exit;
    }

Exit:
    if (MV_ERROR(processorContext->Status) && (maCtxInitialized != FALSE))
    {
        CleanupMemoryAccess(&processorContext->MemoryAccessContext);
    }
}

/*!
    @brief Initializes the MSR bitmaps.

    @details This function clears the bitmaps to avoid VM-exits that do not require
        manual handling. The MSR that requires manual handling for MiniVisor is
        IA32_BIOS_SIGN_ID for read to prevent the guest from attempting update
        BIOS microcode which is not allowed. See HandleMsrAccess for more details.

   @param[out] Bitmaps - The pointer to the MSR bitmaps to initialize.
 */
MV_SECTION_PAGED
static
VOID
InitializeMsrBitmaps (
    _Out_ MSR_BITMAPS* Bitmaps
    )
{
    typedef struct _INTERCEPT_MSR_REGISTRATION
    {
        IA32_MSR_ADDRESS Msr;
        OPERATION_TYPE InterceptType;
    } INTERCEPT_MSR_REGISTRATION;

    static CONST INTERCEPT_MSR_REGISTRATION registrations[] =
    {
        { IA32_BIOS_SIGN_ID, OperationRead, },
    };

    PAGED_CODE();

    RtlZeroMemory(Bitmaps, sizeof(*Bitmaps));

    for (int i = 0; i < RTL_NUMBER_OF(registrations); ++i)
    {
        UpdateMsrBitmaps(Bitmaps,
                         registrations[i].Msr,
                         registrations[i].InterceptType,
                         TRUE);
    }
}

/*!
    @brief Enables the hypervisor on the all processors.

    @return MV_STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
MV_SECTION_PAGED
static
_IRQL_requires_max_(PASSIVE_LEVEL)
_Must_inspect_result_
MV_STATUS
EnableHypervisorOnAllProcessors (
    )
{
    MV_STATUS status;
    UINT32 numberOfProcessors;
    UINT32 allocationSize;
    SHARED_PROCESSOR_CONTEXT* sharedProcessorContext;
    BOOLEAN virtualized;

    PAGED_CODE();

    virtualized = FALSE;

    //
    // Compute the size of shared processor contexts. The shared processor contexts
    // contain VT-x related data shared across all processors and as well as
    // a per-processor context for each processor. The per-processor context
    // contains VT-x related data that are specific to the processor.
    //
    // "numberOfProcessors - 1" because "sizeof(ALL_PROCESSORS_CONTEXTS)" includes
    // one PER_PROCESSOR_CONTEXT.
    //
    numberOfProcessors = GetActiveProcessorCount();
    allocationSize = sizeof(SHARED_PROCESSOR_CONTEXT) +
        (sizeof(PER_PROCESSOR_CONTEXT) * (numberOfProcessors - 1));

    //
    // Allocate the context.
    //
    sharedProcessorContext = MmAllocatePages((UINT8)BYTES_TO_PAGES(allocationSize));
    if (sharedProcessorContext == NULL)
    {
        status = MV_STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    sharedProcessorContext->NumberOfContexts = numberOfProcessors;
    InitializeMsrBitmaps(&sharedProcessorContext->MsrBitmaps);

    //
    // Start virtualizing processors one-by-one. This is done by changing
    // thread affinity and executing callback on each processor at PASSIVE_LEVEL.
    // This is slow as virtualization code is not parallelized but makes debugging
    // MUCH easier exactly because of the reason. Production code normally use
    // DPC or IPI instead, so that this operation is parallelized and eliminates
    // any chance of race.
    //
    RunOnAllProcessors(EnableHypervisor, sharedProcessorContext);

    //
    // Assume success first, then inspect the results from each processor and
    // update status as necessary.
    //
    status = MV_STATUS_SUCCESS;
    for (UINT32 i = 0; i < sharedProcessorContext->NumberOfContexts; ++i)
    {
        if (MV_ERROR(sharedProcessorContext->Contexts[i].Status))
        {
            //
            // At least one processor failed to enable hypervisor.
            //
            LOG_ERROR("EnableHypervisor on processor %lu failed : %08x",
                      i,
                      sharedProcessorContext->Contexts[i].Status);
            status = sharedProcessorContext->Contexts[i].Status;
        }
        else
        {
            //
            // At least one processor enabled hypervisor and so needs clean up
            // in case of failure.
            //
            virtualized = TRUE;
            LOG_INFO("EnableHypervisor on processor %lu succeeded.", i);
        }
    }

Exit:
    if (MV_ERROR(status))
    {
        if (virtualized != FALSE)
        {
            //
            // Disable hypervisor if one or more processors enabled but also the
            // other processor(s) failed. This takes care of freeing the
            // shared processor contexts.
            //
            DisableHypervisorOnAllProcessors();
        }
        else
        {
            if (sharedProcessorContext != NULL)
            {
                MmFreePages(sharedProcessorContext);
            }
        }
    }
    return status;
}

_Use_decl_annotations_
MV_STATUS
InitializeMiniVisor (
    )
{
    MV_STATUS status;
    BOOLEAN platformInitialized;
    BOOLEAN memoryManagerInitialized;

    platformInitialized = FALSE;
    memoryManagerInitialized = FALSE;

    MV_DEBUG_BREAK();

    //
    // Initialize platform dependent bits, including the logging facility. Until
    // this succeeds, only the LOG_EARLY_ERROR macro can be used for logging.
    //
    status = InitializePlatform();
    if (MV_ERROR(status))
    {
        LOG_EARLY_ERROR("InitializePlatform failed : %08x", status);
        goto Exit;
    }
    platformInitialized = TRUE;

    //
    // Bail out if MiniVisor is already installed.
    //
    if (IsMiniVisorInstalled() != FALSE)
    {
        LOG_INFO("MiniVisor already installed");
        status = MV_STATUS_HV_OPERATION_FAILED;
        goto Exit;
    }

    LOG_INFO("Installing MiniVisor.");

    //
    // Compute the required memory size and initialize the memory manager with it.
    //
    // The memory manager is the component that allocates the specified size of
    // non-paged pool at first and uses it as a pool to process memory allocation
    // requests. This pre-allocation approach is required because host code
    // cannot call almost any kernel API including memory allocation functions.
    //
    // The page count allocated are based on the fact that EPT paging structures
    // for 0-1GB of physical memory addresses often need to be constructed without
    // large page EPT entries because of fixed MTRRs. This requires 512 pages (
    // 512 EPT page tables). Add 64 pages for the rest of EPT tables, control
    // structures etc.
    //
    status = MmInitializeMemoryManager(GetActiveProcessorCount() * (512 + 64));
    if (MV_ERROR(status))
    {
        LOG_ERROR("MmInitializeMemoryManager failed : %08x", status);
        goto Exit;
    }
    memoryManagerInitialized = TRUE;

    //
    // Prepare environments for the host. This includes initialization of CR3 and
    // IDTR, but how those set up depend on the platform.
    //
    InitializeHostEnvironment();

    //
    // Build the mapping of "physical address to memory type", based on the memory
    // type range registers (MTRRs). This information is required to set up
    // extended page tables.
    //
    InitializeMemoryTypeMapping();

    //
    // Install the hypervisor.
    //
    status = EnableHypervisorOnAllProcessors();
    if (MV_ERROR(status))
    {
        LOG_ERROR("EnableHypervisorOnAllProcessors failed : %08x", status);
        goto Exit;
    }

    LOG_INFO("MiniVisor installed successfully.");

Exit:
    if (MV_ERROR(status))
    {
        if (memoryManagerInitialized != FALSE)
        {
            MmCleanupMemoryManager();
        }
        if (platformInitialized != FALSE)
        {
            CleanupPlatform();
        }
    }
    return status;
}

_Use_decl_annotations_
VOID
CleanupMiniVisor (
    )
{
    MV_DEBUG_BREAK();

    DisableHypervisorOnAllProcessors();
    MmCleanupMemoryManager();
    LOG_INFO("MiniVisor uninstalled successfully.");
    CleanupPlatform();
}
