/*!
    @file HostMain.c

    @brief Functions for VM-exit handling.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 -, Satoshi Tanda. All rights reserved.
 */
#include "HostMain.h"
#include "HostUtils.h"
#include "Public.h"
#include "Logger.h"
#include "ExtendedPageTables.h"
#include "HostVmcall.h"
#include "HostNesting.h"

//
// The trap frame structure for x64 systems. This is structure is used to help
// Windbg to construct call stack while VM-exit handlers are being executed.
// Since this is for Windbg, this is a Windows specific structure, and its
// layout can be found as nt!_KTRAP_FRAME. In our case, only the Rip and Rsp
// members are used since those are only fields needed to be set for Windbg to
// show proper call stack.
//
typedef struct _WINDOWS_KTRAP_FRAME
{
    UINT64 Reserved1[45];
    UINT64 Rip;
    UINT64 Reserved2[2];
    UINT64 Rsp;
    UINT64 Reserved3;
} WINDOWS_KTRAP_FRAME;
C_ASSERT(sizeof(WINDOWS_KTRAP_FRAME) == 0x190);

//
// The layout of hypervisor stack when the C-handler (HandleVmExit) is executed.
// GuestRegisters and TrapFrame are pushed in assembler part.
//
typedef struct _INITIAL_HYPERVISOR_STACK
{
    GUEST_REGISTERS GuestRegisters;
    WINDOWS_KTRAP_FRAME TrapFrame;
    HYPERVISOR_CONTEXT HypervisorContext;
} INITIAL_HYPERVISOR_STACK;

/*!
    @brief Handles VM-exit due to execution of the RDMSR and WRMSR instruction.

    @details Accessing MSR can results in #GP(0) that would have been handled by
        the guest. However, in this context, this results in host exception leading
        to the panic (See HandleHostException). For graceful handling, the handler
        can check the exception is #GP(0) caused by RDMSR or WRMSR, and if this
        is the case, inject it to the guest.

    @param[in,out] GuestContext - A pointer to the guest context.

    @param[in] OperationType - The type of the operation.
 */
static
VOID
HandleMsrAccess (
    _Inout_ GUEST_CONTEXT* GuestContext,
    _In_ OPERATION_TYPE OperationType
    )
{
    IA32_MSR_ADDRESS msr;
    UINT64 value;

    msr = (IA32_MSR_ADDRESS)GuestContext->StackBasedRegisters->Rcx;
    if (OperationType == OperationRead)
    {
        switch (msr)
        {
        case IA32_BIOS_SIGN_ID:
            //
            // Linux reads this MSR during boot and may attempt to update BIOS
            // microcode. Returning the greater value than the value the kernel
            // wishes prevent it from attempt to update microcode. APs will enter
            // infinite INIT-SIPI loop if this is not done.
            //
            // "The VMM may wish to prevent a guest from loading a microcode
            //  update (...). To prevent microcode update loading, the VMM may
            //  return a microcode update signature value greater than the value
            //  of IA32_BIOS_SIGN_ID MSR. A well behaved guest will not attempt
            //  to load an older microcode update."
            // See: 32.4.2 Late Load of Microcode Updates
            //
            value = MAXUINT64;
            break;

        default:
            value = __readmsr(msr);
            break;
        }

        GuestContext->StackBasedRegisters->Rax = value & MAXUINT32;
        GuestContext->StackBasedRegisters->Rdx = (value >> 32) & MAXUINT32;
    }
    else
    {
        value = (GuestContext->StackBasedRegisters->Rax & MAXUINT32) |
                ((GuestContext->StackBasedRegisters->Rdx & MAXUINT32) << 32);
        __writemsr(msr, value);
    }

    AdvanceGuestInstructionPointer(GuestContext);
}

/*!
    @brief Handles VM-exit due to execution of the RDMSR instruction.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleMsrRead (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    HandleMsrAccess(GuestContext, OperationRead);
}

/*!
    @brief Handles VM-exit due to execution of the WRMSR instruction.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleMsrWrite (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    HandleMsrAccess(GuestContext, OperationWrite);
}

/*!
    @brief Handles VM-exit due to execution of the CPUID instruction.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleCpuid (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    int registers[4];
    int leaf, subLeaf;

    //
    // Execute the same instruction on behalf of the guest.
    //
    leaf = (int)GuestContext->StackBasedRegisters->Rax;
    subLeaf = (int)GuestContext->StackBasedRegisters->Rcx;
    __cpuidex(registers, leaf, subLeaf);

    //
    // Then, modify results when necessary.
    //
    switch (leaf)
    {
        case CPUID_VERSION_INFORMATION:
            //
            // Do not indicate the VMX feature is available on this processor to
            // prevent other hypervisor tries to use it, as MiniVisor does not
            // support nesting the hypervisor.
            //
            ClearFlag(registers[2], CPUID_FEATURE_INFORMATION_ECX_VIRTUAL_MACHINE_EXTENSIONS_FLAG);
            break;

        case CPUID_HV_VENDOR_AND_MAX_FUNCTIONS:
            //
            // Return a maximum supported hypervisor CPUID leaf range and a vendor
            // ID signature as required by the spec.
            //
            registers[0] = CPUID_HV_MAX;
            registers[1] = 'iniM';  // "MiniVisor   "
            registers[2] = 'osiV';
            registers[3] = '   r';
            break;

        case CPUID_HV_INTERFACE:
            //
            // Return non Hv#1 value. This indicate that the MiniVisor does NOT
            // conform to the Microsoft hypervisor interface.
            //
            registers[0] = '0#vH';  // Hv#0
            registers[1] = registers[2] = registers[3] = 0;
            break;

        default:
            break;
    }

    //
    // Update guest's GPRs with results.
    //
    GuestContext->StackBasedRegisters->Rax = (UINT64)registers[0];
    GuestContext->StackBasedRegisters->Rbx = (UINT64)registers[1];
    GuestContext->StackBasedRegisters->Rcx = (UINT64)registers[2];
    GuestContext->StackBasedRegisters->Rdx = (UINT64)registers[3];

    AdvanceGuestInstructionPointer(GuestContext);
}

/*!
    @brief Handles VM-exit due to execution of the VMCALL instruction.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleVmCall (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    UINT64 hypercallNumber;

    //
    // Our hypercall takes the hypercall number in RCX.
    //
    hypercallNumber = GuestContext->StackBasedRegisters->Rcx;
    if (hypercallNumber >= VmcallInvalid)
    {
        //
        // Undefined hypercall number. Inject #UD.
        //
        InjectInterruption(HardwareException, InvalidOpcode, FALSE, 0);
        goto Exit;
    }

    //
    // Executes the corresponding hypercall handler.
    //
    k_VmcallHandlers[hypercallNumber](GuestContext);

    AdvanceGuestInstructionPointer(GuestContext);

Exit:
    return;
}

/*!
    @brief Handles VM-exit due to execution of the XSETBV instruction.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleXsetbv (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    UINT64 value;
    CR4 hostCr4;

    //
    // Execution of the XSETBV instruction requires the OSXSAVE bit to be set,
    // and the host CR4 may not have it. Set the bit and execute the instruction.
    //
    hostCr4.Flags = __readcr4();
    hostCr4.OsXsave = TRUE;
    __writecr4(hostCr4.Flags);

    value = (GuestContext->StackBasedRegisters->Rax & MAXUINT32) |
            ((GuestContext->StackBasedRegisters->Rdx & MAXUINT32) << 32);
    _xsetbv((UINT32)GuestContext->StackBasedRegisters->Rcx, value);

    AdvanceGuestInstructionPointer(GuestContext);
}

/*!
    @brief Returns the address of where the guest general purpose register that
        corresponds to the given index is stored.

    @param[in,out] GuestContext - A pointer to the guest context.

    @param[in] RegisterIndex - The index provided by VMCS up on VM-exit.

    @return The address of where the guest general purpose register that
        corresponds to the given index is stored.
 */
static
UINT64*
SelectEffectiveRegister (
    _Inout_ GUEST_CONTEXT* GuestContext,
    _In_ UINT64 RegisterIndex
    )
{
    UINT64* effectiveRegister;

    switch (RegisterIndex)
    {
        case 0: effectiveRegister = &GuestContext->StackBasedRegisters->Rax; break;
        case 1: effectiveRegister = &GuestContext->StackBasedRegisters->Rcx; break;
        case 2: effectiveRegister = &GuestContext->StackBasedRegisters->Rdx; break;
        case 3: effectiveRegister = &GuestContext->StackBasedRegisters->Rbx; break;
        case 4: effectiveRegister = &GuestContext->VmcsBasedRegisters.Rsp; break;
        case 5: effectiveRegister = &GuestContext->StackBasedRegisters->Rbp; break;
        case 6: effectiveRegister = &GuestContext->StackBasedRegisters->Rsi; break;
        case 7: effectiveRegister = &GuestContext->StackBasedRegisters->Rdi; break;
        case 8: effectiveRegister = &GuestContext->StackBasedRegisters->R8; break;
        case 9: effectiveRegister = &GuestContext->StackBasedRegisters->R9; break;
        case 10: effectiveRegister = &GuestContext->StackBasedRegisters->R10; break;
        case 11: effectiveRegister = &GuestContext->StackBasedRegisters->R11; break;
        case 12: effectiveRegister = &GuestContext->StackBasedRegisters->R12; break;
        case 13: effectiveRegister = &GuestContext->StackBasedRegisters->R13; break;
        case 14: effectiveRegister = &GuestContext->StackBasedRegisters->R14; break;
        case 15: effectiveRegister = &GuestContext->StackBasedRegisters->R15; break;
        default: MV_PANIC(); break;
    }

    return effectiveRegister;
}

/*!
    @brief Handles VM-exit due to execution of access to the control register.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleCrAccess (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    VMX_EXIT_QUALIFICATION_MOV_CR qualification;
    UINT64 newValue;
    CR0 newCr0, currentCr0;
    CR4 newCr4;

    qualification.Flags = VmxRead(VMCS_EXIT_QUALIFICATION);
    newValue = *SelectEffectiveRegister(GuestContext,
                                        qualification.GeneralPurposeRegister);

    switch (qualification.AccessType)
    {
    case VMX_EXIT_QUALIFICATION_ACCESS_MOV_TO_CR:
        //
        // Update what the guest sees (ie, VMCS_CTRL_CRn_READ_SHADOW) exactly
        // as the guest requested, then update the actual state (VMCS_GUEST_CRn)
        // after applying the FIXED0 and FIXED1 MSRs. This ensures VMX continues
        // to function, for example, by keeping the VMXE bit set.
        //
        switch (qualification.ControlRegister)
        {
        case VMX_EXIT_QUALIFICATION_REGISTER_CR0:
            newCr0.Flags = newValue;
            currentCr0.Flags = VmxRead(VMCS_GUEST_CR0);
            VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, newCr0.Flags);
            VmxWrite(VMCS_GUEST_CR0, AdjustGuestCr0(newCr0).Flags);
            if (currentCr0.PagingEnable != newCr0.PagingEnable)
            {
                SwitchGuestPagingMode(newCr0);

                //
                // For demonstration with VMware. On bare-metal, delay because of
                // this logging may lead to failure of AP start up.
                //
                //LOG_INFO("Processor #%d switching to the long mode",
                //         GuestContext->Contexts->ProcessorNumber);
            }
            break;
        case VMX_EXIT_QUALIFICATION_REGISTER_CR4:
            newCr4.Flags = newValue;
            VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, newCr4.Flags);
            VmxWrite(VMCS_GUEST_CR4, AdjustGuestCr4(newCr4).Flags);
            break;
        default:
            MV_PANIC();
        }
        break;
    default:
        MV_PANIC();
    }

    AdvanceGuestInstructionPointer(GuestContext);
}

/*!
    @brief Handles VM-exit due to EPT violation.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleEptViolation (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    UINT64 faultPhysicalAddress;

    //
    // As of now, this should never happen and can panic here. We inject #GP(0)
    // instead, because this is what you may want to do once some EPT related logic
    // such as protecting pages is written.
    //
    faultPhysicalAddress = VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS);
    LOG_WARNING("IP:%016llx PA:%016llx",
                GuestContext->VmcsBasedRegisters.Rip,
                faultPhysicalAddress);

    InjectInterruption(HardwareException, GeneralProtection, TRUE, 0);
}

/*!
    @brief Handles VM-exit due to EPT misconfiguration.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleEptMisconfig (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    UINT64 faultPhysicalAddress;
    ADDRESS_TRANSLATION_HELPER helper;

    //
    // This is a programming error that should never happen. The most helpful
    // thing can be done is to dump information for diagnostics.
    //
    DumpGuestState();
    faultPhysicalAddress = VmxRead(VMCS_GUEST_PHYSICAL_ADDRESS);
    LOG_ERROR("IP:%016llx PA:%016llx",
              GuestContext->VmcsBasedRegisters.Rip,
              faultPhysicalAddress);
    LOG_ERROR("EPT_PML4:%016llx EPTP:%016llx",
              GuestContext->Contexts->EptContext->EptPml4->Flags,
              GuestContext->Contexts->EptContext->EptPointer.Flags);
    helper.AsUInt64 = faultPhysicalAddress;
    LOG_ERROR("Indexes: %llu %llu %llu %llu",
              helper.AsIndex.Pml4,
              helper.AsIndex.Pdpt,
              helper.AsIndex.Pd,
              helper.AsIndex.Pt);

    MV_PANIC();
}

/*!
    @brief Handles VM-exit due to interrupt or exception.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleExceptionOrNmi (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    static BOOLEAN isKeInitAmd64SpecificStateCalled;
    VMEXIT_INTERRUPT_INFORMATION interruptInfo;

    //
    // This handler is specialized for skipping main initialization of PatchGuard.
    // When #DE occurs with the guest state that seems to be during initialization
    // of PatchGuard, suppress it. Otherwise, just inject the exception (pass-through).
    //
    interruptInfo.Flags = (UINT32)VmxRead(VMCS_VMEXIT_INTERRUPTION_INFORMATION);
    MV_ASSERT(interruptInfo.InterruptionType == HardwareException);
    MV_ASSERT(interruptInfo.Vector == DivideError);

    //
    // The below check detects division that will trigger initialization of
    // PatchGuard. The very instruction is this on all versions of Windows.
    //  idiv r8d
    // The IDIV instruction in this form performs (int64)edx:eax / (int32)r8d,
    // and cases #DE, in particular when a positive result is greater than
    // 0x7fffffff. If the kernel debugger is not attached and disabled, the NT
    // kernel executes this instruction with the following values, resulting in
    // the #DE.
    //  ((int64)0xffffffff80000000 / -1) => 0x80000000
    // When this condition is detected for the first time, we do not inject #DE
    // to the guest to avoid initialization of main PatchGuard logic.
    //
    if ((isKeInitAmd64SpecificStateCalled == FALSE) &&
        ((UINT32)GuestContext->StackBasedRegisters->Rax == (UINT32)0x80000000) &&
        ((UINT32)GuestContext->StackBasedRegisters->Rdx == (UINT32)0xffffffff) &&
        ((UINT32)GuestContext->StackBasedRegisters->R8 ==  (UINT32)-1))
    {
        UINT64 ntoskrnlBase;

        //
        // Just as an example of how to access the guest virtual address, search
        // the base address of the NT kernel and print it out.
        //
        ntoskrnlBase = FindImageBase(GuestContext, GuestContext->VmcsBasedRegisters.Rip);
        if (ntoskrnlBase != 0)
        {
            LOG_INFO("Found ntoskrnl.exe at %016llx", ntoskrnlBase);
        }

        LOG_INFO("KeInitAmd64SpecificState triggered #DE");
        LOG_INFO("Skipping main PatchGuard initialization.");
        isKeInitAmd64SpecificStateCalled = TRUE;
        AdvanceGuestInstructionPointer(GuestContext);
        goto Exit;
    }

    //
    // Otherwise, just forward the exception.
    //
    InjectInterruption(interruptInfo.InterruptionType, interruptInfo.Vector, FALSE, 0);

Exit:
    return;
}

/*!
    @brief Handles VM-exit due to the INIT signal.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleInitSignal (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    int regs[4];
    CPUID_EAX_01 cpuVersionInfo;
    UINT64 extendedModel;
    VMX_SEGMENT_ACCESS_RIGHTS accessRights;
    IA32_VMX_ENTRY_CTLS_REGISTER vmEntryControls;
    CR0 newCr0;
    CR4 newCr4;

    //
    // For demonstration with VMware. On bare-metal, delay because of this logging
    // may lead to failure of AP start up.
    //
    //LOG_INFO("Starting up processor #%d", GuestContext->Contexts->ProcessorNumber);
    UNREFERENCED_PARAMETER(GuestContext);

    //
    // Initializes the processor to the state after INIT as described in the
    // Intel SDM.
    //
    // See: Table 9-1. IA-32 and Intel 64 Processor States Following Power-up,
    //      Reset, or INIT
    //
    VmxWrite(VMCS_GUEST_RFLAGS, RFLAGS_READ_AS_1_FLAG);
    VmxWrite(VMCS_GUEST_RIP, 0xfff0);
    VmxWrite(VMCS_CTRL_CR0_READ_SHADOW, CR0_EXTENSION_TYPE_FLAG);
    __writecr2(0);
    VmxWrite(VMCS_GUEST_CR3, 0);
    VmxWrite(VMCS_CTRL_CR4_READ_SHADOW, 0);

    //
    // Actual guest CR0 and CR4 must fulfill requirements for VMX. Apply those.
    //
    newCr0.Flags = CR0_EXTENSION_TYPE_FLAG;
    newCr4.Flags = 0;
    VmxWrite(VMCS_GUEST_CR0, AdjustGuestCr0(newCr0).Flags);
    VmxWrite(VMCS_GUEST_CR4, AdjustGuestCr4(newCr4).Flags);

    accessRights.Flags = 0;

    accessRights.Type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
    accessRights.DescriptorType = TRUE;
    accessRights.Present = TRUE;
    VmxWrite(VMCS_GUEST_CS_SELECTOR, 0xf000);
    VmxWrite(VMCS_GUEST_CS_BASE, 0xffff0000);
    VmxWrite(VMCS_GUEST_CS_LIMIT, 0xffff);
    VmxWrite(VMCS_GUEST_CS_ACCESS_RIGHTS, accessRights.Flags);

    accessRights.Type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
    VmxWrite(VMCS_GUEST_SS_SELECTOR, 0);
    VmxWrite(VMCS_GUEST_SS_BASE, 0);
    VmxWrite(VMCS_GUEST_SS_LIMIT, 0xffff);
    VmxWrite(VMCS_GUEST_SS_ACCESS_RIGHTS, accessRights.Flags);
    VmxWrite(VMCS_GUEST_DS_SELECTOR, 0);
    VmxWrite(VMCS_GUEST_DS_BASE, 0);
    VmxWrite(VMCS_GUEST_DS_LIMIT, 0xffff);
    VmxWrite(VMCS_GUEST_DS_ACCESS_RIGHTS, accessRights.Flags);
    VmxWrite(VMCS_GUEST_ES_SELECTOR, 0);
    VmxWrite(VMCS_GUEST_ES_BASE, 0);
    VmxWrite(VMCS_GUEST_ES_LIMIT, 0xffff);
    VmxWrite(VMCS_GUEST_ES_ACCESS_RIGHTS, accessRights.Flags);
    VmxWrite(VMCS_GUEST_FS_SELECTOR, 0);
    VmxWrite(VMCS_GUEST_FS_BASE, 0);
    VmxWrite(VMCS_GUEST_FS_LIMIT, 0xffff);
    VmxWrite(VMCS_GUEST_FS_ACCESS_RIGHTS, accessRights.Flags);
    VmxWrite(VMCS_GUEST_GS_SELECTOR, 0);
    VmxWrite(VMCS_GUEST_GS_BASE, 0);
    VmxWrite(VMCS_GUEST_GS_LIMIT, 0xffff);
    VmxWrite(VMCS_GUEST_GS_ACCESS_RIGHTS, accessRights.Flags);

    __cpuid(regs, CPUID_VERSION_INFORMATION);
    cpuVersionInfo.CpuidVersionInformation.Flags = regs[0];
    extendedModel = cpuVersionInfo.CpuidVersionInformation.ExtendedModelId;
    GuestContext->StackBasedRegisters->Rdx = 0x600 | (extendedModel << 16);
    GuestContext->StackBasedRegisters->Rbx = 0;
    GuestContext->StackBasedRegisters->Rcx = 0;
    GuestContext->StackBasedRegisters->Rsi = 0;
    GuestContext->StackBasedRegisters->Rdi = 0;
    GuestContext->StackBasedRegisters->Rbp = 0;
    VmxWrite(VMCS_GUEST_RSP, 0);

    VmxWrite(VMCS_GUEST_GDTR_BASE, 0);
    VmxWrite(VMCS_GUEST_GDTR_LIMIT, 0xffff);
    VmxWrite(VMCS_GUEST_IDTR_BASE, 0);
    VmxWrite(VMCS_GUEST_IDTR_LIMIT, 0xffff);

    accessRights.Type = SEGMENT_DESCRIPTOR_TYPE_LDT;
    accessRights.DescriptorType = FALSE;
    VmxWrite(VMCS_GUEST_LDTR_SELECTOR, 0);
    VmxWrite(VMCS_GUEST_LDTR_BASE, 0);
    VmxWrite(VMCS_GUEST_LDTR_LIMIT, 0xffff);
    VmxWrite(VMCS_GUEST_LDTR_ACCESS_RIGHTS, accessRights.Flags);

    accessRights.Type = SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY;
    VmxWrite(VMCS_GUEST_TR_SELECTOR, 0);
    VmxWrite(VMCS_GUEST_TR_BASE, 0);
    VmxWrite(VMCS_GUEST_TR_LIMIT, 0xffff);
    VmxWrite(VMCS_GUEST_TR_ACCESS_RIGHTS, accessRights.Flags);

    __writedr(0, 0);
    __writedr(1, 0);
    __writedr(2, 0);
    __writedr(3, 0);
    __writedr(6, 0xffff0ff0);
    VmxWrite(VMCS_GUEST_DR7, 0x400);

    GuestContext->StackBasedRegisters->R8 = 0;
    GuestContext->StackBasedRegisters->R9 = 0;
    GuestContext->StackBasedRegisters->R10 = 0;
    GuestContext->StackBasedRegisters->R11 = 0;
    GuestContext->StackBasedRegisters->R12 = 0;
    GuestContext->StackBasedRegisters->R13 = 0;
    GuestContext->StackBasedRegisters->R14 = 0;
    GuestContext->StackBasedRegisters->R15 = 0;

    //
    // Those registers are supposed to be cleared but that is not implemented here.
    //  - IA32_XSS
    //  - BNDCFGU
    //  - BND0-BND3
    //  - IA32_BNDCFGS
    //

    VmxWrite(VMCS_GUEST_EFER, 0);
    VmxWrite(VMCS_GUEST_FS_BASE, 0);
    VmxWrite(VMCS_GUEST_GS_BASE, 0);

    vmEntryControls.Flags = VmxRead(VMCS_CTRL_VMENTRY_CONTROLS);
    vmEntryControls.Ia32EModeGuest = FALSE;
    VmxWrite(VMCS_CTRL_VMENTRY_CONTROLS, vmEntryControls.Flags);

    //
    // "All the processors on the system bus (...) execute the multiple processor
    //  (MP) initialization protocol. ... The application (non-BSP) processors
    //  (APs) go into a Wait For Startup IPI (SIPI) state while the BSP is executing
    //  initialization code."
    //
    // See: 9.1 INITIALIZATION OVERVIEW
    //
    // "Upon receiving an INIT ..., the processor responds by beginning the
    //  initialization process of the processor core and the local APIC. The state
    //  of the local APIC following an INIT reset is the same as it is after a
    //  power-up or hardware reset ... . This state is also referred to at the
    //  "wait-for-SIPI" state."
    //
    // See: 10.4.7.3 Local APIC State After an INIT Reset (“Wait-for-SIPI” State)
    //
    VmxWrite(VMCS_GUEST_ACTIVITY_STATE, VmxWaitForSipi);
}

/*!
    @brief Handles VM-exit due to the Startup-IPI (SIPI) signal.

    @param[in,out] GuestContext - A pointer to the guest context.
 */
static
VOID
HandleStartupIpi (
    _Inout_ GUEST_CONTEXT* GuestContext
    )
{
    UNREFERENCED_PARAMETER(GuestContext);

    UINT64 vector;

    //
    // Then, emulate effects of SIPI by making further changes.
    //
    // "For a start-up IPI (SIPI), the exit qualification contains the SIPI
    //  vector information in bits 7:0. Bits 63:8 of the exit qualification are
    //  cleared to 0."
    // See: 27.2.1 Basic VM-Exit Information
    //
    vector = VmxRead(VMCS_EXIT_QUALIFICATION);

    //
    // "At the end of the boot-strap procedure, the BSP sets ... broadcasts a
    //  SIPI message to all the APs in the system. Here, the SIPI message contains
    //  a vector to the BIOS AP initialization code (at 000VV000H, where VV is the
    //  vector contained in the SIPI message)."
    //
    // See: 8.4.3 MP Initialization Protocol Algorithm for MP Systems
    //
    VmxWrite(VMCS_GUEST_CS_SELECTOR, ((UINT64)vector) << 8);
    VmxWrite(VMCS_GUEST_CS_BASE, ((UINT64)vector) << 12);
    VmxWrite(VMCS_GUEST_RIP, 0);

    //
    // Changing CR0.PG from 1 to 0 *using the MOV instruction* invalidates TLBs.
    // The case with INIT-SIPI does not seem to be documented but we do so just
    // in case. Emulate this invalidating combined caches (GVA to HPA translation
    // caches).
    //
    InvalidateVpidDerivedCache((UINT16)VmxRead(VMCS_CTRL_VIRTUAL_PROCESSOR_IDENTIFIER));

    //
    // Done. Note that the 2nd SIPI will be ignored if that occurs after this.
    //
    // "If a logical processor is not in the wait-for-SIPI activity state when a
    //  SIPI arrives, no VM exit occurs and the SIPI is discarded"
    // See: 25.2 OTHER CAUSES OF VM EXITS
    //
    VmxWrite(VMCS_GUEST_ACTIVITY_STATE, VmxActive);
}

/*!
    @brief Handles VM-exit. This is the C-level entry point of the hypervisor.

    @details This function is called the actual entry point of hypervisor, the
        AsmHypervisorEntryPoint function, after it preserved guest registers to
        stack as necessary. Such register values can be referenced and updated
        through the point to the stack location as provided by the Stack
        parameter. Those values are restored in the AsmHypervisorEntryPoint
        function after this function is executed and reflected to the guest.

        Any hypervisor code including this and the AsmHypervisorEntryPoint
        functions are executed while interrupt is disabled via RFLAGS.IF being
        0 (See: 27.5.3 Loading Host RIP, RSP, and RFLAGS). This means IPI, if
        requested, is never delivered and causes deadlock. This condition is
        essentially equal to IRQL being HIGH_LEVEL (i.e., at a higher IRQL than
        IPI_LEVEL), and so, it is unsafe to call any Windows provided API that
        is not stated as callable at HIGH_LEVEL.

    @param[in,out] Stack - A pointer to the hypervisor stack containing the
        guest register values.

    @return TRUE when virtualization should continue and the VMRESUME instruction
        should be executed. FALSE when it should end and the VMXOFF instruction
        should be executed.
 */
_Must_inspect_result_
BOOLEAN
HandleVmExit (
    _Inout_ INITIAL_HYPERVISOR_STACK* Stack
    )
{
    VMX_VMEXIT_REASON vmExitReason;
    GUEST_CONTEXT guestContext;

    //
    // "Determine the exit reason through a VMREAD of the exit-reason field in
    //  the working-VMCS."
    // See: 31.7 HANDLING OF VM EXITS
    //
    vmExitReason.Flags = (UINT32)VmxRead(VMCS_EXIT_REASON);

    //
    // Copy some pointers to a single structure for ease of use.
    //
    guestContext.ContinueVm = TRUE;
    guestContext.Contexts = &Stack->HypervisorContext;
    guestContext.StackBasedRegisters = &Stack->GuestRegisters;

    //
    // Read some of commonly used guest registers that are stored in the VMCS
    // (instead of stack). Reading them are useful for debugging, as we cannot
    // tell which instruction caused the VM-exit if VMCS_GUEST_RIP is not read,
    // for example. Note that those values are not automatically written back to
    // the VMCS. When any of those values should be updated and reflected to the
    // guest, the VMWRITE instruction (the VmxWrite function) should be used.
    //
    guestContext.VmcsBasedRegisters.Rflags.Flags = VmxRead(VMCS_GUEST_RFLAGS);
    guestContext.VmcsBasedRegisters.Rsp = VmxRead(VMCS_GUEST_RSP);
    guestContext.VmcsBasedRegisters.Rip = VmxRead(VMCS_GUEST_RIP);

    //
    // Update the _KTRAP_FRAME structure values in hypervisor stack, so that
    // Windbg can reconstruct call stack of the guest during debug session.
    // This is optional but very useful thing to do for debugging.
    //
    Stack->TrapFrame.Rsp = guestContext.VmcsBasedRegisters.Rsp;
    Stack->TrapFrame.Rip = guestContext.VmcsBasedRegisters.Rip +
        VmxRead(VMCS_VMEXIT_INSTRUCTION_LENGTH);

    //
    // Comment in this for debugging the handlers below.
    //
    //MV_DEBUG_BREAK();

    switch (vmExitReason.BasicExitReason)
    {
        case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
            HandleExceptionOrNmi(&guestContext);
            break;

        case VMX_EXIT_REASON_INIT_SIGNAL:
            HandleInitSignal(&guestContext);
            break;

        case VMX_EXIT_REASON_STARTUP_IPI:
            HandleStartupIpi(&guestContext);
            break;

        case VMX_EXIT_REASON_EXECUTE_CPUID:
            HandleCpuid(&guestContext);
            break;

        case VMX_EXIT_REASON_EXECUTE_VMCALL:
            HandleVmCall(&guestContext);
            break;

        case VMX_EXIT_REASON_MOV_CR:
            HandleCrAccess(&guestContext);
            break;

        case VMX_EXIT_REASON_EXECUTE_RDMSR:
            HandleMsrRead(&guestContext);
            break;

        case VMX_EXIT_REASON_EXECUTE_WRMSR:
            HandleMsrWrite(&guestContext);
            break;

        case VMX_EXIT_REASON_EPT_VIOLATION:
            HandleEptViolation(&guestContext);
            break;

        case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
            HandleEptMisconfig(&guestContext);
            break;

        case VMX_EXIT_REASON_EXECUTE_XSETBV:
            HandleXsetbv(&guestContext);
            break;

        default:
            DumpGuestState();
            DumpHostState();
            DumpControl();
            LOG_DEBUG("VM-exit reason (Full) = %x", vmExitReason.Flags);
            MV_PANIC();
    }

    if (guestContext.ContinueVm  == FALSE)
    {
        //
        // End of virtualization is requested. prevent undesired retention of
        // cache.
        //
        // "Software can use the INVVPID instruction with the "all-context" INVVPID
        //  type (...) immediately prior to execution of the VMXOFF instruction."
        // "Software can use the INVEPT instruction with the "all-context" INVEPT
        //  type (...) immediately prior to execution of the VMXOFF instruction."
        // See: 28.3.3.3 Guidelines for Use of the INVVPID Instruction
        // See: 28.3.3.4 Guidelines for Use of the INVEPT Instruction
        //
        InvalidateEptDerivedCache(0);
        InvalidateVpidDerivedCache(0);
    }

    return guestContext.ContinueVm;
}

typedef struct _EXCEPTION_STACK
{
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
    UINT64 InterruptNumber;
    UINT64 ErrorCode;
    UINT64 Rip;
    UINT64 Cs;
    UINT64 Rflags;
} EXCEPTION_STACK;

/*!
    @brief Handles the interrupt and exception occurred during execution of the
        host.

    @details On Windows, this function is unused because the host uses the same
        IDT as that of the guest. All interrupts and exceptions are handled by
        the NT kernel.

    @param[in] Stack - The pointer to the hypervisor stack containing the
        guest register values.
 */
VOID
HandleHostException (
    _In_ CONST EXCEPTION_STACK* Stack
    )
{
    DumpGuestState();
    DumpHostState();
    DumpControl();
    LOG_ERROR("Exception or interrupt 0x%llx(0x%llx)", Stack->InterruptNumber, Stack->ErrorCode);
    LOG_ERROR("RIP  - %016llx, CS  - %016llx, RFLAGS - %016llx", Stack->Rip, Stack->Cs, Stack->Rflags);
    LOG_ERROR("RAX  - %016llx, RCX - %016llx, RDX - %016llx", Stack->Rax, Stack->Rcx, Stack->Rdx);
    LOG_ERROR("RBX  - %016llx, RSP - %016llx, RBP - %016llx", Stack->Rbx, 0ull, Stack->Rbp);
    LOG_ERROR("RSI  - %016llx, RDI - %016llx", Stack->Rsi, Stack->Rdi);
    LOG_ERROR("R8   - %016llx, R9  - %016llx, R10 - %016llx", Stack->R8, Stack->R9, Stack->R10);
    LOG_ERROR("R11  - %016llx, R12 - %016llx, R13 - %016llx", Stack->R11, Stack->R12, Stack->R13);
    LOG_ERROR("R14  - %016llx, R15 - %016llx", Stack->R14, Stack->R15);
    MV_PANIC();
}

/*!
    @brief Handles error occurred on attempt to exit to the guest.

    @param[in] Stack - The pointer to the hypervisor stack containing the
        guest register values.
 */
VOID
HandleVmExitFailure (
    _In_ CONST INITIAL_HYPERVISOR_STACK* Stack
    )
{
    VMX_ERROR_NUMBER vmxErrorNumber;
    VMX_VMEXIT_REASON vmExitReason;

    UNREFERENCED_PARAMETER(Stack);

    vmxErrorNumber = (VMX_ERROR_NUMBER)VmxRead(VMCS_VM_INSTRUCTION_ERROR);
    vmExitReason.Flags = (UINT32)VmxRead(VMCS_EXIT_REASON);

    DumpGuestState();
    DumpHostState();
    DumpControl();
    LOG_ERROR("VM-exit reason (full) = %x, Error = %ul", vmExitReason.Flags, vmxErrorNumber);
    MV_PANIC();
}
