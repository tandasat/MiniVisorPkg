/*!
    @file HostVmcall.c

    @brief Implementation of hypercall functions.

    @author Satoshi Tanda

    @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
 */
#include "HostVmcall.h"

_Use_decl_annotations_
VOID
HandleVmcallUninstall (
    GUEST_CONTEXT* GuestContext
    )
{
    GDTR gdtr;
    IDTR idtr;

    //
    // This hypercall is not allowed for ring 3.
    //
    if (IsGuestInKernelMode() == FALSE)
    {
        GuestContext->StackBasedRegisters->Rax = (UINT64)MV_STATUS_ACCESS_DENIED;
        goto Exit;
    }

    //
    // On VM-exit, the processor loads registers according with the Host state
    // fields in the VMCS. Some registers are changed, e.g, GPRs, and some
    // others are changed with hard-coded values. The limits of GDTR and IDTR
    // are such example, and updated to 0xFFFF. When the VMRESUME instruction
    // is executed, this is not an issue as VM-entry reloads the proper values
    // from the guest state fields of the VMCS. However, it is not the case when
    // the VMRESUME is not called, like here. In such a case those values must
    // be restored with normal value manually, or PatchGuard will report
    // integrity violation.
    //
    // "The GDTR and IDTR limits are each set to FFFFH."
    // See: 27.5.2 Loading Host Segment and Descriptor-Table Registers
    //
    gdtr.BaseAddress = VmxRead(VMCS_GUEST_GDTR_BASE);
    gdtr.Limit = (UINT16)VmxRead(VMCS_GUEST_GDTR_LIMIT);
    _sgdt(&gdtr);

    idtr.BaseAddress = VmxRead(VMCS_GUEST_IDTR_BASE);
    idtr.Limit = (UINT16)VmxRead(VMCS_GUEST_IDTR_LIMIT);
    __lidt(&idtr);

    //
    // The host may use a different CR3 than that of the guest. This is the case
    // on EFI. Apply the guest one. This assumes that translation both the host
    // CR3 and the guest CR3 has the same translation. Otherwise, the system will
    // crash immediately after updating CR3.
    //
    __writecr3(VmxRead(VMCS_GUEST_CR3));

    //
    // Save some values needed for clean up in the volatile registers.
    // RAX = The address of the all-processors context. This is used as a
    //       return value of the AsmVmxCall function.
    // RCX = The address to continue execution after the execution of the VMXOFF
    //       instruction. This value is needed because we have to manually
    //       transfer execution instead of doing so automatically with the
    //       VMRESUME instruction in this pass.
    // RDX = The RSP value to be restored. Same as the case of RIP, the RSP is
    //       not automatically restored in this pass, and so, has to be updated
    //       by the original value (not host's RSP).
    // Param2  = The RFLAGS value to be restored. Also same as the case of RIP and
    //       RSP. Recall that RFLAGS is also updated automatically on VM-exit.
    //       "RFLAGS is cleared, except bit 1, which is always set."
    //       See: 27.5.3 Loading Host RIP, RSP, and RFLAGS
    //
    GuestContext->StackBasedRegisters->Rax = (UINT64)GuestContext->Contexts->VpContexts;
    GuestContext->StackBasedRegisters->Rcx = GuestContext->VmcsBasedRegisters.Rip +
        VmxRead(VMCS_VMEXIT_INSTRUCTION_LENGTH);
    GuestContext->StackBasedRegisters->Rdx = GuestContext->VmcsBasedRegisters.Rsp;
    GuestContext->StackBasedRegisters->R8 = GuestContext->VmcsBasedRegisters.Rflags.Flags;

    //
    // Finally, indicates that virtualization should be terminated.
    //
    GuestContext->ContinueVm = FALSE;

Exit:
    return;
}
