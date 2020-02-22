;
;   @file Asm.asm
;
;   @brief Cross platform MASM-written functions.
;
;   @author Satoshi Tanda
;
;   @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
;
include AsmCommon.inc

.const

VMX_OK                      equ     0
VMX_ERROR_WITH_STATUS       equ     1
VMX_ERROR_WITHOUT_STATUS    equ     2
KTRAP_FRAME_SIZE            equ     190h
MACHINE_FRAME_SIZE          equ     28h

.code

extern HandleVmExit : proc
extern HandleVmExitFailure : proc

;
;   @brief An entry point for the hypervisor.
;
;   @details The easiest way to understand this code is to see this as an entry
;       point of "VM-exit handler".
;
;       Up on VM-exit, the processor starts executing this function as
;       condifured in the VmcsHostRip field of VMCS. At this time, the processor
;       is in the vmx-root mode, which allows the processor to execute any
;       instructions without causing VM-exit, and the processor is not governed
;       by EPT. The code executed from here emulates the instruction caused
;       VM-exit by, most typically, executing the same instruction on behalf of
;       the guest (see HandleCpuid for example), or changing relevant processor
;       state and letting the guest retry, for example, handling EPT violation.
;
;       What we refer to as hypervisor is basically code executed in this
;       context. We also refer those code as a VM-exit handler.
;
AsmHypervisorEntryPoint proc frame
        ;
        ; Three not-well known techniques are used in this function in oder for
        ; Windbg to display the stack trace of the guest while the VM-exit
        ; handlers are being executed. You can skip this comment block and ignore
        ; the first SUB instruction, .PUSHFRAME, .ALLOCSTACK and .ENDPROLOG if
        ; not interested in. This is not essential for the hypervisor.
        ;
        ; 1) The use of the FRAME (above) attribute. This emits a function table
        ; entry for this function in the .pdata section. See also:
        ; https://docs.microsoft.com/en-us/cpp/assembler/masm/proc?view=vs-2017
        ;
        ; 2) The use of the .PUSHFRAME pseudo operation. This emits unwind data
        ; indicating that a machine frame has been pushed on the stack. A machine
        ; frame is usually pushed by the CPU in response to a trap or fault (
        ; see: 6.12.1 Exception- or Interrupt-Handler Procedures), hence this
        ; pseudo operation is often used for their handler code. (In Windows
        ; kernel, the use of this pseudo operation is often wrapped in the
        ; GENERATE_TRAP_FRAME macro.) In our case, since VM-exit does not push
        ; the machine frame, we manually allocate it with the SUB instruction.
        ; See also:
        ; https://docs.microsoft.com/en-us/cpp/assembler/masm/dot-pushframe?view=vs-2017
        ;
        ; 3) The use of the .ALLOCSTACK pseudo operation. This also emits another
        ; unwind data indicating how much the function uses stack. (This pseudo
        ; code is often wrapped by the alloc_stack macro and used within the
        ; GENERATE_TRAP_FRAME macro.) This function consumes 100h of stack on
        ; the top of the KTRAP_FRAME size (minus the machine frame size, which
        ; is already indicated by the .PUSHFRAME). See also:
        ; https://docs.microsoft.com/en-us/cpp/assembler/masm/dot-allocstack?view=vs-2017
        ;
        .pushframe
        sub     rsp, KTRAP_FRAME_SIZE
        .allocstack KTRAP_FRAME_SIZE - MACHINE_FRAME_SIZE + 100h

        ;
        ; Save the general purpose registers as they are not saved to and loaded
        ; from VMCS. Note that the flag register does not have to be saved as it
        ; is saved to VMCS on VM-exit and loaded from there on VM-entry.
        ;
        ; This operation subtracts RSP 8 * 15.
        ;
        PUSHAQ

        ;
        ; Save volatile XMM registers for the same reason as the general purpose
        ; registers.
        ;
        ; 0x60 for XMM registers and 8 for alignment. Remember that those SSE
        ; SEE instructions has to operate on 0x10 aligned memory.
        ;
        sub     rsp, 68h
        movaps  xmmword ptr [rsp +  0h], xmm0
        movaps  xmmword ptr [rsp + 10h], xmm1
        movaps  xmmword ptr [rsp + 20h], xmm2
        movaps  xmmword ptr [rsp + 30h], xmm3
        movaps  xmmword ptr [rsp + 40h], xmm4
        movaps  xmmword ptr [rsp + 50h], xmm5

        ;
        ; Save the current stack pointer as an argument of the HandleVmExit
        ; function.
        ;
        mov     rcx, rsp

        ;
        ; All stack allocation is done now. Indicate the end of prologue with the
        ; .ENDPROLOG pseudo operation as required by the FRAME attribute.
        ;
        sub     rsp, 20h
        .endprolog

        ;
        ; BOOLEAN continueVm = HandleVmExit(stack);
        ;
        call    HandleVmExit
        add     rsp, 20h

        ;
        ; Restore XMM registers.
        ;
        movaps  xmm0, xmmword ptr [rsp +  0h]
        movaps  xmm1, xmmword ptr [rsp + 10h]
        movaps  xmm2, xmmword ptr [rsp + 20h]
        movaps  xmm3, xmmword ptr [rsp + 30h]
        movaps  xmm4, xmmword ptr [rsp + 40h]
        movaps  xmm5, xmmword ptr [rsp + 50h]
        add     rsp, 68h

        ;
        ; if (continueVm == 0) goto ExitVm
        ;
        test    al, al
        jz      ExitVm

        ;
        ; Otherwise, restore the general purpose registers and resume execution
        ; of the guest.
        ;
        POPAQ
        vmresume
        jmp     VmxError

ExitVm:
        ;
        ; Termination of the VM is requested. Executes VMXOFF and end
        ; virtualization. At this point, some registers have specific values:
        ;   RAX = VpContexts
        ;   RCX = Guest RIP for the next instruction
        ;   RDX = Guest RSP
        ;   R8  = Guest RFLAGS
        ;
        ; Note that unlike VMRESUME, VMXOFF does not update RIP, RSP etc, and
        ; just continues the next instruction (but the processor is no longer in
        ; VMX-root mode). We will check if error occured with VMXOFF subsequently.
        ;
        POPAQ
        vmxoff

        ;
        ; if (ZF) goto VmxError
        ; if (CF) goto VmxError
        ;
        jz      VmxError
        jc      VmxError

        ;
        ; Restore RFLAGS, RSP, and jump to the next instruction.
        ;
        push    r8
        popf
        mov     rsp, rdx
        push    rcx
        ret

VmxError:
        ;
        ; Any of VMX instructions failed. Unrecoverble. The most useful thing
        ; to do here is probably to call a C-function that does diagnostics
        ; like dumping VMCS.
        ;
        PUSHAQ
        sub     rsp, 68h
        movaps  xmmword ptr [rsp +  0h], xmm0
        movaps  xmmword ptr [rsp + 10h], xmm1
        movaps  xmmword ptr [rsp + 20h], xmm2
        movaps  xmmword ptr [rsp + 30h], xmm3
        movaps  xmmword ptr [rsp + 40h], xmm4
        movaps  xmmword ptr [rsp + 50h], xmm5
        mov     rcx, rsp
        sub     rsp, 20h
        call    HandleVmExitFailure
AsmHypervisorEntryPoint endp

;
;   @brief Invalidate translations derived from EPT
;
;   @param[in] RCX - A type of invalidation.
;
;   @param[in] RDX - A description of translations to invalidate.
;
;   @return An appropriate VMX_RESULT value.
;
AsmInvept proc
        invept  rcx, oword ptr [rdx]

        ;
        ; if (ZF) goto ErrorWithCode
        ; if (CF) goto ErrorWithoutCode
        ; return VMX_OK
        ;
        jz      ErrorWithCode
        jc      ErrorWithoutCode
        xor     rax, rax
        ret

ErrorWithCode:
        mov     rax, VMX_ERROR_WITH_STATUS
        ret

ErrorWithoutCode:
        mov     rax, VMX_ERROR_WITHOUT_STATUS
        ret
AsmInvept endp

;
;   @brief Invalidate translations based on VPID
;
;   @param[in] RCX - A type of invalidation.
;
;   @param[in] RDX - A description of translations to invalidate.
;
;   @return An appropriate VMX_RESULT value.
;
AsmInvvpid proc
        invvpid rcx, oword ptr [rdx]

        ;
        ; if (ZF) goto ErrorWithCode
        ; if (CF) goto ErrorWithoutCode
        ; return VMX_OK
        ;
        jz      ErrorWithCode
        jc      errorWithoutCode
        xor     rax, rax
        ret

ErrorWithCode:
        mov     rax, VMX_ERROR_WITH_STATUS
        ret

errorWithoutCode:
        mov     rax, VMX_ERROR_WITHOUT_STATUS
        ret
AsmInvvpid endp

;
;   @brief Reads the access rights byte of the segment.
;
;   @details See: LAR-Load Access Rights Byte
;
;   @param[in] RCX - The selector of the segment to read.
;
;   @return The access rights byte of the segment, or 0 on failure.
;
AsmLoadAccessRightsByte proc
        lar     rax, rcx
        jz      Success
        xor     rax, rax
Success:
        ret
AsmLoadAccessRightsByte endp

;
;   @brief Issues hypercall.
;
;   @param[in] RCX - The hypercall number.
;
;   @param[in] RDX - The arbitrary 64bit parameter 1.
;
;   @param[in] R8 - The arbitrary 64bit parameter 2.
;
;   @param[in] R9 - The arbitrary 64bit parameter 3.
;
;   @return The 64bit return value. Meaning is depends on RCX.
;
AsmVmxCall proc
        vmcall
        ret
AsmVmxCall endp

;
;   @brief Returns the address of the return address from this function.
;
;   @return The address of the return address from this function.
;
AsmGetCurrentInstructionPointer proc
        mov     rax, [rsp]
        ret
AsmGetCurrentInstructionPointer endp

;
;   @brief Returns the current value of RSP.
;
;   @return The current value of RSP.
;
AsmGetCurrentStackPointer proc
        mov     rax, rsp
        add     rax, 8
        ret
AsmGetCurrentStackPointer endp

        end
