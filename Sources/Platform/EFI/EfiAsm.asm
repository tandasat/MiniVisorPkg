;
;   @file EfiAsm.asm
;
;   @brief EFI specific MASM-written functions.
;
;   @author Satoshi Tanda
;
;   @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
;
include AsmCommon.inc
.code

extern HandleHostException : proc

;
; The index to track an interrupt number for generating AsmDefaultExceptionHandlers.
;
Index = 0

;
; Generates the default exception handler code for the given interrupt/exception
; number. The generated code assumes that the interrupt/exception does not push
; error code.
;
; Index is incremented whenever this macro is used.
;
INTERRUPT_HANDLER macro InterruptNumber
        push    0       ; Push dummy error code for consistent stack layout.
        push    InterruptNumber
        jmp     AsmCommonExceptionHandler
        Index = Index + 1
endm

;
; Generates the default exception handler code for the given interrupt/exception
; number. The generated code assumes that the interrupt/exception pushes error code.
;
; Index is incremented whenever this macro is used.
;
INTERRUPT_HANDLER_WITH_CODE macro InterruptNumber
        nop             ; Error code is expected to be pushed by the processor.
        nop
        push    InterruptNumber
        jmp     AsmCommonExceptionHandler
        Index = Index + 1
endm

;
; @brief The default host exception handlers.
;
; @details This is the function containing actually 256 stub functions generated
;   with the INTERRUPT_HANDLER and INTERRUPT_HANDLER_WITH_CODE macros. Each function
;   works as a hendler of the corresponding interrupt/exception in the host.
;
AsmDefaultExceptionHandlers proc
    repeat 8
        INTERRUPT_HANDLER             Index    ; INT0-7
    endm

        INTERRUPT_HANDLER_WITH_CODE   Index    ; INT8
        INTERRUPT_HANDLER             Index    ; INT9

    repeat 5
        INTERRUPT_HANDLER_WITH_CODE   Index    ; INT10-14
    endm

    repeat 2
        INTERRUPT_HANDLER             Index    ; INT15-16
    endm

        INTERRUPT_HANDLER_WITH_CODE   Index    ; INT17

    repeat 238
        INTERRUPT_HANDLER             Index    ; INT18-255
    endm
AsmDefaultExceptionHandlers endp

;
; @brief The common logic for the exception handlers.
;
; @details This function pushes register values into the stack and calls the
;   high-level handler written in C.
;
AsmCommonExceptionHandler proc
        PUSHAQ
        mov     rcx, rsp
        sub     rsp, 20h
        call    HandleHostException
        add     rsp, 20h
        POPAQ
        add     rsp, 10h        ; Remove the error code and interrupt number.
        iretq
AsmCommonExceptionHandler endp

;
; @brief The NMI handler for the host.
;
; @details This implementation is incomplete. When NMI occurs while the host is
;   executed, it should be injected to the guest.
;
AsmNmiExceptionHandler proc
        iretq
AsmNmiExceptionHandler endp

        end
