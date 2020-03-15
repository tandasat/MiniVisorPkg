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
        ;
        ; Push dummy error code for consistent stack layout.
        ;
        push    0
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
        ;
        ; Error code is expected to be pushed by the processor.
        ;
        nop
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
        ;
        ; INT0-7
        ;
        repeat 8
        INTERRUPT_HANDLER             Index
        endm

        ;
        ; INT8, INT9
        ;
        INTERRUPT_HANDLER_WITH_CODE   Index
        INTERRUPT_HANDLER             Index

        ;
        ; INT10-14
        ;
        repeat 5
        INTERRUPT_HANDLER_WITH_CODE   Index
        endm

        ;
        ; INT15-16
        ;
        repeat 2
        INTERRUPT_HANDLER             Index
        endm

        ;
        ; INT17
        ;
        INTERRUPT_HANDLER_WITH_CODE   Index

        ;
        ; INT18-255
        ;
        repeat 238
        INTERRUPT_HANDLER             Index
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

        ;
        ; Remove the error code and interrupt number.
        ;
        add     rsp, 10h
        iretq
AsmCommonExceptionHandler endp

        end
