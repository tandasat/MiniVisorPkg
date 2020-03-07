;
;   @file WinAsm.asm
;
;   @brief Windows specific MASM-written functions.
;
;   @author Satoshi Tanda
;
;   @copyright Copyright (c) 2020 - , Satoshi Tanda. All rights reserved.
;
.code

;
;   @brief Reads the value of LDTR.
;
;   @return The value of LDTR.
;
AsmReadLdtr proc
        sldt    ax
        ret
AsmReadLdtr endp

;
;   @brief Reads the value of TR.
;
;   @return The value of TR.
;
AsmReadTr proc
        str     ax
        ret
AsmReadTr endp

;
;   @brief Reads the value of ES.
;
;   @return The value of ES.
;
AsmReadEs proc
        mov     ax, es
        ret
AsmReadEs endp

;
;   @brief Reads the value of CS.
;
;   @return The value of CS.
;
AsmReadCs proc
        mov     ax, cs
        ret
AsmReadCs endp

;
;   @brief Reads the value of SS.
;
;   @return The value of SS.
;
AsmReadSs proc
        mov     ax, ss
        ret
AsmReadSs endp

;
;   @brief Reads the value of DS.
;
;   @return The value of DS.
;
AsmReadDs proc
        mov     ax, ds
        ret
AsmReadDs endp

;
;   @brief Reads the value of FS.
;
;   @return The value of FS.
;
AsmReadFs proc
        mov     ax, fs
        ret
AsmReadFs endp

;
;   @brief Reads the value of GS.
;
;   @return The value of GS.
;
AsmReadGs proc
        mov     ax, gs
        ret
AsmReadGs endp

;
;   @brief Writes the value to TR.
;
;   @param[in] RCX - The new TR value to write.
;
AsmWriteTr proc
        ltr     cx
        ret
AsmWriteTr endp

        end
