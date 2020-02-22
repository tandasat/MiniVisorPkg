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
;   @brief Read the value from LDTR.
;
;   @return The value of LDTR.
;
AsmReadLdtr proc
        sldt    ax
        ret
AsmReadLdtr endp

;
;   @brief Read the value from TR.
;
;   @return The value of TR.
;
AsmReadTr proc
        str     ax
        ret
AsmReadTr endp

;
;   @brief Read the value from ES.
;
;   @return The value of ES.
;
AsmReadEs proc
        mov     ax, es
        ret
AsmReadEs endp

;
;   @brief Read the value from CS.
;
;   @return The value of CS.
;
AsmReadCs proc
        mov     ax, cs
        ret
AsmReadCs endp

;
;   @brief Read the value from SS.
;
;   @return The value of SS.
;
AsmReadSs proc
        mov     ax, ss
        ret
AsmReadSs endp

;
;   @brief Read the value from DS.
;
;   @return The value of DS.
;
AsmReadDs proc
        mov     ax, ds
        ret
AsmReadDs endp

;
;   @brief Read the value from FS.
;
;   @return The value of FS.
;
AsmReadFs proc
        mov     ax, fs
        ret
AsmReadFs endp

;
;   @brief Read the value from GS.
;
;   @return The value of GS.
;
AsmReadGs proc
        mov     ax, gs
        ret
AsmReadGs endp

;
;   @brief Write the value to TR.
;
;   @param[in] RCX - The new TR value to write.
;
AsmWriteTr proc
        ltr     cx
        ret
AsmWriteTr endp

        end
