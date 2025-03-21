; nc up.zoolab.org 2517

; posneg: test if registers are positive or negative.
;         if ( eax >= 0 ) { var1 = 1 } else { var1 = -1 }
;         if ( ebx >= 0 ) { var2 = 1 } else { var2 = -1 }
;         if ( ecx >= 0 ) { var3 = 1 } else { var3 = -1 }
;         if ( edx >= 0 ) { var4 = 1 } else { var4 = -1 } 
; ======
; * BASEADDR rsi = 0x5b3000, DATAADDR = BASEADDR + 0x200000
;       var1 @ 0x7b3000-7b3004
;       var2 @ 0x7b3004-7b3008
;       var3 @ 0x7b3008-7b300c
;       var4 @ 0x7b300c-7b3010
; ======