; nc up.zoolab.org 2514

; math5: 32-bit signed arithmetic
;         var3 = (var1 * -var2) / (var3 - ebx)
;         note: overflowed part should be truncated
; ======
; * BASEADDR rsi = 0x5cb000, DATAADDR = BASEADDR + 0x200000
;       var1 @ 0x7cb000-7cb004
;       var2 @ 0x7cb004-7cb008
;       var3 @ 0x7cb008-7cb00c
; ======