; nc up.zoolab.org 2513

; math4: 32-bit signed arithmetic
;         var4 = (var1 * -5) / (-var2 % var3)
;         note: overflowed part should be truncated
; ======
; * BASEADDR rsi = 0x5e8000, DATAADDR = BASEADDR + 0x200000
;       var1 @ 0x7e8000-7e8004
;       var2 @ 0x7e8004-7e8008
;       var3 @ 0x7e8008-7e800c
;       var4 @ 0x7e800c-7e8010
; ======