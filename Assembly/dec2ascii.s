; nc up.zoolab.org 2504

; dec2ascii: convert the value (0-9) in AL to its ASCII character
; ======
; * BASEADDR rsi = 0x496000, DATAADDR = BASEADDR + 0x200000
; ======

add al, '0'

done: