; nc up.zoolab.org 2507

; isolatebit:
;         get the value bit-11 ~ bit-5 in AX and store the result in val1
;         (zero-based bit index)
; ======
; * BASEADDR rsi = 0x559000, DATAADDR = BASEADDR + 0x200000
;       val1 @ 0x759000-759001
;       val2 @ 0x759001-759002
; ======

add rsi, 0x200000
and ax, 0x0FE0
shr ax, 5
mov [rsi], al
done: