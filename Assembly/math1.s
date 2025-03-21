; nc up.zoolab.org 2510

; math1: unsigned arithmetic
; 	var4 = (var1 + var2) * var3
; ======
; * BASEADDR rsi = 0x550000, DATAADDR = BASEADDR + 0x200000
;       var1 @ 0x750000-750004
;       var2 @ 0x750004-750008
;       var3 @ 0x750008-75000c
;       var4 @ 0x75000c-750010
; ======

add rsi, 0x200000
mov eax, [rsi]
mov ebx, [rsi + 0x000004]
mov ecx, [rsi + 0x000008]
add eax, ebx
mul ecx
mov [rsi + 0x00000c], eax

done: