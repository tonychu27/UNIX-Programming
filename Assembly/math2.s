; nc up.zoolab.org 2511

; math2: signed arithmetic
; 	eax = (-var1 * var2) + var3
; ======
; * BASEADDR rsi = 0x5f8000, DATAADDR = BASEADDR + 0x200000
;       var1 @ 0x7f8000-7f8004
;       var2 @ 0x7f8004-7f8008
;       var3 @ 0x7f8008-7f800c
; ======

add rsi, 0x200000
mov eax, [rsi]  
mov ebx, [rsi + 0x000004]
mov ecx, [rsi + 0x000008]
neg eax
mul ebx
add eax, ecx 

done: