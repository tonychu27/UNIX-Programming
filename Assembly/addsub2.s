; nc up.zoolab.org 2501

; addsub2:
; 	final = val1 + val2 - val3
; ======
; * BASEADDR rsi = 0x496000, DATAADDR = BASEADDR + 0x200000
;       val1 @ 0x696000-696004
;       val2 @ 0x696004-696008
;       val3 @ 0x696008-69600c
;      final @ 0x69600c-696010
; ======

add rsi, 0x200000
mov eax, [rsi]
add eax, [rsi + 0x000004]
sub eax, [rsi + 0x000008]
mov [rsi + 0x00000c], eax

done: