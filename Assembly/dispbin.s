; nc up.zoolab.org 2505

; dispbin:
;         given a number in AX, store the corresponding bit string in str1.
;         for example, if AX = 0x1234, the result should be:
;         str1 = 0001001000111000
; ======
; * BASEADDR rsi = 0x5b2000, DATAADDR = BASEADDR + 0x200000
;       str1 @ 0x7b2000-7b2014
; ======
; Enter your codes: (type 'done:' when done)