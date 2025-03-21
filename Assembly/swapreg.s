; nc up.zoolab.org 2520

; swapreg: swap the values in RAX and RBX
; ======
; * BASEADDR rsi = 0x41b000, DATAADDR = BASEADDR + 0x200000
; ======

mov rcx, rax
mov rdx, rbx
mov rax, rdx
mov rbx, rcx

done: