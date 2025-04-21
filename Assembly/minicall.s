; nc up.zoolab.org 2515

; minicall: implement a minimal function call in the emulator
; ===== THE CODE
;     call   a
;     jmp    exit

; a:  ; complete function a to read and return ret-addr in rax
;     ...
;     ret
; exit:
; ======
; * BASEADDR rsi = 0x404000, DATAADDR = BASEADDR + 0x200000
; ======

call a
jmp exit

a:
    mov rax, [rsp]
    ret
exit:
done: