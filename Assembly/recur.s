; nc up.zoolab.org 2518

; recur: implement a recursive function

;    r(n) = 0, if n <= 0
;         = 1, if n == 1
;         = 2*r(n-1) + 3*r(n-2), otherwise
   
;    please call r(27) and store the result in RAX
; ======
; * BASEADDR rsi = 0x5ea000, DATAADDR = BASEADDR + 0x200000
; ======

mov rdi, 27
call r
jmp exit

r:
    enter 0x10, 0
    
    cmp rdi, 0x1
    jg  c2
    je  c1
c0:
    mov rax, 0x0
    jmp end
c1:
    mov rax, 0x1
    jmp end
c2:
    dec rdi
    mov [rbp - 0x8], rdi
    call r
    mov [rbp - 0x10], rax

    mov rdi, [rbp - 0x8]
    dec rdi
    call r

    imul rax, 0x3
    imul rbx, [rbp - 0x10], 0x2
    add rax, rbx
end:
    leave
    ret
exit: