; nc up.zoolab.org 2509

; loop15:
;         str1 is a string contains 15 lowercase and uppercase alphbets.
;         implement a loop to convert all alplabets to lowercase,
;         and store the result in str2.
; ======
; * BASEADDR rsi = 0x4b3000, DATAADDR = BASEADDR + 0x200000
;       str1 @ 0x6b3000-6b3010
;       str2 @ 0x6b3010-6b3020
; ======

add rsi, 0x200000
mov rdi, rsi
add rdi, 0x000010
mov rcx, 15

convert_loop:
    mov al, [rsi]
    cmp al, 'A'
    jg not_uppercase

    add al, 32

not_uppercase:
    mov [rdi], al           
    inc rsi
    inc rdi
    loop convert_loop

done: