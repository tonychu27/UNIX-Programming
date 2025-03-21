@ tolower: convert the single character in val1 to uppercase and store in val2
@ ======
@ * BASEADDR rsi = 0x56c000, DATAADDR = BASEADDR + 0x200000
@       val1 @ 0x76c000-76c001
@       val2 @ 0x76c001-76c002
@ ======

add rsi, 0x200000

mov al, [rsi]

cmp al, 'a'
jb skip_conversion
cmp al, 'z'
ja skip_conversion

sub al, 0x20

skip_conversion:
    mov [rsi + 1], al

done: