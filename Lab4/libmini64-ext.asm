%include "libmini.inc"
%define SIGSET_ALL 0xFFFFFFFF
%define CONST 0x5851f42d4c957f2d

; Syscall Calling Convention
; rdi, rsi, rdx, r10, r8, r9
; Syscall Number: rax

section .data
    my_seed dq 0

section .text

global time

global srand
global grand
global rand

global sigemptyset
global sigfillset
global sigaddset
global sigdelset
global sigismember

global sigprocmask

global setjmp
global longjmp

time:
    mov     rax, 201
    xor     rdi, rdi
    syscall
    ret

srand:
    mov     eax, edi
    sub     eax, 1
    mov     dword [rel my_seed], eax
    ret

grand:
    mov     eax, dword [rel my_seed]
    ret

rand:
    mov     rax, [rel my_seed]
    mov     rcx, CONST

    mul     rcx
    add     rax, 1

    mov     [rel my_seed], rax

    shr     rax, 33

    mov     eax, eax
    ret


; int sigemptyset(sigset_t *set)
sigemptyset:
    xor     rax, rax
    mov     qword [rdi], rax
    xor     eax, eax
    ret

; int sigfillset(sigset_t *set)
sigfillset:
    mov     dword [rdi], SIGSET_ALL
    xor     eax, eax
    ret

; int sigaddset(sigset_t *set, int signum)
sigaddset:
    mov     eax, esi
    cmp     eax, 1
    jl      error
    cmp     eax, 32
    jg      error

    dec     eax
    mov     ecx, eax
    mov     eax, 1
    shl     eax, cl
    or      dword [rdi], eax
    xor     eax, eax
    ret

; int sigdelset(sigset_t *set, int signum)
sigdelset:
    mov     eax, esi
    cmp     eax, 1
    jl      error
    cmp     eax, 32
    jg      error

    dec     eax
    mov     ecx, eax
    mov     eax, 1
    shl     eax, cl
    not     eax
    and     dword [rdi], eax
    xor     eax, eax
    ret

; int sigismember(const sigset_t *set, int signum)
sigismember:
    mov     eax, esi
    cmp     eax, 1
    jl      error
    cmp     eax, 32
    jg      error

    dec     eax
    mov     ecx, eax
    mov     eax, 1
    shl     eax, cl
    mov     edx, dword [rdi]
    test    edx, eax
    setnz   al
    movzx   eax, al
    ret

; int sigprocmask(int how, const sigset_t *newset, sigset_t *oldset)
sigprocmask:
    mov     eax, 14
    mov     r10, 8
    syscall
    ret

; int setjmp(jmp_buf jb)
setjmp:
    mov     rax, [rsp]
    mov     [rdi + 0], rax

    mov     [rdi + 8],  rbx
    mov     [rdi + 16], rbp
    mov     [rdi + 24], rsp
    mov     [rdi + 32], r12
    mov     [rdi + 40], r13
    mov     [rdi + 48], r14
    mov     [rdi + 56], r15

    mov     eax, 14
    lea     rdx, [rdi + 64]
    xor     rdi, rdi
    xor     rsi, rsi
    mov     r10, 8
    syscall

    xor     eax, eax
    ret

; void longjmp(jmp_buf jb, int ret);
longjmp:  
    mov     r15, [rdi + 56]
    mov     r14, [rdi + 48]
    mov     r13, [rdi + 40]
    mov     r12, [rdi + 32]
    mov     rsp, [rdi + 24]
    mov     rbp, [rdi + 16]
    mov     rbx, [rdi + 8]

    mov     eax, 14
    lea     rsi, [rdi + 64]
    push    rdi
    mov     rdi, 2
    xor     rdx, rdx
    mov     r10, 8
    syscall

    mov     eax, esi
    pop     rdi
    jmp     qword [rdi]


error:
    mov     eax, -1
    ret 
