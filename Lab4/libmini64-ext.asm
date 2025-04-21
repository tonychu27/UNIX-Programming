%include "libmini.inc"
%define SIGSET_ALL 0xFFFFFFFF

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
    mov     rcx, 0x5851f42d4c957f2d

    mul     rcx
    add     rax, 1

    mov     [rel my_seed], rax

    shr     rax, 33

    mov     eax, eax
    ret


; int sigemptyset(sigset_t *set)
sigemptyset:
    mov     dword [rdi], 0
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
setjmp: ; Haven't implemented

; void longjmp(jmp_buf jb, int ret);
longjmp: ; Haven't implemented
    ret

error:
    mov     eax, -1
    ret 
