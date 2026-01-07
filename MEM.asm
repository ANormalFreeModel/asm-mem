OPTION CASEMAP:NONE

EXTERN ReadProcessMemory:PROC
EXTERN WriteProcessMemory:PROC
EXTERN CreateToolhelp32Snapshot:PROC
EXTERN Process32FirstW:PROC
EXTERN Process32NextW:PROC
EXTERN Module32FirstW:PROC
EXTERN Module32NextW:PROC
EXTERN OpenProcess:PROC
EXTERN CloseHandle:PROC
EXTERN MultiByteToWideChar:PROC
EXTERN GetLastError:PROC
EXTERN Sleep:PROC

.data
memoryprocesshandle dq 0
memoryprocessid     dq 0
memorybaseaddress   dq 0
robloxsigma db "RobloxPlayerBeta.exe",0

.code

modelreadvirtualmemory PROC
    sub     rsp, 28h
    mov     rax, 0
    mov     qword ptr [rsp+20h], rax
    call    ReadProcessMemory
    add     rsp, 28h
    ret
modelreadvirtualmemory ENDP

modelwritevirtualmemory PROC
    sub     rsp, 28h
    mov     rax, 0
    mov     qword ptr [rsp+20h], rax
    call    WriteProcessMemory
    add     rsp, 28h
    ret
modelwritevirtualmemory ENDP

memorygetprocessid PROC
    sub     rsp, 318h
    mov     qword ptr [rsp+300h], rbx
    mov     qword ptr [rsp+308h], rsi
    mov     qword ptr [rsp+310h], rdi
    mov     rsi, rcx
    lea     rax, [rsp+100h]
    mov     rcx, 65001
    xor     rdx, rdx
    mov     r8,  rsi
    mov     r9d, -1
    mov     qword ptr [rsp+20h], rax
    mov     dword ptr [rsp+28h], 260
    call    MultiByteToWideChar
    mov     rcx, 2
    xor     rdx, rdx
    call    CreateToolhelp32Snapshot
    mov     rbx, rax
    cmp     rbx, -1
    je      mgpiddone
    lea     rdx, [rsp+40h]
    mov     dword ptr [rdx], 238h
    mov     rcx, rbx
    call    Process32FirstW
    test    rax, rax
    jz      closeandskip1
nextproc:
    lea     rsi, [rsp+40h+36]
    lea     rdi, [rsp+100h]
    mov     ecx, 260
cmpname:
    mov     ax, word ptr [rsi]
    mov     dx, word ptr [rdi]
    cmp     ax, dx
    jne     nomatch
    test    ax, ax
    jz      processfound
    add     rsi, 2
    add     rdi, 2
    dec     ecx
    jnz     cmpname
nomatch:
    mov     rcx, rbx
    lea     rdx, [rsp+40h]
    call    Process32NextW
    test    rax, rax
    jnz     nextproc
closeandskip1:
    xor     rax, rax
    mov     qword ptr [memoryprocessid], rax
    jmp     close1
processfound:
    mov     eax, dword ptr [rsp+40h+8]
    mov     qword ptr [memoryprocessid], rax
close1:
    mov     rcx, rbx
    call    CloseHandle
mgpiddone:
    mov     rax, qword ptr [memoryprocessid]
    mov     rbx, qword ptr [rsp+300h]
    mov     rsi, qword ptr [rsp+308h]
    mov     rdi, qword ptr [rsp+310h]
    add     rsp, 318h
    ret
memorygetprocessid ENDP

memorygetmoduleaddress PROC
    sub     rsp, 338h
    mov     qword ptr [rsp+320h], rbx
    mov     qword ptr [rsp+328h], rsi
    mov     qword ptr [rsp+330h], rdi
    mov     rsi, rcx
    lea     rax, [rsp+200h]
    mov     rcx, 65001
    xor     rdx, rdx
    mov     r8, rsi
    mov     r9d, -1
    mov     qword ptr [rsp+20h], rax
    mov     dword ptr [rsp+28h], 260
    call    MultiByteToWideChar
    mov     rcx, 18h
    mov     rdx, qword ptr [memoryprocessid]
    call    CreateToolhelp32Snapshot
    mov     rbx, rax
    cmp     rbx, -1
    je      gmaddrdone
    lea     rdx, [rsp+30h]
    mov     dword ptr [rdx], 224h
    mov     rcx, rbx
    call    Module32FirstW
    test    rax, rax
    jz      closeandskip2
modloop:
    lea     rsi, [rsp+30h+32]
    lea     rdi, [rsp+200h]
    mov     ecx, 260
cmpmod:
    mov     ax, word ptr [rsi]
    mov     dx, word ptr [rdi]
    cmp     ax, dx
    jne     nomodmatch
    test    ax, ax
    jz      modfound
    add     rsi, 2
    add     rdi, 2
    dec     ecx
    jnz     cmpmod
nomodmatch:
    mov     rcx, rbx
    lea     rdx, [rsp+30h]
    call    Module32NextW
    test    rax, rax
    jnz     modloop
closeandskip2:
    xor     rax, rax
    mov     qword ptr [memorybaseaddress], rax
    jmp     close2
modfound:
    mov     rax, qword ptr [rsp+30h+16]
    mov     qword ptr [memorybaseaddress], rax
close2:
    mov     rcx, rbx
    call    CloseHandle
gmaddrdone:
    mov     rax, qword ptr [memorybaseaddress]
    mov     rbx, qword ptr [rsp+320h]
    mov     rsi, qword ptr [rsp+328h]
    mov     rdi, qword ptr [rsp+330h]
    add     rsp, 338h
    ret
memorygetmoduleaddress ENDP

memoryattachtoprocessbyid PROC
    sub     rsp, 28h
    mov     r8, rcx
    mov     ecx, 1F0FFFh
    xor     edx, edx
    call    OpenProcess
    mov     qword ptr [memoryprocesshandle], rax
    add     rsp, 28h
    ret
memoryattachtoprocessbyid ENDP

memoryattachtoprocess PROC
    sub     rsp, 28h
    call    memorygetprocessid
    test    rax, rax
    jz      attachfail
    mov     rcx, rax
    call    memoryattachtoprocessbyid
    mov     rax, qword ptr [memoryprocesshandle]
    add     rsp, 28h
    ret
attachfail:
    xor     rax, rax
    add     rsp, 28h
    ret
memoryattachtoprocess ENDP

memoryreadraw PROC
    jmp     modelreadvirtualmemory
memoryreadraw ENDP

memoryreadstring PROC
    sub     rsp, 528h
    mov     qword ptr [rsp+510h], rbx
    mov     qword ptr [rsp+518h], rsi
    mov     qword ptr [rsp+520h], rdi
    mov     rbx, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     rdx, rbx
    add     rdx, 10h
    lea     r8, [rsp+30h]
    mov     r9d, 8
    call    modelreadvirtualmemory
    mov     rsi, qword ptr [rsp+30h]
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     rdx, rbx
    add     rdx, 18h
    lea     r8, [rsp+38h]
    mov     r9d, 8
    call    modelreadvirtualmemory
    mov     rax, qword ptr [rsp+38h]
    cmp     rax, 16
    jb      rs_internal
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     rdx, rbx
    lea     r8, [rsp+40h]
    mov     r9d, 8
    call    modelreadvirtualmemory
    mov     rax, qword ptr [rsp+40h]
    jmp     rs_read
rs_internal:
    mov     rax, rbx
rs_read:
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     rdx, rax
    lea     r8, [rsp+100h]
    mov     r9, rsi
    cmp     r9, 1024
    jb      rs_size_ok
    mov     r9, 1024
rs_size_ok:
    call    modelreadvirtualmemory
    lea     rax, [rsp+100h]
    mov     byte ptr [rax+rsi], 0
    mov     rbx, qword ptr [rsp+510h]
    mov     rsi, qword ptr [rsp+518h]
    mov     rdi, qword ptr [rsp+520h]
    add     rsp, 528h
    ret
memoryreadstring ENDP

memoryreadqword PROC
    sub     rsp, 38h
    mov     rdx, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    lea     r8, [rsp+20h]
    mov     r9d, 8
    call    modelreadvirtualmemory
    mov     rax, qword ptr [rsp+20h]
    add     rsp, 38h
    ret
memoryreadqword ENDP

memoryreaddword PROC
    sub     rsp, 38h
    mov     rdx, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    lea     r8, [rsp+20h]
    mov     r9d, 4
    call    modelreadvirtualmemory
    mov     eax, dword ptr [rsp+20h]
    add     rsp, 38h
    ret
memoryreaddword ENDP

memoryreadbyte PROC
    sub     rsp, 38h
    mov     rdx, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    lea     r8, [rsp+20h]
    mov     r9d, 1
    call    modelreadvirtualmemory
    movzx   rax, byte ptr [rsp+20h]
    add     rsp, 38h
    ret
memoryreadbyte ENDP

memorywriteqword PROC
    sub     rsp, 28h
    mov     r8, rdx
    mov     rdx, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     r9d, 8
    call    modelwritevirtualmemory
    add     rsp, 28h
    ret
memorywriteqword ENDP

memorywritedword PROC
    sub     rsp, 28h
    mov     r8, rdx
    mov     rdx, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     r9d, 4
    call    modelwritevirtualmemory
    add     rsp, 28h
    ret
memorywritedword ENDP

memorygetprocessidvalue PROC
    mov     rax, qword ptr [memoryprocessid]
    ret
memorygetprocessidvalue ENDP

memorysetprocessid PROC
    mov     qword ptr [memoryprocessid], rcx
    ret
memorysetprocessid ENDP

memorygetbaseaddress PROC
    mov     rax, qword ptr [memorybaseaddress]
    ret
memorygetbaseaddress ENDP

memorysetbaseaddress PROC
    mov     qword ptr [memorybaseaddress], rcx
    ret
memorysetbaseaddress ENDP

PUBLIC memoryfindroblox
memoryfindroblox PROC
    sub     rsp, 28h
    lea     rcx, robloxsigma
    call    memorygetprocessid
    test    rax, rax
    jz      mf_fail
    lea     rcx, robloxsigma
    call    memorygetmoduleaddress
    mov     rax, qword ptr [memoryprocessid]
    mov     rdx, qword ptr [memorybaseaddress]
    add     rsp, 28h
    ret
mf_fail:
    xor     rax, rax
    xor     rdx, rdx
    add     rsp, 28h
    ret
memoryfindroblox ENDP

PUBLIC WaitForever
WaitForever PROC
    sub     rsp, 28h
wait_loop:
    mov     ecx, 1000
    call    Sleep
    jmp     wait_loop
WaitForever ENDP
END
