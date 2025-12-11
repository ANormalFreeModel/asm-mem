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
    sub     rsp, 40h
    mov     qword ptr [rsp+0], rbx
    mov     qword ptr [rsp+8], rsi
    mov     qword ptr [rsp+10h], rdi
    lea     rax, [rsp+30h]
    mov     qword ptr [rsp+20h], rax
    call    ReadProcessMemory
    mov     rbx, qword ptr [rsp+0]
    mov     rsi, qword ptr [rsp+8]
    mov     rdi, qword ptr [rsp+10h]
    add     rsp, 40h
    ret
modelreadvirtualmemory ENDP
modelwritevirtualmemory PROC
    sub     rsp, 40h
    mov     qword ptr [rsp+0], rbx
    mov     qword ptr [rsp+8], rsi
    mov     qword ptr [rsp+10h], rdi
    lea     rax, [rsp+30h]
    mov     qword ptr [rsp+20h], rax
    call    WriteProcessMemory
    mov     rbx, qword ptr [rsp+0]
    mov     rsi, qword ptr [rsp+8]
    mov     rdi, qword ptr [rsp+10h]
    add     rsp, 40h
    ret
modelwritevirtualmemory ENDP
memorygetprocessid PROC
    sub     rsp, 300h
    mov     qword ptr [rsp+0], rbx
    mov     qword ptr [rsp+8], rsi
    mov     qword ptr [rsp+10h], rdi
    mov     qword ptr [rsp+18h], rcx
    lea     rax, [rsp+100h]
    mov     rcx, 65001
    xor     rdx, rdx
    mov     r8,  qword ptr [rsp+18h]
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
    cmp     rax, 0
    je      closeandskip1
nextproc:
    lea     rsi, [rsp+40h]
    add     rsi, 36
    lea     rdi, [rsp+100h]
    mov     ecx, 260
cmpname:
    mov     ax, word ptr [rsi]
    mov     dx, word ptr [rdi]
    cmp     ax, dx
    jne     nomatch
    cmp     ax, 0
    je      processfound
    add     rsi, 2
    add     rdi, 2
    dec     ecx
    jne     cmpname
nomatch:
    mov     rcx, rbx
    lea     rdx, [rsp+40h]
    call    Process32NextW
    cmp     rax, 0
    je      closeandskip1
    jmp     nextproc
processfound:
    lea     rdi, [rsp+40h]
    mov     eax, dword ptr [rdi+8]
    mov     qword ptr [memoryprocessid], rax
    jmp     close1
closeandskip1:
    xor     rax, rax
    mov     qword ptr [memoryprocessid], rax
close1:
    mov     rcx, rbx
    call    CloseHandle
mgpiddone:
    mov     rdi, qword ptr [rsp+10h]
    mov     rsi, qword ptr [rsp+8]
    mov     rbx, qword ptr [rsp+0]
    add     rsp, 300h
    mov     rax, qword ptr [memoryprocessid]
    ret
memorygetprocessid ENDP




memorygetmoduleaddress PROC
    sub     rsp, 300h
    mov     qword ptr [rsp+0], rbx
    mov     qword ptr [rsp+8], rsi
    mov     qword ptr [rsp+10h], rdi
    mov     rcx, 8
    mov     rdx, qword ptr [memoryprocessid]
    call    CreateToolhelp32Snapshot
    mov     rbx, rax
    cmp     rbx, -1
    je      gmaddrdone
    lea     rdx, [rsp+30h]
    mov     dword ptr [rdx], 438h
    mov     rcx, rbx
    call    Module32FirstW
    cmp     rax, 0
    je      closeandskip2
modloop:
    lea     rsi, [rsp+30h]
    add     rsi, 36
    lea     rdi, [rsp+200h]
    mov     ecx, 260
cmpmod:
    mov     ax, word ptr [rsi]
    mov     dx, word ptr [rdi]
    cmp     ax, dx
    jne     nomodmatch
    cmp     ax, 0
    je      modfound
    add     rsi, 2
    add     rdi, 2
    dec     ecx
    jne     cmpmod
nomodmatch:
    mov     rcx, rbx
    lea     rdx, [rsp+30h]
    call    Module32NextW
    cmp     rax, 0
    je      closeandskip2
    jmp     modloop
modfound:
    lea     rdi, [rsp+30h]
    mov     rax, qword ptr [rdi+16]
    mov     qword ptr [memorybaseaddress], rax
    jmp     close2
closeandskip2:
    xor     rax, rax
    mov     qword ptr [memorybaseaddress], rax
close2:
    mov     rcx, rbx
    call    CloseHandle
gmaddrdone:
    mov     rdi, qword ptr [rsp+10h]
    mov     rsi, qword ptr [rsp+8]
    mov     rbx, qword ptr [rsp+0]
    add     rsp, 300h
    mov     rax, qword ptr [memorybaseaddress]
    ret
memorygetmoduleaddress ENDP
memoryattachtoprocessbyid PROC
    sub     rsp, 40h
    mov     qword ptr [rsp+0], rbx
    mov     rsi, rcx
    mov     ecx, 1F0FFFh
    xor     edx, edx
    mov     r8,  rsi
    call    OpenProcess
    mov     rbx, rax
    cmp     rbx, 0
    je      atpbad
    mov     qword ptr [memoryprocesshandle], rbx
    mov     qword ptr [memoryprocessid], rsi
    mov     rcx, rsi
    call    memorygetmoduleaddress
    jmp     atpend
atpbad:
    xor     rax, rax
    mov     qword ptr [memoryprocesshandle], rax
atpend:
    mov     rbx, qword ptr [rsp+0]
    add     rsp, 40h
    mov     rax, qword ptr [memoryprocesshandle]
    ret
memoryattachtoprocessbyid ENDP







memoryattachtoprocess PROC
    sub     rsp, 40h
    mov     qword ptr [rsp+0], rbx
    mov     qword ptr [rsp+8], rsi
    call    memorygetprocessid
    mov     rbx, rax
    cmp     rbx, 0
    je      attachfail
    mov     rcx, qword ptr [memoryprocessid]
    call    memoryattachtoprocessbyid
    mov     rax, qword ptr [memoryprocesshandle]
    jmp     attachend
attachfail:
    xor     rax, rax
attachend:
    mov     rsi, qword ptr [rsp+8]
    mov     rbx, qword ptr [rsp+0]
    add     rsp, 40h
    ret
memoryattachtoprocess ENDP
memoryreadraw PROC
    sub     rsp, 40h
    mov     rcx, qword ptr [memoryprocesshandle]
    call     modelreadvirtualmemory
    add     rsp, 40h
    ret
memoryreadraw ENDP




memoryreadstring PROC
    sub     rsp, 300h
    mov     qword ptr [rsp+0], rbx
    mov     qword ptr [rsp+8], rsi
    mov     qword ptr [rsp+10h], rdi
    mov     rax, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     rdx, rax
    lea     r8,  [rsp+100h]
    mov     r9d, 4
    call     modelreadvirtualmemory
    mov     eax, dword ptr [rsp+100h]
    mov     ecx, eax
    cmp     ecx, 16
    jb      rsdirect
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     rdx, rax
    lea     r8,  [rsp+110h]
    mov     r9d, 8
    call     modelreadvirtualmemory
    mov     rax, qword ptr [rsp+110h]
rsdirect:
    xor     rsi, rsi
    lea     rdi, [rsp+120h]
rsloop:
    mov     rcx, qword ptr [memoryprocesshandle]
    lea     r8,  [rsp+140h]
    mov     rdx, rax
    add     rdx, rsi
    mov     r9d, 1
    call     modelreadvirtualmemory
    mov     al, byte ptr [rsp+140h]
    mov     byte ptr [rdi + rsi], al
    cmp     al, 0
    je      rsend
    inc     rsi
    cmp     rsi, 1024
    jb      rsloop
rsend:
    lea     rcx, [rsp+120h]
    mov     rax, rsi
    mov     rdx, rcx
    mov     rdi, qword ptr [rsp+10h]
    mov     rsi, qword ptr [rsp+8]
    mov     rbx, qword ptr [rsp+0]
    add     rsp, 300h
    ret
memoryreadstring ENDP




memoryreadqword PROC
    sub     rsp, 40h
    mov     qword ptr [rsp+0], rbx
    mov     rdx, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    lea     r8,  [rsp+10h]
    mov     r9d, 8
    call    modelreadvirtualmemory
    mov     rax, qword ptr [rsp+10h]
    mov     rbx, qword ptr [rsp+0]
    add     rsp, 40h
    ret
memoryreadqword ENDP



memoryreaddword PROC
    sub     rsp, 40h
    mov     qword ptr [rsp+0], rbx
    mov     rdx, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    lea     r8, [rsp+10h]
    mov     r9d, 4
    call    modelreadvirtualmemory
    mov     eax, dword ptr [rsp+10h]
    mov     rbx, qword ptr [rsp+0]
    add     rsp, 40h
    ret
memoryreaddword ENDP
memoryreadbyte PROC
    sub     rsp, 40h
    mov     qword ptr [rsp+0], rbx
    mov     rdx, rcx
    mov     rcx, qword ptr [memoryprocesshandle]
    lea     r8, [rsp+10h]
    mov     r9d, 1
    call    modelreadvirtualmemory
    mov     al, byte ptr [rsp+10h]
    movzx   rax, al
    mov     rbx, qword ptr [rsp+0]
    add     rsp, 40h
    ret
memoryreadbyte ENDP


memorywriteqword PROC
    sub     rsp, 40h
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     r9d, 8
    call     modelwritevirtualmemory
    add     rsp, 40h
    ret
memorywriteqword ENDP
memorywritedword PROC
    sub     rsp, 40h
    mov     rcx, qword ptr [memoryprocesshandle]
    mov     r9d, 4
    call     modelwritevirtualmemory
    add     rsp, 40h
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
    sub     rsp, 300h
    mov     qword ptr [rsp+0], rbx
    mov     qword ptr [rsp+8], rsi
    mov     qword ptr [rsp+10h], rdi
    lea     rax, [rsp+100h]
    mov     rcx, 65001
    xor     rdx, rdx
    lea     r8, robloxsigma
    mov     r9d, -1
    mov     qword ptr [rsp+20h], rax
    mov     dword ptr [rsp+28h], 260
    call    MultiByteToWideChar
    mov     rcx, 2
    xor     rdx, rdx
    call    CreateToolhelp32Snapshot
    mov     rbx, rax
    cmp     rbx, -1
    je      mfdonenoprc
    lea     rdx, [rsp+40h]
    mov     dword ptr [rdx], 238h
    mov     rcx, rbx
    call    Process32FirstW
    cmp     rax, 0
    je      mfcloseproccess
mfproccessloop:
    lea     rsi, [rsp+40h]
    add     rsi, 36
    lea     rdi, [rsp+100h]
    mov     ecx, 260
mfcmp:
    mov     ax, word ptr [rsi]
    mov     dx, word ptr [rdi]
    cmp     ax, dx
    jne     mfnoresult
    cmp     ax, 0
    je      mfprocessfound
    add     rsi, 2
    add     rdi, 2
    dec     ecx
    jne     mfcmp
mfnoresult:
    mov     rcx, rbx
    lea     rdx, [rsp+40h]
    call    Process32NextW
    cmp     rax, 0
    je      mfcloseproccess
    jmp     mfproccessloop
mfprocessfound:
    lea     rdi, [rsp+40h]
    mov     eax, dword ptr [rdi+8]
    mov     rax, rax
    mov     qword ptr [memoryprocessid], rax
    mov     rcx, rbx
    call    CloseHandle
    mov     rcx, 8
    mov     rdx, qword ptr [memoryprocessid]
    call    CreateToolhelp32Snapshot
    mov     rbx, rax
    cmp     rbx, -1
    je      mfnomodulerr
    lea     rdx, [rsp+30h]
    mov     dword ptr [rdx], 438h
    mov     rcx, rbx
    call    Module32FirstW
    cmp     rax, 0
    je      mfclosesmod
mfmodloop:
    lea     rsi, [rsp+30h]
    add     rsi, 36
    lea     rdi, [rsp+100h]
    mov     ecx, 260
mfcmpmod:
    mov     ax, word ptr [rsi]
    mov     dx, word ptr [rdi]
    cmp     ax, dx
    jne     mfnomodulerrmatch
    cmp     ax, 0
    je      mfmodfound
    add     rsi, 2
    add     rdi, 2
    dec     ecx
    jne     mfcmpmod
mfnomodulerrmatch:
    mov     rcx, rbx
    lea     rdx, [rsp+30h]
    call    Module32NextW
    cmp     rax, 0
    je      mfclosesmod
    jmp     mfmodloop
mfmodfound:
    lea     rdi, [rsp+30h]
    mov     rax, qword ptr [rdi+16]
    mov     qword ptr [memorybaseaddress], rax
    mov     rcx, rbx
    call    CloseHandle
    mov     rax, qword ptr [memoryprocessid]
    mov     rdx, qword ptr [memorybaseaddress]
    jmp     mfcleanup
mfclosesmod:
    xor     rax, rax
    mov     qword ptr [memorybaseaddress], rax
    mov     rcx, rbx
    call    CloseHandle
    jmp     mf_done
mfnomodulerr:
    xor     rax, rax
    mov     qword ptr [memorybaseaddress], rax
    jmp     mf_done
mfcloseproccess:
    xor     rax, rax
    mov     qword ptr [memoryprocessid], rax
    mov     rcx, rbx
    call    CloseHandle
mfdonenoprc:
    xor     rax, rax
    xor     rdx, rdx
mf_done:
    mov     rax, qword ptr [memoryprocessid]
    mov     rdx, qword ptr [memorybaseaddress]
mfcleanup:
    mov     rdi, qword ptr [rsp+10h]
    mov     rsi, qword ptr [rsp+8]
    mov     rbx, qword ptr [rsp+0]
    add     rsp, 300h
    ret
memoryfindroblox ENDP

PUBLIC WaitForever
WaitForever PROC
    sub     rsp, 28h
wait_loop:
    mov     ecx, 1000
    sub     rsp, 20h
    call    Sleep
    add     rsp, 20h
    jmp     wait_loop
WaitForever ENDP
END
