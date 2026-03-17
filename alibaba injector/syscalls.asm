.data
    systemCall WORD 000h
    syscallAddr QWORD 0h
.code
    GetSyscall proc
        mov systemCall, cx
        ret
    GetSyscall endp

    GetSyscallAddr proc
        mov syscallAddr, rcx
        ret
    GetSyscallAddr endp

    sysZwAllocateVirtualMemory proc
        mov r10, rcx
        mov ax, systemCall
        jmp qword ptr syscallAddr
        ret
    sysZwAllocateVirtualMemory endp

    sysNtProtectVirtualMemory proc
        mov r10, rcx
        mov ax, systemCall
        jmp qword ptr syscallAddr
        ret
    sysNtProtectVirtualMemory endp

    sysNtWriteVirtualMemory proc
        mov r10, rcx
        mov ax, systemCall
        jmp qword ptr syscallAddr
        ret
    sysNtWriteVirtualMemory endp

    sysNtCreateThreadEx proc
        mov r10, rcx
        mov ax, systemCall
        jmp qword ptr syscallAddr
        ret
    sysNtCreateThreadEx endp

    sysNtWaitForSingleObject proc
        mov r10, rcx
        mov ax, systemCall
        jmp qword ptr syscallAddr
        ret
    sysNtWaitForSingleObject endp

    sysNtOpenProcess proc
        mov r10, rcx
        mov ax, systemCall
        jmp qword ptr syscallAddr
        ret
    sysNtOpenProcess endp

    sysNtReadVirtualMemory proc
        mov r10, rcx
        mov ax, systemCall
        jmp qword ptr syscallAddr
        ret
    sysNtReadVirtualMemory endp

    sysNtFreeVirtualMemory proc
        mov r10, rcx
        mov ax, systemCall
        jmp qword ptr syscallAddr
        ret
    sysNtFreeVirtualMemory endp
end
