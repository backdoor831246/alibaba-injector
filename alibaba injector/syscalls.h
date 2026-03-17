#pragma once
#include <windows.h>
#include <winternl.h>

#ifdef _WIN64
extern "C" {
    void GetSyscall(WORD systemCall);
    void GetSyscallAddr(ULONG64 syscallAddr);

    NTSTATUS sysZwAllocateVirtualMemory(
        HANDLE    ProcessHandle,
        PVOID     *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T   RegionSize,
        ULONG     AllocationType,
        ULONG     Protect
    );

    NTSTATUS sysNtProtectVirtualMemory(
        HANDLE  ProcessHandle,
        PVOID   *BaseAddress,
        PSIZE_T RegionSize,
        ULONG   NewProtect,
        PULONG  OldProtect
    );

    NTSTATUS sysNtWriteVirtualMemory(
        HANDLE  ProcessHandle,
        PVOID   BaseAddress,
        PVOID   Buffer,
        SIZE_T  NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS sysNtCreateThreadEx(
        PHANDLE     hThread,
        ACCESS_MASK DesiredAccess,
        PVOID       ObjectAttributes,
        HANDLE      ProcessHandle,
        PVOID       lpStartAddress,
        PVOID       lpParameter,
        ULONG       Flags,
        SIZE_T      StackZeroBits,
        SIZE_T      SizeOfStackCommit,
        SIZE_T      SizeOfStackReserve,
        PVOID       lpBytesBuffer
    );

    NTSTATUS sysNtWaitForSingleObject(
        HANDLE         Handle,
        BOOLEAN        Alertable,
        PLARGE_INTEGER Timeout
    );

    NTSTATUS sysNtOpenProcess(
        PHANDLE            ProcessHandle,
        ACCESS_MASK        DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        CLIENT_ID          *ClientId
    );

    NTSTATUS sysNtReadVirtualMemory(
        HANDLE  ProcessHandle,
        PVOID   BaseAddress,
        PVOID   Buffer,
        SIZE_T  NumberOfBytesToRead,
        PSIZE_T NumberOfBytesRead
    );

    NTSTATUS sysNtFreeVirtualMemory(
        HANDLE  ProcessHandle,
        PVOID   *BaseAddress,
        PSIZE_T RegionSize,
        ULONG   FreeType
    );
}
#endif
