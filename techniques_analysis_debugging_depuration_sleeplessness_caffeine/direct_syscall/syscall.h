#pragma once
#include <windows.h>

extern NTSTATUS NtAllocateVirtualMemory (
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);