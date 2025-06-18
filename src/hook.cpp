#include "Hook.h"

typedef struct _RTL_HEAP_INFORMATION {
    PVOID BaseAddress;
    ULONG Flags;
    USHORT EntryOverhead;
    USHORT CreatorBackTraceIndex;
    SIZE_T BytesAllocated;
    SIZE_T BytesCommitted;
    ULONG NumberOfTags;
    ULONG NumberOfEntries;
    ULONG NumberOfPseudoTags;
    ULONG PseudoTagGranularity;
    ULONG Reserved[5];
    PVOID Tags;
    PVOID Entries;
} RTL_HEAP_INFORMATION, * PRTL_HEAP_INFORMATION;

typedef struct _RTL_PROCESS_HEAPS {
    ULONG NumberOfHeaps;
    RTL_HEAP_INFORMATION Heaps[1];
} RTL_PROCESS_HEAPS, * PRTL_PROCESS_HEAPS;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN DebuggerEnabled;
    BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _HEAP_ENTRY_INFO {
    PVOID lpData;
    SIZE_T cbData;
} HEAP_ENTRY_INFO;

typedef BOOL(WINAPI* ISDEBUGGERPRESENT)();
ISDEBUGGERPRESENT fpIsDebuggerPresent = NULL;

typedef BOOL(WINAPI* CHECKREMOTEDEBUGGERPRESENT)(HANDLE, PBOOL);
CHECKREMOTEDEBUGGERPRESENT fpCheckRemoteDebuggerPresent = NULL;

typedef NTSTATUS(WINAPI* NTQUERYINFORMATIONPROCESS)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );
NTQUERYINFORMATIONPROCESS fpNtQueryInformationProcess = NULL;

typedef NTSTATUS(WINAPI* RTLQUERYPROCESSHEAPINFORMATION)(
    PVOID HeapInformation,
    ULONG HeapInformationLength,
    PULONG ReturnLength
    );
RTLQUERYPROCESSHEAPINFORMATION fpRtlQueryProcessHeapInformation = NULL;

typedef NTSTATUS(WINAPI* RTLQUERYPROCESSDEBUGINFORMATION)(
    ULONG ProcessId,
    ULONG DebugInfoClassMask,
    PVOID DebugInformation
    );
RTLQUERYPROCESSDEBUGINFORMATION fpRtlQueryProcessDebugInformation = NULL;

typedef NTSTATUS(WINAPI* NTQUERYSYSTEMINFORMATION)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );
NTQUERYSYSTEMINFORMATION fpNtQuerySystemInformation = NULL;

typedef LPVOID(WINAPI* HEAPALLOC)(HANDLE, DWORD, SIZE_T);
HEAPALLOC fpHeapAlloc = NULL;

typedef BOOL(WINAPI* GETTHREADCONTEXT)(HANDLE, LPCONTEXT);
GETTHREADCONTEXT fpGetThreadContext = nullptr;
typedef PVOID(WINAPI* ADDVECTOREDEXCEPTIONHANDLER)(ULONG, PVECTORED_EXCEPTION_HANDLER);
ADDVECTOREDEXCEPTIONHANDLER fpAddVectoredExceptionHandler = nullptr;
typedef ULONG(WINAPI* REMOVEVECTOREDEXCEPTIONHANDLER)(PVOID);
REMOVEVECTOREDEXCEPTIONHANDLER fpRemoveVectoredExceptionHandler = nullptr;

PVECTORED_EXCEPTION_HANDLER g_OriginalVEH = nullptr;
PVOID g_VEHHandle = nullptr;

static BOOL WINAPI MyIsDebuggerPresent() {
    return FALSE;
}

static BOOL WINAPI MyCheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    if (pbDebuggerPresent) {
        *pbDebuggerPresent = FALSE;
    }
    return TRUE;
}

static NTSTATUS WINAPI MyNtQueryInformationProcess(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength) {

    NTSTATUS status = fpNtQueryInformationProcess(
        ProcessHandle, ProcessInformationClass,
        ProcessInformation, ProcessInformationLength, ReturnLength);

    switch (ProcessInformationClass) {
    case ProcessDebugPort:
        if (ProcessInformation) {
            *(PDWORD)ProcessInformation = 0;
        }
        break;
    case ProcessDebugObjectHandle:
        if (ProcessInformation) {
            *(PDWORD)ProcessInformation = NULL;
            return STATUS_PORT_NOT_SET;
        }
        break;
    case ProcessDebugFlags:
        if (ProcessInformation) {
            *(PDWORD)ProcessInformation = 1;
        }
        break;
    default:
        break;
    }

    return status;
}

static NTSTATUS WINAPI MyRtlQueryProcessHeapInformation(
    PVOID HeapInformation,
    ULONG HeapInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = fpRtlQueryProcessHeapInformation(
        HeapInformation, HeapInformationLength, ReturnLength);

    if (NT_SUCCESS(status) && HeapInformation) {
        PRTL_PROCESS_HEAPS pHeaps = (PRTL_PROCESS_HEAPS)HeapInformation;
        if (pHeaps->NumberOfHeaps > 0) {
            pHeaps->Heaps[0].Flags = HEAP_GROWABLE;
        }
    }
    return status;
}

static NTSTATUS WINAPI MyRtlQueryProcessDebugInformation(
    ULONG ProcessId,
    ULONG DebugInfoClassMask,
    PVOID DebugInformation)
{
    NTSTATUS status = fpRtlQueryProcessDebugInformation(
        ProcessId, DebugInfoClassMask, DebugInformation);

    if (NT_SUCCESS(status) && DebugInformation) {
        if (DebugInfoClassMask & 0x01) { // PDI_HEAPS
            PRTL_PROCESS_HEAPS pHeaps = (PRTL_PROCESS_HEAPS)DebugInformation;
            if (pHeaps->NumberOfHeaps > 0) {
                pHeaps->Heaps[0].Flags = HEAP_GROWABLE;
            }
        }
    }
    return status;
}

static NTSTATUS WINAPI MyNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status = fpNtQuerySystemInformation(
        SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);

    // SystemKernelDebuggerInformation = 35
    if (SystemInformationClass == 35 && NT_SUCCESS(status) && SystemInformation) {
        PSYSTEM_KERNEL_DEBUGGER_INFORMATION pInfo =
            (PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation;
        pInfo->DebuggerEnabled = FALSE;
        pInfo->DebuggerNotPresent = TRUE;
    }
    return status;
}

static void PatchHeapDebugInfo(PVOID pHeapMemory, SIZE_T dwSize) {
    if (!pHeapMemory || dwSize == 0) return;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(pHeapMemory, &mbi, sizeof(mbi)) == 0) return;
    if (!(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) return;

#ifndef _WIN64
    SIZE_T nBytesToPatch = 12;
#else
    SIZE_T nBytesToPatch = 20;
#endif

    if (dwSize < nBytesToPatch) return;

    PBYTE pPatchStart = (PBYTE)pHeapMemory + dwSize - nBytesToPatch;

    __try {
        memset(pPatchStart, 0, nBytesToPatch);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {

    }
}

static LPVOID WINAPI MyHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
    LPVOID pResult = fpHeapAlloc(hHeap, dwFlags, dwBytes);

    if (pResult) {
        PatchHeapDebugInfo(pResult, dwBytes);
    }

    return pResult;
}

static void ClearContextDebugInfo(PCONTEXT pContext) {
    if (!pContext) return;

    pContext->Dr0 = 0;
    pContext->Dr1 = 0;
    pContext->Dr2 = 0;
    pContext->Dr3 = 0;
    pContext->Dr6 = 0;
    pContext->Dr7 = 0;

    pContext->EFlags &= ~(0x100 | 0x10000); // TF RF

#ifdef _WIN64
    if (pContext->ContextFlags & CONTEXT_EXTENDED_REGISTERS) {
        PBYTE pExtended = (PBYTE)pContext + 0x4B0;
        RtlZeroMemory(pExtended, 0x20);
    }
#endif
}

static BOOL WINAPI MyGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
    BOOL result = fpGetThreadContext(hThread, lpContext);

    if (result && lpContext) {
        ClearContextDebugInfo(lpContext);
    }

    return result;
}

static LONG WINAPI MyVectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (!pExceptionInfo || !pExceptionInfo->ContextRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    CONTEXT backupContext;
    memcpy(&backupContext, pExceptionInfo->ContextRecord, sizeof(CONTEXT));

    ClearContextDebugInfo(pExceptionInfo->ContextRecord);

    LONG result = EXCEPTION_CONTINUE_SEARCH;
    if (g_OriginalVEH) {
        result = g_OriginalVEH(pExceptionInfo);
    }

    if (result == EXCEPTION_CONTINUE_SEARCH) {
        memcpy(pExceptionInfo->ContextRecord, &backupContext, sizeof(CONTEXT));
    }

    return result;
}

static PVOID WINAPI MyAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler) {
    g_OriginalVEH = Handler;

    g_VEHHandle = fpAddVectoredExceptionHandler(First, MyVectoredExceptionHandler);

    return g_VEHHandle;
}

static ULONG WINAPI MyRemoveVectoredExceptionHandler(PVOID Handle) {
    if (Handle == g_VEHHandle) {
        g_VEHHandle = nullptr;
        g_OriginalVEH = nullptr;
    }

    return fpRemoveVectoredExceptionHandler(Handle);
}

void SetIsDebuggerPresentHook() {
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    if (!hKernelBase) return;

    FARPROC pIsDebuggerPresent = GetProcAddress(hKernelBase, "IsDebuggerPresent");
    if (pIsDebuggerPresent) {
        MH_CreateHook(pIsDebuggerPresent, &MyIsDebuggerPresent,
            reinterpret_cast<void**>(&fpIsDebuggerPresent));
        MH_EnableHook(pIsDebuggerPresent);
    }
}

void SetNtQueryInformationProcessHook() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    FARPROC pNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (pNtQueryInformationProcess) {
        MH_CreateHook(pNtQueryInformationProcess, &MyNtQueryInformationProcess,
            reinterpret_cast<void**>(&fpNtQueryInformationProcess));

        MH_EnableHook(pNtQueryInformationProcess);
    }
}

void SetRemoteDebugHook() {
    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    if (!hKernelBase) return;

    FARPROC pRealCheckRemoteDebuggerPresent = GetProcAddress(hKernelBase, "CheckRemoteDebuggerPresent");
    if (pRealCheckRemoteDebuggerPresent) {
        MH_CreateHook(pRealCheckRemoteDebuggerPresent, &MyCheckRemoteDebuggerPresent,
            reinterpret_cast<void**>(&fpCheckRemoteDebuggerPresent));
        MH_EnableHook(pRealCheckRemoteDebuggerPresent);
    }
}

void SetAdvancedAntiAntiDebugHooks() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    FARPROC pRtlQueryProcessHeapInfo = GetProcAddress(hNtdll, "RtlQueryProcessHeapInformation");
    if (pRtlQueryProcessHeapInfo) {
        MH_CreateHook(pRtlQueryProcessHeapInfo, &MyRtlQueryProcessHeapInformation,
            reinterpret_cast<void**>(&fpRtlQueryProcessHeapInformation));
        MH_EnableHook(pRtlQueryProcessHeapInfo);
    }

    FARPROC pRtlQueryProcessDebugInfo = GetProcAddress(hNtdll, "RtlQueryProcessDebugInformation");
    if (pRtlQueryProcessDebugInfo) {
        MH_CreateHook(pRtlQueryProcessDebugInfo, &MyRtlQueryProcessDebugInformation,
            reinterpret_cast<void**>(&fpRtlQueryProcessDebugInformation));
        MH_EnableHook(pRtlQueryProcessDebugInfo);
    }

    FARPROC pNtQuerySystemInfo = GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (pNtQuerySystemInfo) {
        MH_CreateHook(pNtQuerySystemInfo, &MyNtQuerySystemInformation,
            reinterpret_cast<void**>(&fpNtQuerySystemInformation));
        MH_EnableHook(pNtQuerySystemInfo);
    }
}

void SetHeapAllocHook() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return;

    FARPROC pHeapAlloc = GetProcAddress(hKernel32, "HeapAlloc");
    if (pHeapAlloc) {
        MH_CreateHook(pHeapAlloc, &MyHeapAlloc,
            reinterpret_cast<void**>(&fpHeapAlloc));
        MH_EnableHook(pHeapAlloc);
    }
}

void SetContextHooks() {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return;

    FARPROC pGetThreadContext = GetProcAddress(hKernel32, "GetThreadContext");
    if (pGetThreadContext) {
        MH_CreateHook(pGetThreadContext, &MyGetThreadContext,
            reinterpret_cast<void**>(&fpGetThreadContext));
        MH_EnableHook(pGetThreadContext);
    }
    
    FARPROC pAddVectoredExceptionHandler = GetProcAddress(hKernel32, "AddVectoredExceptionHandler");
    if (pAddVectoredExceptionHandler) {
        MH_CreateHook(pAddVectoredExceptionHandler, &MyAddVectoredExceptionHandler,
            reinterpret_cast<void**>(&fpAddVectoredExceptionHandler));
        MH_EnableHook(pAddVectoredExceptionHandler);
    }

    FARPROC pRemoveVectoredExceptionHandler = GetProcAddress(hKernel32, "RemoveVectoredExceptionHandler");
    if (pRemoveVectoredExceptionHandler) {
        MH_CreateHook(pRemoveVectoredExceptionHandler, &MyRemoveVectoredExceptionHandler,
            reinterpret_cast<void**>(&fpRemoveVectoredExceptionHandler));
        MH_EnableHook(pRemoveVectoredExceptionHandler);
    }
}

void InitializeHooks() {
    if (MH_Initialize() == MH_OK) {
        SetIsDebuggerPresentHook();
        SetRemoteDebugHook();
        SetNtQueryInformationProcessHook();
        SetAdvancedAntiAntiDebugHooks();
        SetHeapAllocHook();
        SetContextHooks();
    }
}

void UninitializeHooks() {
    if (MH_DisableHook(MH_ALL_HOOKS) == MH_OK) {
        MH_Uninitialize();
    }
}
