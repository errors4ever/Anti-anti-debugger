#include <windows.h>
#include <winternl.h>

#include "hook.h"
#include "MinHook.h"

//THANKS TO https://anti-debug.checkpoint.com/

static void SetBeingDebuggedFlag() {
#ifndef _WIN64
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#else
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#endif // _WIN64
    pPeb->BeingDebugged = 0;
}

static void SetNtGlobalFlag() {
#ifndef _WIN64
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    *(PDWORD)((PBYTE)pPeb + 0x68) = 0;
#else
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    *(PDWORD)((PBYTE)pPeb + 0xBC) = 0;
#endif // _WIN64
}

static void SetHeapFlag() {
#ifndef _WIN64
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    PVOID pHeapBase = !m_bIsWow64
        ? (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x18))
        : (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x1030));
    DWORD dwHeapFlagsOffset = 0x40;
    DWORD dwHeapForceFlagsOffset = 0x44;
#else
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x30));
    DWORD dwHeapFlagsOffset = 0x70;
    DWORD dwHeapForceFlagsOffset = 0x74;
#endif // _WIN64

    * (PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset) = HEAP_GROWABLE;
    *(PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset) = 0;
}

static void SetAllFlags() {
    SetBeingDebuggedFlag();
    SetNtGlobalFlag();
    SetHeapFlag();
}

static DWORD WINAPI ThreadProc(void* param)
{
    while (true) {
        SetAllFlags();
        Sleep(50);
    }
    return 0;
}

static DWORD WINAPI HookThread(LPVOID) {
    InitializeHooks();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, HookThread, nullptr, 0, nullptr);
    }
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        
        CreateThread(0, 0, ThreadProc, 0, 0, 0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        UninitializeHooks();
        break;
    }
    return TRUE;
}
