#pragma once

#include <Windows.h>

#include "MinHook.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef CONTEXT_EXTENDED_REGISTERS
#define CONTEXT_EXTENDED_REGISTERS 0x00000020L
#endif

#define ProcessDebugPort 7
#define ProcessDebugObjectHandle 30
#define ProcessDebugFlags 31
#define STATUS_PORT_NOT_SET ((NTSTATUS)0xC0000353L)

void SetIsDebuggerPresentHook();
void SetRemoteDebugHook();
void SetAdvancedAntiAntiDebugHooks();
void SetHeapAllocHook();
void SetContextHooks();
void SetNtQueryInformationProcessHook();

void InitializeHooks();
void UninitializeHooks();