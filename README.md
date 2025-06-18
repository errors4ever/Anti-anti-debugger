# AntiAntiDebugger DLL

用于绕过Windows应用程序反调试技术的DLL库,注入程序后即可使用

## hook的api

1. kernelbase!IsDebuggerPresent()
2. ntdll!NtQueryInformationProcess()
3. kernelbase!CheckRemoteDebuggerPresent()
4. ntdll!RtlQueryProcessHeapInformation()
5. ntdll!RtlQueryProcessDebugInformation()
6. ntdll!NtQuerySystemInformation()
7. kernel32!HeapAlloc()
8. kernel32!GetThreadContext()
9. kernel32!AddVectoredExceptionHandler()
10. kernel32!RemoveVectoredExceptionHandler()

## 设置的flag

1. pPeb->BeingDebugged
2. pPeb->NtGlobalFlag
3. heapFlags

## 编译说明

### 环境要求

- Visual Studio 2019/2022
- Windows SDK
- MinHook库

## 踩坑

1.dllmain中安装启用所有hook导致死锁,改为创建线程延后运行hook后问题解决

## 致谢

[checkpoint](https://anti-debug.checkpoint.com/)提供的大部分反反调试知识与源码
