// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>

BYTE g_pOrgBytes[5] = { 0 };

typedef BOOL(WINAPI* LPFN_CreateProcessW)(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

BOOL api_hook(LPCSTR szDllName, LPCSTR funName, PROC pfnNew, PBYTE pOrgBytes)
{
    HMODULE hMoudle;
    PROC  pfnOld;
    DWORD   dwOldProtect;
    DWORD   dwAddress;

    BYTE pBuf[5] = { 0xe9, 0 };
    hMoudle = GetModuleHandleA(szDllName);
    if (hMoudle == NULL)
    {
        GetLastError();
    }
    //获取函数地址
    pfnOld = GetProcAddress(hMoudle, funName);
    if (pfnOld == NULL)
    {
        GetLastError();
    }
    //修改权限
    VirtualProtect(pfnOld, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    //存储原始的5个字节
    memcpy(pOrgBytes, pfnOld, 5);
    //计算需要跳转到的地址
    //跳转偏移 = 跳转目的地址 - 当前指令地址 - 指令长度
    dwAddress = (ULONGLONG)pfnNew - (ULONGLONG)pfnOld - 5;
    memcpy(&pBuf[1], &dwAddress, 4);
    memcpy(pfnOld, pBuf, 5);
    VirtualProtect(pfnOld, 5, dwOldProtect, &dwOldProtect);
    return TRUE;
}

BOOL api_unhook(LPCSTR szDllName, LPCSTR funcName, PBYTE pOrgBytes)
{
    HMODULE hModule;
    PROC pfnOld;
    DWORD dwOldProtect;

    hModule = GetModuleHandleA(szDllName);
    pfnOld = GetProcAddress(hModule, funcName);
    VirtualProtect(pfnOld, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy(pfnOld, pOrgBytes, 5);
    VirtualProtect(pfnOld, 5, dwOldProtect, &dwOldProtect);
    return TRUE;
}



BOOL MyCreateProcess(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{

    HMODULE hMoudle;
    FARPROC hFunc;
    api_unhook("kernel32.dll", "CreateProcessW", g_pOrgBytes);
    hMoudle = GetModuleHandleA("kernel32.dll");
    hFunc = GetProcAddress(hMoudle, "CreateProcessW");
    LPCWSTR applicationName = L"C:\\Windows\\System32\\calc.exe";
    BOOL ret = ((LPFN_CreateProcessW)hFunc)(
            applicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    api_hook("kernel32.dll", "CreateProcessW", (PROC)MyCreateProcess, g_pOrgBytes);
    return ret;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        api_hook("kernel32.dll", "CreateProcessW", (PROC)MyCreateProcess, g_pOrgBytes);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        api_unhook("kernel32.dll", "CreateProcessW", g_pOrgBytes);
        break;
    }
    return TRUE;
}

