// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

BYTE g_pOrdBytes[2] = { 0 };

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
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    HMODULE hModule = GetModuleHandle(L"kernel32.dll");
    FARPROC pfnOld = GetProcAddress(hModule, "CreateProcessW");
    LPCWSTR applicationName = L"C:\\Windows\\System32\\calc.exe";
    BOOL ret = ((LPFN_CreateProcessW)((DWORD)pfnOld + 2))(
        applicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
        );
    return ret;
}

BOOL hotPatch_hook(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOldBytes)
{
    DWORD dwOldProtect;
    //长跳转指令
    BYTE pBuf[5] = { 0xE9, 0 };
    //短跳转指令 + 偏移值
    BYTE pShortJmp[2] = { 0xEB, 0xF9};
    //获取模块地址
    HMODULE hModule = GetModuleHandleA(szDllName);
    //获取函数地址
    FARPROC pfnOld = GetProcAddress(hModule, szFuncName);
    //选中长跳转指令填充的地址，这里选择恰好能容纳jmp指令的位置
    DWORD target = (DWORD)pfnOld - 5;
    //计算跳转的偏移
    DWORD dwAddress =  (DWORD)pfnNew - target - 5;
    //修改区域的权限
    VirtualProtect((LPVOID)target, 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    //将偏移填充到指令中
    memcpy(&pBuf[1], &dwAddress, 4);
    //将长跳转指令填充
    memcpy((LPVOID)target, pBuf, 5);
    //保存原始的两个字节
    memcpy(pOldBytes, pfnOld, 2);
    //将短跳转指令填充
    memcpy(pfnOld, pShortJmp, 2);
    VirtualProtect((LPVOID)target, 7, dwOldProtect, &dwOldProtect);
    return TRUE;
}

BOOL hotPatch_unhook(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOldBytes)
{
    DWORD dwOldProtect;
    HMODULE hModule = GetModuleHandleA(szDllName);
    FARPROC pfnOld = GetProcAddress(hModule, szFuncName);
    VirtualProtect(pfnOld, 2, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy(pfnOld, pOldBytes, 2);
    VirtualProtect(pfnOld, 2, dwOldProtect, &dwOldProtect);
    return TRUE;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hotPatch_hook("kernel32.dll", "CreateProcessW", (FARPROC)MyCreateProcess, g_pOrdBytes);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        hotPatch_unhook("kernel32.dll", "CreateProcessW", g_pOrdBytes); 
        break;
    }
    return TRUE;
}

