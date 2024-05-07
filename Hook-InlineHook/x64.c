// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

BYTE g_pOrgBytes[12] = { 0 };

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

BOOL api_hook(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
    FARPROC pfnOrg;
    DWORD dwOldProtect;
    BYTE pBuf[12] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0xff, 0xe0 };


    //获取需要HOOK的函数地址
    pfnOrg = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);

    /*
    * 48 B8 88 77 66 55 44 33 22 11 mov rax, 0x1122334455667788
    * FF E0                         jmp rax
    * 需要12个字节进行跳转
    */

    //修改区域权限
    VirtualProtect((LPVOID)pfnOrg, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    //保存原有的12字节数据
    memcpy(pOrgBytes, pfnOrg, 12);
    //将HOOK函数的地址填进缓冲区
    //将目标地址拷贝到指令中
    memcpy(&pBuf[2], &pfnNew, 8);
    //篡改待钩取函数
    memcpy(pfnOrg, pBuf, 12);
    //恢复权限
    VirtualProtect((LPVOID)pfnOrg, 12, dwOldProtect, &dwOldProtect);

    return TRUE;

}

BOOL api_unhook(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
    FARPROC pfnOrg;
    DWORD dwOldProtect;

    pfnOrg = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    VirtualProtect(pfnOrg, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy(pfnOrg, pOrgBytes, 12);
    VirtualProtect(pfnOrg, 12, dwOldProtect, &dwOldProtect);
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
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    HMODULE hModule;
    FARPROC func;

    api_unhook("kernel32.dll", "CreateProcessW", g_pOrgBytes);
    hModule = GetModuleHandleA("kernel32.dll");
    func = GetProcAddress(hModule, "CreateProcessW");
    LPCWSTR applicationName = L"C:\\Windows\\System32\\calc.exe";
    BOOL ret = ((LPFN_CreateProcessW)(func))(
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
    api_hook("kernel32.dll", "CreateProcessW", (FARPROC)MyCreateProcess, g_pOrgBytes);
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
        api_hook("kernel32.dll", "CreateProcessW", (FARPROC)MyCreateProcess, g_pOrgBytes);
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

