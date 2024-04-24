// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>

typedef BOOL(WINAPI *LPFN_CreateProcessW)(
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

FARPROC g_pOrgFunc = NULL;

BOOL MyCreateProcessW(
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
    LPCWSTR applicationName = L"C:\\Windows\\System32\\calc.exe";
    
    return ((LPFN_CreateProcessW)g_pOrgFunc)(applicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);

}

BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
    HMODULE hMod;
    LPCSTR szLibName;
    PIMAGE_DOS_HEADER pImageDosHeader;
    PBYTE pBase;
    PIMAGE_NT_HEADERS pImageNtHeaders;
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;
    DWORD dwOldProtect;

    //获取当前进程的基地址
    hMod = GetModuleHandle(NULL);
    pBase = (PBYTE)hMod;
    //进程的基地址是从DOS头开始的
    pImageDosHeader = (PIMAGE_DOS_HEADER)hMod;
    //通过e_lfanew变量获取NT头的偏移，然后加上基地址及NT头的位置
    pImageNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pImageDosHeader->e_lfanew);
    //数据目录项下标为1的项是导入表
    pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(pImageNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress + pBase);

    for (; pImageImportDescriptor->Name; pImageImportDescriptor++)
    {
        szLibName = (LPCSTR)(pImageImportDescriptor->Name + pBase);
        if (!_stricmp(szLibName, szDllName))
        {
            PIMAGE_THUNK_DATA pImageThunkData = (PIMAGE_THUNK_DATA)(pImageImportDescriptor->FirstThunk + pBase);
            for (; pImageThunkData->u1.Function; pImageThunkData++)
            {
                if (pImageThunkData->u1.Function == (ULONGLONG)pfnOrg)
                {
                    VirtualProtect(&pImageThunkData->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    pImageThunkData->u1.Function = (ULONGLONG)pfnNew;
                    VirtualProtect(&pImageThunkData->u1.Function, 4, dwOldProtect, &dwOldProtect);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_pOrgFunc = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateProcessW");
        hook_iat("kernel32.dll", g_pOrgFunc, (PROC)MyCreateProcessW);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        BOOL ret = hook_iat("kernel32.dll", (PROC)MyCreateProcessW, g_pOrgFunc);
        break;
    }
    return TRUE;
}

