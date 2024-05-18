// INT3_HOOK.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>

PROC g_pfCreateProcess = NULL;
BYTE  g_chINT3 = 0xcc, g_orInfo = 0;
CREATE_PROCESS_DEBUG_INFO g_cpdi;

void PrintLastError() {
	DWORD errorMessageID = GetLastError();

	if (errorMessageID == 0) {
		std::cout << "No error." << std::endl;
		return;
	}

	LPVOID messageBuffer = nullptr;

	// 格式化错误信息
	size_t size = FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		nullptr,
		errorMessageID,
		0, // Default language
		reinterpret_cast<LPWSTR>(&messageBuffer),
		0,
		nullptr
	);

	if (size == 0) {
		std::cerr << "Error while formatting the error message." << std::endl;
		return;
	}

	// 打印错误信息
	std::wcout << L"Error Code: " << errorMessageID << std::endl;
	std::wcout << L"Error Message: " << static_cast<LPWSTR>(messageBuffer) << std::endl;

	// 释放内存
	LocalFree(messageBuffer);
}

void HookFunction(LPDEBUG_EVENT pde)
{
	HMODULE hMoudle =  GetModuleHandleW(L"kernel32.dll");
	if (hMoudle == NULL)
	{
		std::cerr << "Get Module ERROR" << std::endl;
		exit(-1);
	}
	//获取需要HOOK的函数
	g_pfCreateProcess = GetProcAddress(hMoudle, "CreateProcessW");
	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
	ReadProcessMemory(g_cpdi.hProcess, g_pfCreateProcess,&g_orInfo, sizeof(BYTE), NULL);
	WriteProcessMemory(g_cpdi.hProcess, g_pfCreateProcess, &g_chINT3, sizeof(BYTE), NULL);
}

void HandleFunction(LPDEBUG_EVENT pde)
{
	//typedef struct _EXCEPTION_DEBUG_INFO {
	//	EXCEPTION_RECORD ExceptionRecord;
	//	DWORD            dwFirstChance;
	//} EXCEPTION_DEBUG_INFO, * LPEXCEPTION_DEBUG_INFO;

	//typedef struct _EXCEPTION_RECORD {
	//	DWORD    ExceptionCode;
	//	DWORD    ExceptionFlags;
	//	struct _EXCEPTION_RECORD* ExceptionRecord;
	//	PVOID    ExceptionAddress;
	//	DWORD    NumberParameters;
	//	ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
	//} EXCEPTION_RECORD, * PEXCEPTION_RECORD;



	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;
	CONTEXT ctx;


	//异常是断点异常
	if (per->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		std::cout << "Exception Success\n" << std::endl;
		printf("Exception Address:%p\n", per->ExceptionAddress);
		printf("g_pfCreateProcess:%p\n", g_pfCreateProcess);
		if (per->ExceptionAddress == g_pfCreateProcess)
		{
			WriteProcessMemory(g_cpdi.hProcess,
				g_pfCreateProcess, 
				&g_orInfo, 
				sizeof(BYTE),
				NULL);

			ctx.ContextFlags = CONTEXT_INTEGER;
			GetThreadContext(g_cpdi.hThread, &ctx);

			//BOOL CreateProcess(
			//	LPCTSTR               lpApplicationName,     // 可执行文件的路径或者名称
			//	LPTSTR                lpCommandLine,         // 命令行参数
			//	LPSECURITY_ATTRIBUTES lpProcessAttributes,   // 进程的安全描述符
			//	LPSECURITY_ATTRIBUTES lpThreadAttributes,    // 线程的安全描述符
			//	BOOL                  bInheritHandles,       // 是否继承父进程的句柄
			//	DWORD                 dwCreationFlags,       // 进程创建标志
			//	LPVOID                lpEnvironment,        // 进程的环境变量
			//	LPCTSTR               lpCurrentDirectory,    // 进程的当前目录
			//	LPSTARTUPINFO         lpStartupInfo,        // STARTUPINFO 结构指针
			//	LPPROCESS_INFORMATION lpProcessInformation  // 接收进程信息的结构指针
			//);
			//RCX、RDX、R8、R9
			LPCSTR appName = (LPCSTR)malloc(MAX_PATH);
			ReadProcessMemory(
				g_cpdi.hProcess,
				(LPVOID)ctx.Rcx,
				(LPVOID)appName,
				MAX_PATH,
				NULL
			);
			wprintf(L"appName:%s\n", appName);

			LPTSTR commandLine = (LPTSTR)malloc(MAX_PATH);
			ReadProcessMemory(
				g_cpdi.hProcess,
				(LPVOID)ctx.Rdx,
				(LPVOID)commandLine,
				MAX_PATH,
				NULL
			);
			wprintf(L"commandLine:%s\n", commandLine);

			LPTSTR currentFile = (LPTSTR)malloc(MAX_PATH);
			ReadProcessMemory(
				g_cpdi.hProcess,
				(LPVOID)ctx.Rax,
				(LPVOID)currentFile,
				MAX_PATH,
				NULL
			);
			wprintf(L"currentFile:%s\n", currentFile);

			std::wstring newCommandLine(L"C:\\WINDOWS\\system32\\cmd.exe  C:\\Project\\Typora-Image\\src\\main.exe ");
			std::wstring wCurrentFile(currentFile);
			newCommandLine = newCommandLine + wCurrentFile;
			WriteProcessMemory(
				g_cpdi.hProcess,
				(LPVOID)ctx.Rdx,
				(LPVOID)newCommandLine.c_str(),
				MAX_PATH,
				NULL
			);

			ctx.ContextFlags = CONTEXT_CONTROL;
			GetThreadContext(g_cpdi.hThread, &ctx);
			ctx.Rip = (DWORD64)g_pfCreateProcess;
			SetThreadContext(g_cpdi.hThread, &ctx);

		}
	}
}

void DebugLoop()
{
	//调试事件
	//typedef struct _DEBUG_EVENT {
	//	DWORD dwDebugEventCode; 调试状态码
	//	DWORD dwProcessId;		进程号
	//	DWORD dwThreadId;		线程号
	//	union {
	//		EXCEPTION_DEBUG_INFO Exception;
	//		CREATE_THREAD_DEBUG_INFO CreateThread;
	//		CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
	//		EXIT_THREAD_DEBUG_INFO ExitThread;
	//		EXIT_PROCESS_DEBUG_INFO ExitProcess;
	//		LOAD_DLL_DEBUG_INFO LoadDll;
	//		UNLOAD_DLL_DEBUG_INFO UnloadDll;
	//		OUTPUT_DEBUG_STRING_INFO DebugString;
	//		RIP_INFO RipInfo;
	//	} u;
	//} DEBUG_EVENT, * LPDEBUG_EVENT;

	DEBUG_EVENT de;
	//状态码
	DWORD dwContinueStatus;

	while (WaitForDebugEvent(&de, INFINITE))
	{
		//继续调试的状态
		dwContinueStatus = DBG_CONTINUE;
		//printf("debug event:%d\n", de.dwDebugEventCode);
		if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
		{
			//附加调试则进行断点处理
			printf("HookFunction\n");
			HookFunction(&de);
		}
		if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			//printf("HandleFunction\n");
			HandleFunction(&de);
		}
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}

int main(int argc, char *argv[])
{
	DWORD pid;

	if (argc < 2)
	{
		std::cerr << "\nUsage : hook.exe <pid>" << std::endl;
		exit(-1);
	}
	
	pid = atoi(argv[1]);
	if (!DebugActiveProcess(pid))
	{
		PrintLastError();
		exit(-1);
	}

	std::cout << "success debug" << std::endl;
	DebugLoop();
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
