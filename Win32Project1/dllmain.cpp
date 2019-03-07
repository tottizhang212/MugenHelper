// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <assert.h>
#include "proc.h"
#include <stdlib.h>  
#include "importTableInject.h"

HANDLE hThread;
HMODULE hDll;



/*

修改ALLEG40.dll让其加载时自动加载MugenHelper.dll，需出场一次后重启程序生效
*/
void attachDllEx() {

	WIN32_FIND_DATA wfd;
	HANDLE hFind = FindFirstFile(L"ALLEG40_old.dll", &wfd);
	if (INVALID_HANDLE_VALUE != hFind) return;
	
	char newFile[MAX_PATH];
	char dllPath[MAX_PATH];
	char* fileName= "ALLEG40.dll";

	sprintf(newFile, "%s.bak", fileName);
	sprintf(dllPath, path, "MugenHelper.dll");
	CopyFileA(fileName, newFile, 0);
	
	importTableInject(newFile, dllPath);

	rename(fileName, "ALLEG40_old.dll");
	rename(newFile, fileName);


}

DWORD WINAPI proc(LPVOID lpParam) {

	Sleep(500L);


	UINT level;
	level = loadCodes(hDll); //加载代码
	if (level >=4) {
		attachDllEx();


	}

	return 0;

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DWORD threadID;
		
		hDll = hModule;
		
		
		hThread = CreateThread(NULL, 0, proc, NULL, 0, &threadID); // 创建线程
		break;
	case DLL_THREAD_ATTACH:

		break;
	case DLL_THREAD_DETACH:

		break;
	case DLL_PROCESS_DETACH:
		
		break;
	}
	return TRUE;
}

