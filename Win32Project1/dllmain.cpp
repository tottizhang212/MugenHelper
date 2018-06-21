// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <assert.h>
#include "proc.h"
#include <stdlib.h>  
#include "importTableInject.h"

HANDLE hThread;
pFunc Hook = (pFunc)(0x0047AA60);




void attachDllEx() {
	
	char newFile[MAX_PATH];
	char* path= "ALLEG40.dll";

	sprintf(newFile, "%s.bak", path);
	CopyFileA(path, newFile, 0);
	
	importTableInject(newFile, "chars\\kfm\\MugenHelper.dll");

	rename(path, "ALLEG40_old.dll");
	rename(newFile, path);

}
/*
	使用Ms的detours库修改dll导入表的功能
	修改zlib.dll让其加载时自动加载MugenHelper.dll，需出场一次后重启程序生效
*/


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DWORD threadID;
		UINT level;
		//HANDLE hThread;
		level= loadCodes(hModule); //加载代码
		if (level >4) {
			attachDllEx();
			//attachDll(); //下次程序启动时直接加载代码
			
		}
				
		
		// MessageBoxW(0, L"正常消息框", L"测试", 0);
		//hThread = CreateThread(NULL, 0, ThreadProc, NULL, 0, &threadID); // 创建线程
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

void hookTest(DWORD para1, DWORD para2) {
	
	MessageBoxA(NULL, "hookTest!", "INFO", MB_OK);
	Hook(para1, para2);
	
}