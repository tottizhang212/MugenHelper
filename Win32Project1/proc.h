#pragma once

#include "stdafx.h"
typedef void(WINAPI *pFunc)(DWORD, DWORD);
 DWORD WINAPI ThreadProc(LPVOID lpParam);
 UINT WINAPI loadCodes(HMODULE hmodule);
 void hookTest(DWORD para1, DWORD para2);
 void WINAPI playerHandle();
 void log( char* info);