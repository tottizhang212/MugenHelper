#pragma once

#include "stdafx.h"
typedef DWORD(WINAPI *pFunc)(DWORD);
 DWORD WINAPI ThreadProc(LPVOID lpParam);
 void WINAPI loadCodes(HMODULE hmodule);
 DWORD hookTest(DWORD para);
 void WINAPI playerHandle();