#pragma once

#include "stdafx.h"
typedef void(WINAPI *pFunc)(DWORD, DWORD);
 UINT WINAPI loadCodes(HMODULE hmodule);
 void WINAPI playerHandle();
 void log( char* info);