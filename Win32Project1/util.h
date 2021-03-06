#pragma once
#include "stdafx.h"


#define VALID_ADDRESS 0x004B404A 
#define VAR(index,address) (address+0xE40+index * 4)
#define MODIFYCNS(selfAdR,targetAdR) *((PUINT)(*((PUINT)(targetAdr + 0xBE8)))) = *((PUINT)(*((PUINT)(selfAdr + 0xBE8))))
#define ADRDATA(address) *((PUINT)(address))
#define ADR_BYTE_DATA(address) *((PBYTE)(address))
#define BIT_EXIST(data,byte)( ((data>>byte) & 1)>0 )
#define DEBUG(info) MessageBox(NULL, TEXT(info), TEXT(info), MB_OK)
#define DEBUG2(info) MessageBoxA(NULL, info, info, MB_OK)
#define setbit(x,y)  x|=(1<<y)
#define clrbit(x,y)  x&=~(1<<y)
#define IS_NOT_SELF(selfAdr,targetAdr) ((selfAdr != NULL &&targetAdr!=NULL) && ((ADRDATA(targetAdr + 0xBE8) != ADRDATA(selfAdr + 0xBE8))))  



char* WINAPI ReadCodeFile(char* file, char* startAddress);
void log(const char* content);
void switchJmp(HMODULE hmodule, LPCSTR funName, UINT funAdr, UINT startAdr, UINT relCode);
void switchJmp2(HMODULE hmodule, LPCSTR funName, UINT funAdr, UINT startAdr, UINT writeAdr);
void switchJmp3(UINT jumpAdr, UINT targetAdr);
UINT copyAsmCode(UINT begin, int len);
int isFileExist(const char* file);
char* trim(const char* str);