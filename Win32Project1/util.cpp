
#include "stdafx.h"
#include <stdlib.h>  
#include<time.h>
#include <assert.h>
#include "proc.h"
#include "util.h"
#include "resource.h"




/*

从cem文件中读取 shellcode代码到内存的指定地址中
*/
char* WINAPI ReadCodeFile(char* file, char* startAddress) {

	FILE * pFile;
	long lSize;
	char buffer[100];
	sprintf(buffer, path, file);
	//char * buffer;
	size_t result;
	pFile = fopen(buffer, "rb");
	if (pFile == NULL)
	{
		fputs("File error", stderr);
		exit(1);
	}

	/* 获取文件大小 */
	fseek(pFile, 0, SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);
	/* 分配内存存储整个文件 */
	//buffer 
	if (startAddress == NULL)
	{
		startAddress = (char*)malloc(sizeof(char)*lSize);
	}
	/* 将文件拷贝到buffer中 */
	result = fread(startAddress, 1, lSize, pFile);
	if (result != lSize)
	{
		fputs("Reading error", stderr);
		exit(3);
	}

	fclose(pFile);

	return startAddress;
}
void switchJmp(HMODULE hmodule, LPCSTR funName, UINT funAdr, UINT startAdr, UINT relCode) {

	ADRDATA(funAdr) = (UINT)GetProcAddress(hmodule, funName);
	VirtualProtect((LPVOID)startAdr, 16, 0x40, (PDWORD)0x004BE200);
	ADRDATA(startAdr) = relCode;
	startAdr += 4;
	ADR_BYTE_DATA(startAdr) = 0;


}

void switchJmp2(HMODULE hmodule, LPCSTR funName, UINT funAdr, UINT startAdr, UINT writeAdr) {

	ADRDATA(funAdr) = (UINT)GetProcAddress(hmodule, funName);

	
	VirtualProtect((LPVOID)startAdr, 16, 0x40, (PDWORD)0x004BE200);
	UINT rav = writeAdr - startAdr - 5;


	UINT relCode = 0xE9 | (rav << 8);
	ADRDATA(startAdr) = relCode;
	startAdr += 4;
	relCode = 0 | (rav >> 24);
	ADR_BYTE_DATA(startAdr) = relCode;


}

void log(const char* content) {

	FILE * pFile;
	char buffer[100];
	sprintf(buffer, path, "debug.log");
	pFile = fopen(buffer, "a+");
	time_t t = time(0);
	char tmpBuf[100];
	strftime(tmpBuf, 100, "%Y-%m-%d %H:%M:%S", localtime(&t)); //format date and time. 
	fprintf(pFile, "%s---%s\r\n", tmpBuf, content);
	fclose(pFile);
}