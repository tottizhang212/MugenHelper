#include "stdafx.h"
#include "util.h"

//st: 在statedef 处理函数跳转值前,保存调用入口点
UINT saveEsp1() {

	goto END;
BEGIN:
	__asm {
		MOV DWORD PTR DS : [0x4BE600] , 0x0047EB31;
		PUSH EDX;
		LEA EAX, [ESP + 0x1C];
		mov  ecx, 0x0047EB29;
		jmp ecx;
	}

END:
	//确定代码范围
	UINT begin, end;
	__asm
	{
		mov eax, BEGIN;
		mov begin, eax;
		mov eax, END;
		mov end, eax;
	}
	return copyAsmCode(begin, (end - begin));
}
//st:恢复S溢出的ESP
UINT restoreEsp1() {

	goto END;
BEGIN:
	__asm {
		add esp, 0x90;
		CMP DWORD PTR DS : [0x4BE600] , 0x0047EB31
			jne  _end;
		mov  DWORD PTR DS : [esp] , 0x0047EB31;
		mov  DWORD PTR DS : [0x4BE600] , 0;
	_end:
		retn;

	}

END:
	//确定代码范围
	UINT begin, end;
	__asm
	{
		mov eax, BEGIN;
		mov begin, eax;
		mov eax, END;
		mov end, eax;
	}

	return copyAsmCode(begin, (end - begin));
}
//cmd:在statedef 处理函数跳转值前,保存调用入口点
UINT saveEsp2() {

	goto END;
BEGIN:
	__asm {
		LEA EDX, [ESP + 0x1C];
		PUSH ECX;
		MOV DWORD PTR DS : [0x004BE604] , 0x0047E9B6;
		MOV EBX, 0x0047E9AC;
		JMP EBX;
	}

END:
	//确定代码范围
	UINT begin, end;
	__asm
	{
		mov eax, BEGIN;
		mov begin, eax;
		mov eax, END;
		mov end, eax;
	}
	return copyAsmCode(begin, (end - begin));
}


//cmd:恢复S溢出的ESP
UINT restoreEsp2() {

	goto END;
BEGIN:
	__asm {
		add esp, 0x90;
		CMP DWORD PTR DS : [0x4BE604] , 0x0047E9B6
			jne  _end;
		mov  DWORD PTR DS : [esp] , 0x0047E9B6;
		mov  DWORD PTR DS : [0x4BE604] , 0;
	_end:
		retn;

	}

END:
	//确定代码范围
	UINT begin, end;
	__asm
	{
		mov eax, BEGIN;
		mov begin, eax;
		mov eax, END;
		mov end, eax;
	}

	return copyAsmCode(begin, (end - begin));
}



UINT changeController1() {

	goto END;
BEGIN:
	__asm {
		
		
		                                                               
		MOV EAX, DWORD PTR SS : [ESP + 0x10A0];
		PUSH EDI;
		PUSH ESI;
		PUSH ECX;
		PUSH EDX;
		PUSH EBX;
		PUSH EAX;
		CALL DWORD PTR DS : [0x4BEA08];
		MOV EBX, EAX;
		POP EDX;
		POP ECX;
		POP ESI;
		POP EDI;
		JMP DWORD PTR DS : [EBX * 4 + 0x471644];


	}

END:
	//确定代码范围
	UINT begin, end;
	__asm
	{
		mov eax, BEGIN;
		mov begin, eax;
		mov eax, END;
		mov end, eax;
	}

	return copyAsmCode(begin, (end - begin));
}

UINT changeRever() {

	goto END;
BEGIN:
	__asm {

				                                               
		MOV ESI,EAX;
		PUSH ESI;
		PUSH EDI;
		CALL DWORD PTR DS : [0x4BEA0C];
		CMP EAX, 0x26;
		JNE _end;
		JMP DWORD PTR DS : [0x4BF600];
		_end :
		JMP DWORD PTR DS : [0x4BF604];

	}

END:
	//确定代码范围
	UINT begin, end;
	__asm
	{
		mov eax, BEGIN;
		mov begin, eax;
		mov eax, END;
		mov end, eax;
	}

	return copyAsmCode(begin, (end - begin));


}