// proc.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <stdlib.h>  
#include<time.h>
#include <assert.h>
#include "proc.h"
#include "resource.h"

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

/*
#define CHAR_NAME "MysteriousKFM"
const char* path = "chars\\kfm\\%s";
const char* configName = "kfm%s";
*/

#define CHAR_NAME "setsuna_tzg"
const  char* path = "chars\\setsuna_tzg\\st\\%s";
const char* configName = "setsuna_tzg%s";


UINT pPlayerHandle = NULL;

UINT version = 0;
UINT level = 0;
UINT mainEntryPoint = ADRDATA(0x004b5b4c);  //主程序入口地址
UINT pDef = NULL; //人物def入口地址
size_t pIndex = -1;//人物def索引
UINT pCns1 = NULL; //cns地址的地址备份
UINT pCns2 = NULL;//cns的地址备份
UINT pDefPath = NULL;//人物def地址
UINT pDeffilePath = NULL;//人物def地址
UINT pChaosorDefPath = NULL;
size_t pChaosorIndex = -1;
UINT lockVic = 0;//胜负锁定
int cnsAtk = 0; //判断对方CNS攻击
UINT selfIndex = 1;//自己的序号
UINT isExist = 0; //判断自己是否在战斗中
UINT myAddr = NULL; //自己的人物入口地址

typedef UINT(*pOnctrl)(UINT pAddress,UINT code);
pOnctrl _onCtrl;


/*

固定地址说明:

  0x004ba000 :自己的人物地址
  0x004bEA04 :汇编代码用：缓存中间结果 
  0x004bEA08 : 控制器回调处理函数地址  
  0x004bEA0C : noko解除回调
  0x004BEA10: 动画回调
  0x004BEA14: 控制器回调处理函数地址2
  0x004BEA18: 控制器回调处理函数地址3
  0x004BF500: dis 返回地址
  0x004BF600: 
*/



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
void log(const char* content) {

	FILE * pFile;
	char buffer[100];
	sprintf(buffer, path, "debug.log");
	pFile = fopen(buffer, "a+");
	time_t t = time(0);
	char tmpBuf[100];
	strftime(tmpBuf, 100, "%Y-%m-%d %H:%M:%S", localtime(&t)); //format date and time. 
	fprintf(pFile, "%s---%s\r\n", tmpBuf,content);
	fclose(pFile);
}

UINT pFloatCallback = 0x00496651;//替代用%F入口跳转地址变量

void forbidStateDefOverFlow() {


	//在statedef 处理函数跳转值前把0x004be600写为0047eb31，保存调用入口点
	//BOOL ret = VirtualProtect((LPVOID)0x0047EB24, 8, 0x40, (PDWORD)0x004BE200);


	ReadCodeFile("forStdef1.CEM", (char *)0x0047EB24);

	//ReadCodeFile("chars\\Scathacha_A\\St\\forStdef1.CEM", (char *)0x0047EB24);
	//statedef溢出阻止：原理是在0x0047F184，Ret之前跳转至自己的代码，检查如果入口地址不是0047eb31，就强制把esp恢复为0047eb31
	 VirtualProtect((LPVOID)0x0047F184, 8, 0x40, (PDWORD)0x004BE200);

	ReadCodeFile("forStdef2.CEM", (char *)0x0047F184);

	//ReadCodeFile("chars\\Scathacha_A\\St\\forStdef2.CEM", (char *)0x0047F184);


	//statedef溢出阻止：同上，此处为处理在def文件中溢出，入口点不一样！
	//在statedef 处理函数跳转到0x004BE500前把0x004be604写为0047e9B6，保存调用入口点
	 VirtualProtect((LPVOID)0x0047E9A7, 8, 0x40, (PDWORD)0x004BE200);
	ADRDATA(0x0047E9A7) = 0x03FB54E9;
	*(PBYTE(0x0047E9AB)) = 0x00;

	//跳转到0x004BE516执行ESP恢复
	 VirtualProtect((LPVOID)0x0047F239, 8, 0x40, (PDWORD)0x004BE200);
	ADRDATA(0x0047F239) = 0x03F2D8E9;
	*(PBYTE(0x0047F23D)) = 0x00;
		

	
}
void WINAPI checkStateDefOverFlow(char* content,char* name) {
	
	
	if (strcmp(name, CHAR_NAME) != 0)
	{
		bool isFind = false;
		for (size_t i = 10; i <= 65; i++)
		{
			if (content[i] == ']')
			{
				isFind = true;
				break;
			}
		}
		if (!isFind)
		{
			//DEBUG2("溢出检测");
			
			strcpy(content, "[statedef 199922712]");			
			content = content + 20;
			content[0] = 0;
			content++;
			memset(content, 30, 255);
			strcpy(content, "[state -1]");
			content = content + 10;
			content[0] = 0;
			content++;
			strcpy(content, "type=selfstate");
			content = content + 14;
			content[0] = 0;
			content++;
			strcpy(content, "trigger1 = 1");
			content = content + 12;
			content[0] = 0;
			content++;
			strcpy(content, "value = 120");
			content = content + 11;

		}
	}
	ADRDATA(0x004BF600) = 0x0047EB29;
	


}



void WINAPI checkStateDefOverFlow2(char* content, char* name) {


	if (strcmp(name, CHAR_NAME) != 0)
	{
		
		bool isFind = false;
		for (size_t i = 10; i <= 65; i++)
		{
			if (content[i] == ']')
			{
				isFind = true;
				break;
			}
		}
		if (!isFind)
		{
			
			strcpy(content, "[statedef 299922712]");
			content = content + 20;
			content[0] = 0;
			content++;
			memset(content, 67, 255);
			strcpy(content, "[state -1]");
			content = content + 10;
			content[0] = 0;
			content++;
			strcpy(content, "type=selfstate");
			content = content + 14;
			content[0] = 0;
			content++;
			strcpy(content, "trigger1 = 1");
			content = content + 12;
			content[0] = 0;
			content++;
			strcpy(content, "value = 120");
			content = content + 11;
			memset(content, 67, 1400);

		}
	}
	ADRDATA(0x004BF600) = 0x0047E9AC;



}
//干涉对方控制器 小于6E
UINT WINAPI checkController(UINT ptr,UINT code) {
	//函数偏移量: 0x0C: ctrlset; 0x08:lifeset; 0x09:lifeadd ; 0x34: hitadd; nothitby:0x15  Changeanim:0x16

	
	if (IS_NOT_SELF(myAddr, ptr)) {

		UINT flag = ADRDATA(VAR(CONTROLER_VAR, myAddr));
		UINT newCode = code;
		UINT ishelper = ADRDATA(ptr + 28);
		if (BIT_EXIST(flag, 0) )
		{
			//锁血禁止
			switch (code)
			{

			case 0x08: //lifeset
				newCode= 0x34;

			case 0x09: //lifeadd
				newCode = 0x34;

			case 0x29: //TargetLifeAdd
				newCode = 0x34;

			
			}
		}
			if (BIT_EXIST(flag, 1))
			{
				//脱离-selfstate-禁止
				switch (code)
				{
					//case 0x01: //changestate
						//newCode = 0x34;
					case 0x02: //selfstate
						newCode = 0x34;
									

				}

			}
			if (BIT_EXIST(flag, 2) && ishelper == 0)
			{
				//无敌解除
				switch (code)
				{

				case 0x15://nothitby
					newCode = 0x34;
					ADRDATA(ptr + 4088) = 0;
					ADRDATA(ptr + 4092) = 0x7FFF;
					ADRDATA(ptr + 4096) = 0x7FFF;
	

				}
			}
			if (BIT_EXIST(flag, 3))
			{
				//永续攻击禁止
				switch (code)
				{

					case 0x27: //targetstate
						newCode = 0x2D;
							
				}
			}
			if (BIT_EXIST(flag, 4))
			{
				//弹幕攻击禁止
				switch (code)
				{


					//case 25: //当身
					//return 0x34;
					//case 26://攻击
					//return 0x34;
				case 0x1C://弹幕
					newCode = 0x34;
					//newCode = 0x1B;

				}
			}
			if (BIT_EXIST(flag, 5))
			{
				//hit,当身禁止
				switch (code)
				{

				case 0x1B: //当身,攻击
					newCode = 0x34;
				
			

				}
			}
			if (BIT_EXIST(flag, 7))
			{
				//对方Helper脱离禁止
				
				UINT id= ADRDATA(ptr + 4);
				if ( (ishelper > 0) &&(id== ADRDATA(VAR(34, myAddr))) ) {
					switch (code)
					{
					
					case 0x02: //selfstate
						newCode = 0x34;


					}

				}
				
			}
			if (BIT_EXIST(flag, 8))
			{
				//changestate-禁止
				switch (code)
				{
					case 0x01: //changestate
					newCode = 0x34;
				//case 0x02: //selfstate
					//newCode = 0x34;
					

				}

			}
			if (BIT_EXIST(flag, 10))
			{
				//varset-禁止
				switch (code)
				{
				case 0x04: //varset
					newCode = 0x34;
					//case 0x02: //varset
					//newCode = 0x34;


				}

			}
			
			return newCode;
			
	}
	else
	{
		return code;
	}
}
// 干涉对方控制器 大于6E
UINT WINAPI checkController2(UINT ptr, UINT code) {
	ADRDATA(0x004BF600) = 0x0047037D;
	if (IS_NOT_SELF(myAddr, ptr)) {

		UINT flag = ADRDATA(VAR(CONTROLER_VAR, myAddr));
		UINT newCode = code;
		UINT ishelper = ADRDATA(ptr + 28);
		
		
		if (BIT_EXIST(flag, 11)&& (ishelper==0))
		{

			
			switch (code)
			{
			case 0x78: //Hitoverride
				newCode = 0xDD;
				ADRDATA(ptr + 4268) = 0;
				ADRDATA(ptr + 4272) = 0;
				ADRDATA(ptr + 4276) = 0;
				ADRDATA(ptr + 4280) = 0;

				ADRDATA(ptr + 4268+20) = 0;
				ADRDATA(ptr + 4272 + 20) = 0;
				ADRDATA(ptr + 4276 + 20) = 0;
				ADRDATA(ptr + 4280 + 20) = 0;


				ADRDATA(ptr + 4268 + 40) = 0;
				ADRDATA(ptr + 4272 + 40) = 0;
				ADRDATA(ptr + 4276 + 40) = 0;
				ADRDATA(ptr + 4280 + 40) = 0;
				
				break;


			}

			//UINT adr1 = ADRDATA(ptr + 4268);
			//ADRDATA(adr1 + 4) = 0;
			//ADRDATA(ptr + 4268) = 0;
			//ADRDATA(ptr + 4272) = 0;
			

		}
		
		return newCode;

	}
	else
	{
				
		return code;
	}


}

// 干涉对方控制器 大于136
UINT WINAPI checkController3(UINT ptr, UINT code)
{
	ADRDATA(0x004BF600) = 0x0047121B;
	if ((ptr!=NULL) && (IS_NOT_SELF(myAddr, ptr)))
	{

		UINT flag = ADRDATA(VAR(CONTROLER_VAR, myAddr));
		UINT newCode = code;
		UINT ishelper = ADRDATA(ptr + 28);

		switch (code)
		{
			case 0x136: //DisplaytoClipboard禁用
				
				if ( (ADRDATA(VAR(PRIMARY_LEVEL_VAR, myAddr)) >= 2) || level>=2)
				{
					
					newCode = 0x141;
				}
				
		
				break;

		}

		return newCode;

	}
	else {

		return code;
	}


}
//当身切换为Hitdef
UINT WINAPI checkRever(UINT ptr, UINT code) {
	ADRDATA(0x004BF600) = 0x0046F52D;
	ADRDATA(0x004BF604) = 0x0046F537;
	if (IS_NOT_SELF(myAddr, ptr))
	{
		UINT flag = ADRDATA(VAR(CONTROLER_VAR, myAddr));
		if (BIT_EXIST(flag, 6))
		{
			
			if (code == 0x26)
				return 0x25;
			
		}
	
	}
	return code;

}


//修改对方动画号
UINT WINAPI checkAnim(UINT ptr, UINT code) {
	ADRDATA(0x004BF600) = 0x0046EA95;
	if (IS_NOT_SELF(myAddr, ptr))
	{
		UINT flag = ADRDATA(VAR(CONTROLER_VAR, myAddr));
		if (BIT_EXIST(flag, 9))

		{
			UINT anim=ADRDATA(VAR(TARGET_ANIM_NO_VAR, myAddr));
			return anim;
		

		}

	}
	return code;


}

UINT WINAPI checkParentVarSet(UINT ptr,UINT isParent) {

	if (IS_NOT_SELF(myAddr, ptr))
	{

		UINT ishelper = ADRDATA(ptr + 28);
		if (ishelper != 0)
		{
			if (isParent == 1)
				return 0;

		}

	}
	return isParent;

}


void switchJmp(HMODULE hmodule,LPCSTR funName,UINT funAdr, UINT startAdr, UINT relCode) {

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

void modifyCode(HMODULE hmodule,UINT level) {

	//log("加载代码！");
	//获取playerHandle的函数地址写入地址0x004BF700，让0x004b7000处的代码能够调用
	*((PUINT)0x004BF700)=(UINT) GetProcAddress(hmodule, "playerHandle");
	
	//修改主线程0x004829A3处的代码，使之跳转执行0x004b7000处代码，而0x004b7000处代码为执行下面的playerHandle函数
		
	PUINT ptr = (PUINT)0x004829A3;
	BOOL ret = VirtualProtect((LPVOID)0x004829A3, 13, 0x40, (PDWORD)0x004BE200);
	//*ptr = 0x4B7000B8;
	*ptr = 0xB8 | (pPlayerHandle << 8);
	ptr++;
	
	*ptr = 0xC3E0FF00 | (pPlayerHandle >>24) ;

	//溢出阻止,在statedef 处理函数跳转值前把0x004be600写为0047eb31，保存调用入口点
	VirtualProtect((LPVOID)0x0047EB24, 8, 0x40, (PDWORD)0x004BE200);
	VirtualProtect((LPVOID)0x0047E9A7, 8, 0x40, (PDWORD)0x004BE200);

	// %n无效化---将0x00496CB6处的 mov [eax],ecx改为 mov ecx,ecx,让写入内存无效！
	 ret = VirtualProtect((LPVOID)0x00496CB6, 8, 0x40, (PDWORD)0x004BE200);

	
	//%F无效化-----将 call [0x0048e848] 改为 call pFloatCallback的地址，对方再修改0x0048e848就没有作用了!
	ret = VirtualProtect((LPVOID)0x00496B8B, 8, 0x40, (PDWORD)0x004BE200);

	//对方调用控制器函数入口： 0x0046E800, 跳转至 0x004BA100
	//函数偏移量存在ebx中，地址值存在 0x00471644+EBX:  0x0C: ctrlset; 0x08:lifeset; 0x09:lifeadd ; 0x34: hitadd;nothitby:0x15
	

	//switchJmp(hmodule, "checkController", 0x004BEA08, 0x0046E854, 0x0501D7E9);

	//noko解除地址运行读写

	ret = VirtualProtect((LPVOID)0x00470449, 16, 0x40, (PDWORD)0x004BE200);
	ret = VirtualProtect((LPVOID)0x00470489, 16, 0x40, (PDWORD)0x004BE200);
	ret = VirtualProtect((LPVOID)0x004704CE, 16, 0x40, (PDWORD)0x004BE200);

	//当身切换为Hitdef 0x0046F528跳转至 0x004BF100
	//switchJmp(hmodule, "checkRever", 0x004BEA0C, 0x0046F528, 0x04FBD3E9);
	
	

	//changeanim回调       0x0046EA90跳转至0x004BF200
	//switchJmp(hmodule, "checkAnim", 0x004BEA10, 0x0046EA90, 0x05076BE9);

	
	//对方调用控制器函数回调2    0x00470378跳转至0x004BF220
	//switchJmp(hmodule, "checkController2", 0x004BEA14, 0x00470378, 0x04EEA3E9);
	

	//对方调用控制器函数回调3
	//switchJmp(hmodule, "checkController3", 0x004BEA18, 0x00471216, 0x04E0B5E9);
	
	//Alive 触发器读取代码地址可读写
	VirtualProtect((LPVOID)0x0047B5EA, 16, 0x40, (PDWORD)0x004BE200);

	// dis溢出阻止--1 保存进入地址
	//startAdr = 0x004131dc;
	//VirtualProtect((LPVOID)startAdr, 16, 0x40, (PDWORD)0x004BE200);
	//ADRDATA(startAdr) = 0x0AC09FE9;
	//startAdr += 4;
	//ADR_BYTE_DATA(startAdr) = 0;
	//恢复esp
	//startAdr = 0x004132A7;
	//VirtualProtect((LPVOID)startAdr, 16, 0x40, (PDWORD)0x004BE200);
	//ADRDATA(startAdr) = 0x0ABFE6E9;
	//startAdr += 4;
	//ADR_BYTE_DATA(startAdr) = 0;
		
	//0x0047B5E9 -- trigger读取Alive的代码地址

	//%F阻止
	if (level >= 1) {
		ADRDATA(0x00496B8B) = (UINT)(&pFloatCallback);
		
	}
	//S溢出阻止
	char buffer[100];
	if (level >= 2) {

		//forbidStateDefOverFlow();
	}

	if (level >= 3) {

		//0x0041f8bb 为判定胜负的代码: edx!=0 && eax=0 时 2p侧胜; edx=0 && eax!=0 时 1p侧判定胜 ;edx=0 && eax=0 时 正常
		ret = VirtualProtect((LPVOID)0x0041F8BB, 8, 0x40, (PDWORD)0x004BE200);
		ADRDATA(0x0041F8BB) = 0x09F040E9;
		ADR_BYTE_DATA(0x0041F8BF) = 0x00;
		//*(PBYTE(0x0041F8BF)) = 0x00;
	}
		
	
}
UINT WINAPI loadCodes(HMODULE hmodule) {

	
	//读取配置文件
	char buffer[100];
	sprintf(buffer, path, "config.ini");

	level = GetPrivateProfileIntA("Fight", "Level", 0, buffer);
	
	//加载Shellcode代码二进制文件到内存中的指定地址
	
	
	

	pPlayerHandle=(UINT)ReadCodeFile("1.CEM", NULL);
	//ReadCodeFile("1.CEM", (char *)address);

	//stdef溢出阻止代码
	//恢复ESP
	UINT address = (UINT)ReadCodeFile("forStdef3.CEM", (char *)0x004BE700);
	//把0x004be600写为0047eb31,恢复ESP
	address = (UINT)ReadCodeFile("forStdef4.CEM", (char *)0x004BE800);
	//def中stdef溢出阻止代码 
	address = (UINT)ReadCodeFile("forStdef8.CEM", (char *)0x004BE500);
	//胜负锁定修改代码
	address = (UINT)ReadCodeFile("victory.CEM", (char *)0x004BE900);

	//控制器回调代码
	address = (UINT)ReadCodeFile("contrl.CEM", NULL);
	switchJmp2(hmodule, "checkController", 0x004BEA08, 0x0046E854, address);
	//当身回调代码
	address = (UINT)ReadCodeFile("rever.CEM", NULL);
	switchJmp2(hmodule, "checkRever", 0x004BEA0C, 0x0046F528, address);
	//切换动画回调代码
	address = (UINT)ReadCodeFile("anim.CEM", NULL);
	switchJmp2(hmodule, "checkAnim", 0x004BEA10, 0x0046EA90, address);
	//控制器回调代码2
	address = (UINT)ReadCodeFile("contrl2.CEM", NULL);
	switchJmp2(hmodule, "checkController2", 0x004BEA14, 0x00470378, address);
	// dis溢出阻止
	address = (UINT)ReadCodeFile("dis1.CEM", (char *)0x004BF280);
	//控制器回调代码3
	address = (UINT)ReadCodeFile("contrl3.CEM", NULL);
	switchJmp2(hmodule, "checkController3", 0x004BEA18, 0x00471216, address);

	//溢出阻止1
	address = (UINT)ReadCodeFile("checkStateoverflow.CEM", NULL);
	switchJmp2(hmodule, "checkStateDefOverFlow", 0x004BF516, 0x0047EB24, address);


	//溢出阻止2
	address = (UINT)ReadCodeFile("checkStateoverflow2.CEM", NULL);
	switchJmp2(hmodule, "checkStateDefOverFlow2", 0x004BF520, 0x0047E9A7, address);
	
	modifyCode(hmodule, level);
	return level;
}



/*

人物状态保护
*/
void protect(UINT selfAdr) {



	UINT teamSide = ADRDATA(selfAdr + 0x0C);
	ADRDATA(0x4B699D) = teamSide == 2 ? 1 : 0;
	ADRDATA(0x4B6A1D) = teamSide == 2 ? 1 : 0; //禁用CTRL
	ADRDATA(selfAdr + 0x158) = 1;//防御P消去

	if (ADRDATA(VAR(PRIMARY_LEVEL_VAR, selfAdr)) >= 1 ) {

		ADRDATA(0x00496B8B) = (UINT)(&pFloatCallback);//%F禁止

		ADRDATA((selfAdr + 0xE24)) = 200;//Alive锁定
								
		ADRDATA(selfAdr + 0x1DC) = MAXINT;
		ADRDATA(selfAdr + 0x1E0) = MAXINT;//时停抗性
		ADRDATA(selfAdr + 0x15C) = 0; // pause解除
		ADRDATA(selfAdr + 0x1028) = 0;//damgae消除
		ADRDATA(selfAdr + 0x1074) = 0;//fall.damgae消除

	}
	
}

/*

保护修复DEF信息
*/
void protectDef() {


	if (pDefPath == NULL || pChaosorDefPath==NULL) {
		//读取初始信息
				
		UINT defStartAdr = ADRDATA(mainEntryPoint + 0xCD0);//def包起始地址

		UINT pCount = ADRDATA(mainEntryPoint + 0xCD4);//人物数量

		for (size_t i = 1; i <= pCount; i++)
		{

			UINT defPath = (defStartAdr - 0xA1E + 0xE30 * i);
			UINT deffilePath= defPath - 0x206;


			UINT defPlayer = NULL;
			char buffer[50];
			char buffer2[50];
			if (ADRDATA(defPath - 0x40A) > VALID_ADDRESS)
				defPlayer = ADRDATA(defPath - 0x40A);
					
			sprintf(buffer, configName, "/");
			sprintf(buffer2, configName, "\\");
			if (strcmp((char*)defPath, buffer) == 0)
			{
				version = 1;

			}
			else if (strcmp((char*)defPath, buffer2) == 0)
			{
				version = 2;
			}
			
						
			if (version!=0)
			{

				if (pDefPath == NULL) {
					pDefPath = defPath; //def包路径
					pDeffilePath = deffilePath; //def包文件名



				}
				if (defPlayer != NULL && pDef == NULL)
				{

					pDef = defPlayer; //人物信息地址
					pIndex = i;

				}

			}			
			else if(strcmp((char*)deffilePath, "chaosor.def") == 0)
			{
				//对策：混沌蛟，statedef防御代码会造成混沌蛟解析异常，此对策仅为了防止报错
				if(pChaosorDefPath==NULL) pChaosorDefPath = defPath;
					
				memset(buffer, 0, sizeof(buffer));
				sprintf(buffer, configName, "/st/");
				strcpy((char*)defPath, buffer);
				
				//strcpy((char*)defPath, "Scathacha_A/St/");
				strcpy((char*)deffilePath, "Enemy.def");
							
			}

		}

	}
	else if(pDefPath != NULL)
	{
				
		
		char buffer[50];
		if (version == 1)
		{
			sprintf(buffer, configName, "/");

		}
		else
		{
			sprintf(buffer, configName, "\\");
		}
		
	
	
		//修复 def路径
		if (level >= 2)
		{
			if (strcmp((char*)pDefPath, buffer) != 0) {

				strcpy((char*)pDefPath, buffer);

			}
			//修复 def文件名 
			memset(buffer, 0, sizeof(buffer));
			sprintf(buffer, configName, ".def");

			if (strcmp((char*)pDeffilePath, buffer) != 0) {

				strcpy((char*)pDeffilePath, buffer);

			}
			

		}
		
		
	}
}

UINT getDefPath(size_t index) {

	UINT defStartAdr = ADRDATA(mainEntryPoint + 0xCD0);//def包起始地址
	return (defStartAdr - 0xA1E + 0xE30 * index);


}

UINT getDef(size_t index) {
	if (index != -1)
	{
		UINT defStartAdr = ADRDATA(mainEntryPoint + 0xCD0);//def包起始地址
		UINT defPath = (defStartAdr - 0xA1E + 0xE30 * index);
		return ADRDATA(defPath - 0x40A);
	}
	else
	{

		return NULL;
	}

	
}
/*

保护修复DEF信息
*/
void protectDef2() {


	if (pIndex == -1 || pChaosorIndex == -1) {
		//读取初始信息


		UINT pCount = ADRDATA(mainEntryPoint + 0xCD4);//人物数量

		for (size_t i = 1; i <= pCount; i++)
		{

			

			UINT defPath = getDefPath(i);
			UINT deffilePath = defPath - 0x206;


			UINT defPlayer = NULL;
			char buffer[50];
			char buffer2[50];
			if (ADRDATA(defPath - 0x40A) > VALID_ADDRESS)
				defPlayer = ADRDATA(defPath - 0x40A);

			sprintf(buffer, configName, "/");
			sprintf(buffer2, configName, "\\");
			if (strcmp((char*)defPath, buffer) == 0)
			{
				version = 1;

			}
			else if (strcmp((char*)defPath, buffer2) == 0)
			{
				version = 2;
			}


			if (version != 0)
			{

			
				if (defPlayer != NULL && pIndex == -1)
				{

					 
					pIndex = i;//人物信息地址

				}

			}
			else if (strcmp((char*)deffilePath, "chaosor.def") == 0)
			{
				pChaosorIndex = i;
				//对策：混沌蛟，statedef防御代码会造成混沌蛟解析异常，此对策仅为了防止报错
				if (pChaosorDefPath == NULL) pChaosorDefPath = defPath;

				memset(buffer, 0, sizeof(buffer));
				sprintf(buffer, configName, "/st/");
				strcpy((char*)defPath, buffer);

				//strcpy((char*)defPath, "Scathacha_A/St/");
				strcpy((char*)deffilePath, "Enemy.def");

			}

		}

	}
	else if (pIndex != -1)
	{


		char buffer[50];
		if (version == 1)
		{
			sprintf(buffer, configName, "/");

		}
		else
		{
			sprintf(buffer, configName, "\\");
		}

		UINT defPath = getDefPath(pIndex);
		UINT deffilePath = defPath - 0x206;

		//修复 def路径
		if (level >= 2)
		{
			if (strcmp((char*)defPath, buffer) != 0) {

				strcpy((char*)defPath, buffer);

			}
			//修复 def文件名 
			memset(buffer, 0, sizeof(buffer));
			sprintf(buffer, configName, ".def");

			if (strcmp((char*)deffilePath, buffer) != 0) {

				strcpy((char*)deffilePath, buffer);

			}


		}


	}
}


/*

  试合前CNS指针保护恢复
*/
void protectCnsBeforeRound(UINT dAdr, UINT &cns1, UINT &cns3) {
	UINT def = getDef(pIndex);

	if (pCns1 == NULL || pCns1<VALID_ADDRESS) {
		//首次运行时备份cns地址的地址		

		
		if (def != NULL)
		{
			pCns1 = ADRDATA(def + 0x3C4);
			cns1 = pCns1;
		}
		else
		{
			return;
		}

	}
	if (pCns1>VALID_ADDRESS && (ADRDATA(def + 0x3C4) )!= pCns1) {
			
		
		ADRDATA(def + 0x3C4) = pCns1;//检查修复def的cns地址的地址	
		cns1 = pCns1;		
		cnsAtk = 1;
	}

	if (pCns2 == NULL || pCns2<VALID_ADDRESS) 
	{
		if (pCns1 != NULL)
		{
			pCns2 = ADRDATA(pCns1);//首次运行时备份cns的地址
			cns3 = pCns2;

		}	

	}
	if (pCns2>VALID_ADDRESS && cns3>VALID_ADDRESS && (ADRDATA(pCns1)) != pCns2)
	{
		
		ADRDATA(pCns1) = pCns2;//检查修复人物的cns的地址		
		cns3 = pCns2;
		cnsAtk = 1;
	}
}

/*
试合中CNS指针保护恢复
*/
void protectCnsInRound(UINT dAdr, UINT pAdr, UINT &cns1,UINT &cns2, UINT &cns3,UINT &cns4) {

	//if (pCns1 == NULL || pCns1<VALID_ADDRESS) {
	//	//首次运行时备份cns地址的地址
	//	pCns1 = cns1;

	//}
	//
	
	if (pCns1>VALID_ADDRESS && cns2 != pCns1) {


		ADRDATA(pAdr + 0xBE8) = pCns1;//检查修复人物的cns地址的地址
		cns2 = pCns1;
		cnsAtk = 1;
	}

	//if (pCns2 == NULL || pCns2<VALID_ADDRESS) {
	//	pCns2 = cns3;//首次运行时备份cns的地址


	//}

	if (pCns2>VALID_ADDRESS && cns2>VALID_ADDRESS && cns4 != pCns2)
	{
		ADRDATA(cns2) = pCns2;//检查修复人物的cns的地址
		
		cns4 = pCns2;
		cnsAtk = 1;
	}
	
}


/*
对方的Helper无效化
*/
void clearHelpers() {

	
	UINT selfAdr = NULL;
	for (size_t i = 5; i <= 60; i++)
	{
		
		UINT pAdr = ADRDATA(mainEntryPoint + i * 4 + 0xB750); //人物指针
		
		if (pAdr < VALID_ADDRESS) {
			continue;
		}
		UINT lpName = ADRDATA(pAdr);
		
		
		if (lpName!=NULL&&strcmp((char*)lpName, CHAR_NAME)!=0) {
			
		
			ADRDATA(pAdr + 0xE24) = 0;
			ADRDATA(pAdr + 416) = 100000;
			ADRDATA(pAdr + 440) = 100;
			if (pCns1!=NULL)
			{
				ADRDATA(pAdr + 0xBE8) = pCns1;
			}

		}
	 
	}

}

UINT findHelper(UINT parentAdr, UINT helperId) {


	UINT parentId = ADRDATA(parentAdr +4);
	for (size_t i = 5; i <= 60; i++)
	{
		UINT pAdr = ADRDATA(mainEntryPoint + i * 4 + 0xB750); //人物指针
		
		if (pAdr < VALID_ADDRESS) {
			continue;
		}
		if ((parentId == ADRDATA(pAdr + 9756)) && (helperId == ADRDATA(pAdr + 9752))) {

			return pAdr;
		}
		

	}
	return NULL;
	
}


UINT getTarget(UINT selfAdr) {

	UINT L = ADRDATA(selfAdr + 544);
	if (ADRDATA(L + 8) == 0)
	{
		return NULL;
	}
	UINT target = ADRDATA(L + 24);
	UINT base = ADRDATA(L + 20);
	return ADRDATA(base);
}

void setTarget(UINT selfAdr, UINT targetAdr) {

	UINT L = ADRDATA(selfAdr + 544);	
	ADRDATA(L + 8) =  1; //numtarget
	UINT pNo = ADRDATA(L + 24);
	ADRDATA(pNo ) =  1; //target序号
	UINT base = ADRDATA(L + 20);
	ADRDATA(base ) = targetAdr; //target对象地址
	

}

bool isHelperExist(UINT hAdr) {
			
	for (size_t i = 5; i <= 60; i++)
	{
		UINT pAdr = ADRDATA(mainEntryPoint + i * 4 + 0xB750); //人物指针
		UINT id = ADRDATA(hAdr + 4);
		ADRDATA(0x004bF300) = id;
		if (pAdr < VALID_ADDRESS)
		{
			continue;
		}
		
		if ((ADRDATA(hAdr + 344) == 1) && (ADRDATA(pAdr + 344) == 1) && (id == ADRDATA(pAdr + 4)))
		{
			
			return true;
		}
				
	}
	return false;
}

/*
隔离辅助:通过监控 var(ASSISTANT_VAR)的各个位的值来执行)
*/
void assiant(UINT selfAdr, UINT targetAdr) {

	UINT flag = ADRDATA(VAR(ASSISTANT_VAR, selfAdr));
	UINT teamSide = ADRDATA(selfAdr + 0x0C);
	UINT emySide = ADRDATA(targetAdr + 0x0C);
	UINT emyNo= ADRDATA(targetAdr + 8);

	//根据配置文件设置起始等级

	if (ADRDATA(VAR(PRIMARY_LEVEL_VAR, selfAdr)) < level ) {
		ADRDATA(VAR(PRIMARY_LEVEL_VAR, selfAdr)) = level;

	

	}
	
	

	//对方亲捏造判断----提高AI等级到1


	if (ADRDATA(targetAdr + 0x2620) > 9999)
	{

		if (ADRDATA(VAR(PRIMARY_LEVEL_VAR, selfAdr)) < 1)
		{

			ADRDATA(VAR(PRIMARY_LEVEL_VAR, selfAdr)) = 1;
			ADRDATA(targetAdr + 0x2620) = targetAdr;
			flag = flag | (1 << 8);;//关闭%N

		}
	


	}

	//checkHelper(targetAdr);
	//P消去检测
	if (ADRDATA(mainEntryPoint + 0xB950) == emySide && ADRDATA(mainEntryPoint + 0xB954) == emySide) {

		ADRDATA(VAR(PRIMARY_LEVEL_VAR, selfAdr)) = 1;
		flag = flag | (1 << 8);//关闭%N
		flag = flag | (1 << 4);//反向消去对方
		ADRDATA(VAR(ATTAACK_VAR, selfAdr)) = 4;//对方CNS指空
		

	}
	//对方修改胜场检测
	UINT roundNo = ADRDATA(mainEntryPoint + 0xBC04);
	UINT roundState= ADRDATA(mainEntryPoint + 0xBC30);
	UINT targetSide= ADRDATA(targetAdr + 0x0C);
	UINT targetWins = ADRDATA(mainEntryPoint + 0xBC08 + (targetSide - 1) * 4);

	if (roundState <= 2 && (targetWins > roundNo - 1)) {
		ADRDATA(mainEntryPoint + 0xBC08 + (targetSide - 1) * 4) = 0;
	
	}

	if (BIT_EXIST(flag, 0)) {
		//清除对方Helper
		
		clearHelpers();
		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 0);


	}
	if (BIT_EXIST(flag, 1)) {
	
		//noko解除
		ADR_BYTE_DATA(0x00470450)= 0;
		ADR_BYTE_DATA(0x00470490) = 0;
		ADR_BYTE_DATA(0x004704D5) = 0;
		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 1);
		ADRDATA(targetAdr + 0xE18) = 0;
		ADRDATA(targetAdr + 0xE1C) = 0;

	}
	if (BIT_EXIST(flag, 2)) {

		//noko恢复

		ADR_BYTE_DATA(0x00470450) = 1;
		ADR_BYTE_DATA(0x00470490) = 1;
		ADR_BYTE_DATA(0x004704D5) = 1;

		//PBYTE ptr = (PBYTE)0x00470450;
		//*ptr = 1;

		//ADRDATA(0x004AE75A) = 0x6B;
		//ADRDATA(0x004AE75B) = 0x6F;
		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 2);

	}
	if (BIT_EXIST(flag, 3)) {

		//胜负修改
		UINT side = ADRDATA(selfAdr + 0x0C);
		ADRDATA(mainEntryPoint+0xBC08+(side-1)*4)= ADRDATA(mainEntryPoint + 0xBC08 + (side - 1) * 4)+1;
		ADRDATA(mainEntryPoint + 0xBC34) = side;
		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 3);
	}
	if (BIT_EXIST(flag, 4)) {
		//P消去
		UINT side = ADRDATA(selfAdr + 0x0C);
		ADRDATA(mainEntryPoint + 0xB950) = side;
		ADRDATA(mainEntryPoint + 0xB954) = side;

		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 4);

	}
	if (BIT_EXIST(flag, 5)) {

		//按Enter键防止卡R3R4
		ADRDATA(0x004B5948)=0;
		ADRDATA(0x004B594C) = 0;//关闭前一帧的输出, 开启当前帧的输出
		ADRDATA(0x004B5964) = 1;//键盘可用

		ADRDATA(0x004B5548) = 0x39;//按下空格键，强制跳过R3,R4
		
		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 5);
	}
	
	if (BIT_EXIST(flag, 6)) {

		//时停抗性
		
		ADRDATA(selfAdr + 476) = 2147483647;
		ADRDATA(selfAdr + 480) = 2147483647;

		//ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 6);
		
	}
	if (BIT_EXIST(flag, 7)) {

		//消除对方HitpauseTime
		ADRDATA(targetAdr+0xE18) = 0;
		ADRDATA(targetAdr+0xE1C) = 0;

		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 7);

	}
	if (BIT_EXIST(flag, 8)) {

		//%n无效化
		ADRDATA(0x00496CB6) = 0x45C7C989;

		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 8);

	}
	if (BIT_EXIST(flag, 9)) {

		//%n可用
		ADRDATA(0x00496CB6) = 0x45C70889;

		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 9);

	}
	if (BIT_EXIST(flag, 10)) {

		//跳开幕
		ADRDATA(mainEntryPoint + 0xBC30) = 2;

		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 10);
		

	}
	if (BIT_EXIST(flag, 11)) {

		//Alive恢复
		ADRDATA((selfAdr + 0xE24)) = 200;


		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 11);


	}
	if (BIT_EXIST(flag, 12)) {

		// P数提升
		UINT plano = ADRDATA((selfAdr + 0x13C4));
		if (plano <= 3)
		{
			ADRDATA((selfAdr + 0x13C4)) = 6;
		}
		if (plano > 3 && plano <= 6)
		{
			ADRDATA((selfAdr + 0x13C4)) = 9;
		}
		if (plano > 6 && plano <= 9)
		{
			ADRDATA((selfAdr + 0x13C4)) = 11;
		}
		if (plano > 9 && plano <= 11)
		{
			ADRDATA((selfAdr + 0x13C4)) = 12;
		}
		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 12);
	}
	if (BIT_EXIST(flag, 13)) {
		//对方降为1p
		ADRDATA(targetAdr + 0x13C4) = 1;
		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 13);
	}
	if (BIT_EXIST(flag, 14)) {

		//对方状态弄

		//DEBUG2("状态弄!");

		ADRDATA((targetAdr + 0xBF4)) = ADRDATA(VAR(TARGET_STATUS_VAR, selfAdr));

		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 14);


	}
	if (BIT_EXIST(flag, 15)) {
		//消除 时停
		ADRDATA(mainEntryPoint + 48084) = 0;
		ADRDATA(mainEntryPoint + 48120) = 0;
		ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = clrbit(flag, 15);

	}

	if (BIT_EXIST(flag, 16)) {

		//helperTarget获取

		UINT helperId = ADRDATA(VAR(TARGET_HELPER_VAR, selfAdr));
	
		UINT adr = findHelper(selfAdr, helperId);
		if (adr != NULL)
		{
			setTarget(adr, targetAdr);

		}
		

	}

	if (BIT_EXIST(flag, 17))
	{
		//本体Target获取

		setTarget(selfAdr, targetAdr);


	}

	if (BIT_EXIST(flag, 18))
	{
		//Alive触发器强制不为0
			
		ADR_BYTE_DATA(0x0047B5EA) = 0xC4;
		ADR_BYTE_DATA(0x0047B5EB) = 0x13;
	}
	if (BIT_EXIST(flag, 19))
	{
		//Alive触发器恢复

		ADR_BYTE_DATA(0x0047B5EA) = 0x24;
		ADR_BYTE_DATA(0x0047B5EB) = 0x0E;
	}

	

	//ADRDATA(VAR(ASSISTANT_VAR, selfAdr)) = 0;
}

/*
	隔离即死攻击:通过监控 var(ATTAACK_VAR)的值来执行)
*/
void attack(UINT selfAdr, UINT targetAdr) {

	UINT flag = *((PUINT)VAR(ATTAACK_VAR, selfAdr));
	UINT no = ADRDATA((targetAdr + 0x08));
	UINT life = ADRDATA((targetAdr + 0x160));
	UINT lifeMax= ADRDATA((targetAdr + 0x164));
	UINT var = 0;
	switch (flag)
	{
		
	case 1://削血
		var= lifeMax*0.001;
		if (var <= 0)
			var = 1;
		if (var <= life)
		{
			ADRDATA((targetAdr + 0x160)) = life - var;
		}
		else
		{
			ADRDATA((targetAdr + 0x160)) = 0;
		}
		
		ADRDATA(VAR(TARGET_LIFE_VAR, selfAdr)) = 0;
		break;
	case 2:
		//生命值归0
		
		ADRDATA((targetAdr + 0x160)) = 0;
		
		
		break;
	case 3://即死
		ADRDATA((targetAdr + 0xE24)) = 0;
		break;
	case 4://即死+CNS修改
		MODIFYCNS(selfAdr, targetAdr);
		//*((PUINT)(*((PUINT)(targetAdr + 0xBE8)))) = *((PUINT)(*((PUINT)(selfAdr + 0xBE8))));
		ADRDATA((targetAdr + 0xE24)) = 0;
		break;

	
	}
	ADRDATA(VAR(ATTAACK_VAR, selfAdr)) = 0;


}
/*

人物名字修复
*/
void WINAPI protectName() {

	if (pDef != NULL) {

		UINT lpName = pDef;

		if (strcmp((PCHAR)lpName, CHAR_NAME) != NULL) {
			
			DEBUG2((LPCSTR)lpName);
			strcpy((PCHAR)lpName, CHAR_NAME);
			if(myAddr>VALID_ADDRESS)
				ADRDATA(VAR(PRIMARY_LEVEL_VAR, myAddr)) = 2;


		}
		lpName = pDef + 0x30;
		if (strcmp((PCHAR)lpName, CHAR_NAME) != NULL) {
			DEBUG2((LPCSTR)lpName);
			strcpy((PCHAR)lpName, CHAR_NAME);
			if (myAddr>VALID_ADDRESS)
				ADRDATA(VAR(PRIMARY_LEVEL_VAR, myAddr)) = 2;


		}

	}

}


void WINAPI protectName2() {

	if (pIndex != -1) {

		UINT defPath = getDefPath(pIndex);
		UINT defPlayer = ADRDATA(defPath - 0x40A);
		if (defPlayer > VALID_ADDRESS)
		{

			UINT lpName = defPlayer;
			if (strcmp((PCHAR)lpName, CHAR_NAME) != NULL) 
			{
				
				strcpy((PCHAR)lpName, CHAR_NAME);
				if (myAddr>VALID_ADDRESS)
					ADRDATA(VAR(PRIMARY_LEVEL_VAR, myAddr)) = 2;


			}
			lpName = defPlayer + 0x30;
			if (strcmp((PCHAR)lpName, CHAR_NAME) != NULL) 
			{
			
				strcpy((PCHAR)lpName, CHAR_NAME);
				if (myAddr>VALID_ADDRESS)
					ADRDATA(VAR(PRIMARY_LEVEL_VAR, myAddr)) = 2;


			}
		}
		
			

		

	}

}

//不是自己对战时恢复一些状态防止异常
void restore() {
	isExist = 0;
	myAddr = NULL;
	ADRDATA(0x004ba000) = 0;
	if (ADR_BYTE_DATA(0x00470450)== 0) {
		// noko允许恢复
		ADR_BYTE_DATA(0x00470450) = 1;
		ADR_BYTE_DATA(0x00470490) = 1;
		ADR_BYTE_DATA(0x004704D5) = 1;

			//Alive触发器恢复

		//ADR_BYTE_DATA(0x0047B5EA) = 0x24;
		//ADR_BYTE_DATA(0x0047B5EB) = 0x0E;
	}
	
}

/*

每帧自动运行的代码，进行隔离攻击与防御的入口
*/
void WINAPI playerHandle() {
	
	
	mainEntryPoint = ADRDATA(0x004b5b4c);	
	
	if (mainEntryPoint< VALID_ADDRESS) return;

	
	UINT selfAddress = NULL;
	int pCount = 0;

	UINT otherAdrs[3] = {NULL,NULL,NULL};
	UINT otherCns[3] = { NULL,NULL,NULL };
	int varAddress = 0xE40;
	protectDef2(); //def文件信息修复
	
	protectName2(); //人物名字修复
	for (size_t i = 1; i <= 4; i++)
	{
		
		UINT roundState =ADRDATA(mainEntryPoint + 0xBC30);
		if (roundState == 4)
		{
			cnsAtk = 0;

		}

		//protectDef(); //def文件信息修复
		UINT def = def = getDef(pIndex);//自己的def指针
		UINT dAdr = ADRDATA((mainEntryPoint + i * 4 + 0xB650)); //def人物指针
		//DEBUG2("获取def人物指针");
		if (def < VALID_ADDRESS || dAdr< VALID_ADDRESS) {
			continue;
		}

				
		//
		UINT cns1 = NULL;
		UINT cns3 = NULL;
		
		cns1 = ADRDATA((dAdr + 0x3C4));    //def中的CNS地址的地址
		
		
		if (cns1 < VALID_ADDRESS) continue;
		cns3 = ADRDATA(cns1); //def中的CNS地址

		protectCnsBeforeRound(dAdr, cns1, cns3); //试合前CNS保护

	
		UINT pAdr = ADRDATA((mainEntryPoint + i * 4 + 0xB750)); //人物指针
		if (pAdr < VALID_ADDRESS) {
			continue;
		}
			
		UINT cns2 = ADRDATA((pAdr + 0xBE8));//人物的cns地址的地址
		
		UINT cns4 = NULL;		
		
		if (cns2 < VALID_ADDRESS) continue;
		cns4 = ADRDATA(cns2);//人物的cns地址			
		
		if (def == dAdr) {			
			
			selfAddress = pAdr;
			ADRDATA(0x004ba000) = selfAddress;
			
				
			protect(pAdr);
			protectCnsInRound(dAdr, pAdr, cns1, cns2, cns3, cns4);//试合中CNS保护
			

		}
		else
		{

			otherAdrs[pCount] = pAdr;
			otherCns[pCount] = cns2;
			pCount++;
			if (cnsAtk == 1)
			{
			
				if (pAdr>VALID_ADDRESS && pCns1>VALID_ADDRESS)
					ADRDATA(cns2) = pCns2;//对方CNS修改

				ADRDATA((pAdr + 0xE24)) = 0;//对方死亡
				if(selfAddress>VALID_ADDRESS&&VAR(PRIMARY_LEVEL_VAR, selfAddress)<2)
					ADRDATA(VAR(PRIMARY_LEVEL_VAR, selfAddress))= 2;//检测到对方CNS指空时,AI等级提到最高
				
				cnsAtk = 0;
			}

		}
		
		
	}

	if (selfAddress != NULL) 
	{
		myAddr = selfAddress;
		ADRDATA(VAR(SWITCH_VAR, myAddr)) = 1;
		isExist = 1;
		
		for (int j = 0; j < pCount; j++)
		{		
				
		
			assiant(selfAddress, otherAdrs[j]);
			attack(selfAddress, otherAdrs[j]);

		}
		
	}
	else
	{
		restore();
		
	}

}

DWORD WINAPI ThreadProc(LPVOID lpParam) {

	
	playerHandle();
	return 0;


}


