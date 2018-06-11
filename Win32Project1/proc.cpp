// Win32Project1.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <stdlib.h>  
#include <assert.h>
#include <time.h>
#include "proc.h"
#define VALID_ADDRESS 0x004B404A 
#define VAR(index,address) (address+0xE40+index * 4)
#define MODIFYCNS(selfAdR,targetAdR) *((PUINT)(*((PUINT)(targetAdr + 0xBE8)))) = *((PUINT)(*((PUINT)(selfAdr + 0xBE8))))
#define ADRDATA(address) *((PUINT)(address))
#define BIT_EXIST(data,byte)( ((data>>byte) & 1)>0 )
#define CHAR_NAME "Scathacha"
#define DEBUG(info) MessageBox(NULL, TEXT(info), TEXT(info), MB_OK)




void log(const char* info) {

	FILE *fpWrite = fopen("chars\\Scathacha_A\\St\\debug.log", "a+");
	time_t t = time(NULL);
	struct tm *  tm_local = localtime(&t);
	char str_f_t[100];
	strftime(str_f_t, sizeof(str_f_t), "%G-%m-%d %H:%M:%S", tm_local);
	fprintf(fpWrite, "%s:%s\n", str_f_t,info);
	fclose(fpWrite);
	
}

/*

从cem文件中读取 shellcode代码到内存的指定地址中
*/
char* WINAPI ReadCodeFile(char* file, char* startAddress) {

	FILE * pFile;
	long lSize;
	//char * buffer;
	size_t result;
	pFile = fopen(file, "rb");
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
UINT pFloatCallback = 0x00496651;//替代用%F入口跳转地址变量
void modifyCode(HMODULE hmodule) {

	
	
	//获取playerHandle的函数地址写入地址0x004BF300，让0x004b7000处的代码能够调用
	*((PUINT)0x004BF700)=(UINT) GetProcAddress(hmodule, "playerHandle");


	//修改主线程0x004829A3处的代码，使之跳转执行0x004b7000处代码，而0x004b7000处代码为执行下面的playerHandle函数
	PUINT ptr = (PUINT)0x004829A3;
	BOOL ret = VirtualProtect((LPVOID)0x004829A3, 13, 0x40, (PDWORD)0x004BE200);
	*ptr = 0x4B7000B8;
	ptr++;
	*ptr = 0xC3E0FF00;
	

	// %n无效化---将0x00496CB6处的 mov [eax],ecx改为 mov ecx,ecx,让写入内存无效！
	 ret = VirtualProtect((LPVOID)0x00496CB6, 8, 0x40, (PDWORD)0x004BE200);
	//ADRDATA(0x00496CB6) = 0x45C7C989;
	 //ADRDATA(0x00496CB6) = 0x45C70889;
	//%F无效化-----将 call [0x0048e848] 改为 call pFloatCallback的地址，对方再修改0x0048e848就没有作用了!
	ret = VirtualProtect((LPVOID)0x00496B8B, 8, 0x40, (PDWORD)0x004BE200);
	ADRDATA(0x00496B8B) = (UINT)(&pFloatCallback);

	//在statedef 处理函数跳转值前把0x004be600写为0047eb31
	ret = VirtualProtect((LPVOID)0x0047EB24, 8, 0x40, (PDWORD)0x004BE200);
	ReadCodeFile("chars\\Scathacha_A\\St\\forStdef1.CEM", (char *)0x0047EB24);
	//statedef溢出阻止：原理是在0x0047F184，Ret之前跳转至自己的代码，检查如果入口地址是0047eb31，就强制把esp恢复为0047eb31
	ret = VirtualProtect((LPVOID)0x0047F184, 8, 0x40, (PDWORD)0x004BE200);
	ReadCodeFile("chars\\Scathacha_A\\St\\forStdef2.CEM", (char *)0x0047F184);

}
void WINAPI loadCodes(HMODULE hmodule) {

	
	//加载Shellcode代码二进制文件到内存中的指定地址
	int address = 0x004b5b4c;
	
	address = 0x004B7000; //跳转到playerHandle
	ReadCodeFile("chars\\Scathacha_A\\St\\1.CEM", (char *)address);

	//stdef溢出阻止代码
	//恢复ESP
	ReadCodeFile("chars\\Scathacha_A\\St\\forStdef3.CEM", (char *)0x004BE700);
	//标志调用
	ReadCodeFile("chars\\Scathacha_A\\St\\forStdef4.CEM", (char *)0x004BE800);
	modifyCode(hmodule);
}


UINT mainEntryPoint = ADRDATA(0x004b5b4c);  //主程序入口地址
UINT pDef = NULL; //人物def入口地址
UINT pCns1 = NULL; //cns地址的地址备份
UINT pCns2 = NULL;//cns的地址备份
UINT pDefPath = NULL;//人物def地址
UINT pDeffilePath = NULL;//人物def地址
int cnsAtk = 0; //判断对方CNS攻击




/*

人物状态保护
*/
void protect(UINT selfAdr) {

	if (ADRDATA(VAR(18, selfAdr)) >= 6) {

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


	if (pDefPath == NULL) {
		//读取初始信息

		UINT defStartAdr = ADRDATA(mainEntryPoint + 0xCD0);//def包起始地址

		UINT pCount = ADRDATA(mainEntryPoint + 0xCD4);//人物数量

		for (size_t i = 1; i <= pCount; i++)
		{

			UINT defPath = (defStartAdr - 0xA1E + 0xE30 * i);


			if (strcmp((char*)defPath, "Scathacha_A/") == 0) {

				pDefPath = defPath; //def包路径
				pDeffilePath = pDefPath - 0x206; //def包文件名
				if (ADRDATA(pDefPath - 0x40A) > VALID_ADDRESS)
					pDef = ADRDATA(pDefPath - 0x40A); //人物信息地址
				break;

			 }

		}

	}
	else
	{

		if (ADRDATA(pDefPath - 0x40A) > VALID_ADDRESS)
		{
			pDef = ADRDATA(pDefPath - 0x40A);

		}

		//修复 def路径
		if (strcmp((char*)pDefPath, "Scathacha_A/") != 0) {

			strcpy((char*)pDefPath, "Scathacha_A/");


		}
		//修复 def文件名 
		if (strcmp((char*)pDeffilePath, "Scathacha_A.def") != 0) {


			strcpy((char*)pDeffilePath, "Scathacha_A.def");

		}


	}

	

}

/*

  试合前CNS指针保护恢复
*/
void protectCnsBeforeRound(UINT dAdr, UINT &cns1, UINT &cns3) {

	if (pCns1 == NULL || pCns1<VALID_ADDRESS) {
		//首次运行时备份cns地址的地址
		
		pCns1 = cns1;

	}
	if (pCns1>VALID_ADDRESS && cns1 != pCns1) {
		ADRDATA(dAdr + 0x3C4) = pCns1;//检查修复def的cns地址的地址
	
		cns1 = pCns1;
		
		cnsAtk = 1;
	}

	if (pCns2 == NULL || pCns2<VALID_ADDRESS) {
	
		pCns2 = cns3;//首次运行时备份cns的地址


	}
	if (pCns2>VALID_ADDRESS && cns3>VALID_ADDRESS && cns3 != pCns2)
	{
		ADRDATA(cns1) = pCns2;//检查修复人物的cns的地址
		
		
		cns3 = pCns2;
		cnsAtk = 1;
	}
}

/*
试合中CNS指针保护恢复
*/
void protectCnsInRound(UINT dAdr, UINT pAdr, UINT &cns1,UINT &cns2, UINT &cns3,UINT &cns4) {

	if (pCns1 == NULL || pCns1<VALID_ADDRESS) {
		//首次运行时备份cns地址的地址
		pCns1 = cns1;

	}
	if (pCns1>VALID_ADDRESS && cns1 != pCns1) {
		ADRDATA(dAdr + 0x3C4) = pCns1;//检查修复def的cns地址的地址
		
		cns1 = pCns1;
		
		cnsAtk = 1;
	}
	if (pCns1>VALID_ADDRESS && cns2 != pCns1) {

		ADRDATA(pAdr + 0xBE8) = pCns1;//检查修复人物的cns地址的地址
	
		cnsAtk = 1;
	}

	if (pCns2 == NULL || pCns2<VALID_ADDRESS) {
		pCns2 = cns3;//首次运行时备份cns的地址


	}

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
			
			if (pCns1!=NULL)
			{
				ADRDATA(pAdr + 0xBE8) = pCns1;
			}

		}
	 
	}

}
/*
隔离辅助:通过监控 var(39)的各个位的值来执行)
*/
void assiant(UINT selfAdr, UINT targetAdr) {


	//对方亲捏造判断----提高AI等级到6
	if (ADRDATA(VAR(18, selfAdr)) < 6)
	{
		if (ADRDATA(targetAdr + 0x17E0) > VALID_ADDRESS) 
		{
			ADRDATA(VAR(18, selfAdr)) = 6;
		}
	}
	

	UINT flag = *((PUINT)VAR(39, selfAdr));
	if (BIT_EXIST(flag, 0)) {
		//清除对方Helper
		
		clearHelpers();


	}
	if (BIT_EXIST(flag, 1)) {

		//noko解除
		ADRDATA(mainEntryPoint+0xBB79) = 0;
		ADRDATA(0x004AE75A)=0x62;
		ADRDATA(0x004AE75B) = 0x67;

	}
	if (BIT_EXIST(flag, 2)) {

		//noko恢复
		ADRDATA(0x004AE75A) = 0x6B;
		ADRDATA(0x004AE75B) = 0x6F;

	}
	if (BIT_EXIST(flag, 3)) {

		//胜负修改
		UINT side = ADRDATA(selfAdr + 0x0C);
		ADRDATA(mainEntryPoint+0xBC08+(side-1)*4)= ADRDATA(mainEntryPoint + 0xBC08 + (side - 1) * 4)+1;
		
	}
	if (BIT_EXIST(flag, 4)) {
		//P消去
		UINT side = ADRDATA(selfAdr + 0x0C);
		ADRDATA(mainEntryPoint + 0xB950) = side;
		ADRDATA(mainEntryPoint + 0xB954) = side;

	}
	if (BIT_EXIST(flag, 5)) {

		//按Enter键防止卡R3R4
		ADRDATA(0x004B5948)=0;
		ADRDATA(0x004B594C) = 0;//关闭前一帧的输出, 开启当前帧的输出
		ADRDATA(0x004B5964) = 1;//键盘可用

		ADRDATA(0x004B5548) = 0x39;//按下空格键，强制跳过R3,R4

	}
	if (BIT_EXIST(flag, 6)) {

		//时止解除
		ADRDATA(mainEntryPoint + 0xBBD4) = 0;
		ADRDATA(mainEntryPoint + 0xBBF8) = 0;
		
	}
	if (BIT_EXIST(flag, 7)) {

		//消除对方HitpauseTime
		ADRDATA(targetAdr+0xE18) = 0;
		ADRDATA(targetAdr+0xE1C) = 0;

	}
	if (BIT_EXIST(flag, 8)) {

		//%n无效化
		ADRDATA(0x00496CB6) = 0x45C7C989;

	}
	if (BIT_EXIST(flag, 9)) {

		//%n可用
		ADRDATA(0x00496CB6) = 0x45C70889;

	}

	ADRDATA(VAR(39, selfAdr)) = 0;
}

/*
	隔离即死攻击:通过监控 var(22)的值来执行)
*/
void attack(UINT selfAdr, UINT targetAdr) {

	UINT flag = *((PUINT)VAR(22, selfAdr));

	switch (flag)
	{
	case 1://削血
		ADRDATA((targetAdr + 0x160)) = ADRDATA((targetAdr + 0x160)) - 20;
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
	ADRDATA(VAR(22, selfAdr)) = 0;


}
/*

人物名字修复
*/
void WINAPI protectName() {

	if (pDef != NULL) {

		UINT lpName = pDef;

		if (strcmp((PCHAR)lpName, CHAR_NAME) != NULL) {
			strcpy((PCHAR)lpName, CHAR_NAME);


		}
		lpName = pDef + 0x30;
		if (strcmp((PCHAR)lpName, CHAR_NAME) != NULL) {
			strcpy((PCHAR)lpName, CHAR_NAME);


		}

	}

}

/*

每帧自动运行的代码，进行隔离攻击与防御的入口
*/
void WINAPI playerHandle() {


	bool hasSelected = false;
	UINT selfAddress = NULL;
	int pCount = 0;

	UINT otherAdrs[3] = {NULL,NULL,NULL};
	UINT otherCns[3] = { NULL,NULL,NULL };
	int varAddress = 0xE40;
	for (size_t i = 1; i <= 4; i++)
	{
		if (ADRDATA((mainEntryPoint + 0xBC30)) == 4)
		{
			cnsAtk = 0;

		}

		protectDef(); //def文件信息修复

		UINT dAdr = ADRDATA((mainEntryPoint + i * 4 + 0xB650)); //def人物指针
	
		if (pDef < VALID_ADDRESS) {
			continue;
		}
		UINT lpName = dAdr ;


		protectName(); //人物名字修复
		UINT cns3 = NULL;
		UINT cns1 = ADRDATA((pDef + 0x3C4));    //def中的CNS地址的地址
		if (cns1 < VALID_ADDRESS) continue;
		cns3 = ADRDATA(cns1); //def中的CNS地址
		
		protectCnsBeforeRound(pDef, cns1, cns3); //试合前CNS保护


		UINT pAdr = ADRDATA((mainEntryPoint + i * 4 + 0xB750)); //人物指针
		if (pAdr < VALID_ADDRESS) {
			continue;
		}
			
		UINT cns2 = ADRDATA((pAdr + 0xBE8));//人物的cns地址的地址
		
		UINT cns4 = NULL;
	
		
		if (cns2 < VALID_ADDRESS) continue;
		cns4 = ADRDATA(cns2);//人物的cns地址
		
		
				
		if (pDef == dAdr) {
			
			selfAddress = pAdr;
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
				if(selfAddress>VALID_ADDRESS&&VAR(18, selfAddress>VALID_ADDRESS))
					ADRDATA(VAR(18, selfAddress))= 12;//AId等级提到最高
				
				cnsAtk = 0;
			}

		}
		
		
	}

	if (selfAddress != NULL) {


		for (int j = 0; j < pCount; j++)
		{
			
			UINT adr = VAR(j + 12, selfAddress);
						
			
			if (ADRDATA((adr)) < VALID_ADDRESS) {

				//对方的人物地址设置到var(12)-var(14)
				ADRDATA((adr)) = otherAdrs[j];
			}
			adr = VAR(j + 41, selfAddress);
			
			if (ADRDATA((adr)) < VALID_ADDRESS) {

				//对方的CNS地址设置到var(41)-var(43)
				ADRDATA((adr)) = otherCns[j];
			}
			assiant(selfAddress, otherAdrs[j]);
			attack(selfAddress, otherAdrs[j]);

		}
		
	}

}

DWORD WINAPI ThreadProc(LPVOID lpParam) {



	playerHandle();

	return 0;


}


