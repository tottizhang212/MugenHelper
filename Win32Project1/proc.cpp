// Win32Project1.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include <stdlib.h>  
#include <assert.h> 
#include "proc.h"
#define VALID_ADDRESS 0x004B404A 
#define VAR(index,address) (address+0xE40+index * 4)
#define MODIFYCNS(selfAdR,targetAdR) *((PUINT)(*((PUINT)(targetAdr + 0xBE8)))) = *((PUINT)(*((PUINT)(selfAdr + 0xBE8))))
#define ADRDATA(address) *((PUINT)(address))
#define BIT_EXIST(data,byte)( ((data>>byte) & 1)>0 )



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
	assert(ret);

	// %n无效化---将0x00496CB6处的 mov [eax],ecx改为 mov ecx,ecx,让写入内存无效！
	 ret = VirtualProtect((LPVOID)0x00496CB6, 8, 0x40, (PDWORD)0x004BE200);
	//ADRDATA(0x00496CB6) = 0x45C7C989;
	 //ADRDATA(0x00496CB6) = 0x45C70889;
	//%F无效化-----将 call [0x0048e848] 改为 call pFloatCallback的地址，对方再修改0x0048e848就没有作用了!
	ret = VirtualProtect((LPVOID)0x00496B8B, 8, 0x40, (PDWORD)0x004BE200);
	ADRDATA(0x00496B8B) = (UINT)(&pFloatCallback);

}
void WINAPI loadCodes(HMODULE hmodule) {


	//加载Shellcode代码二进制文件到内存中的指定地址
	int address = 0x004b5b4c;

	address = 0x004B7000; //跳转到playerHandle
	ReadCodeFile("chars\\Scathacha_A\\St\\1.CEM", (char *)address);
	/*
	address = 0x004B8000;
	ReadCodeFile("chars\\Scathacha_A\\St\\2.CEM", (char *)address);
	address = 0x004BE700;
	ReadCodeFile("chars\\Scathacha_A\\St\\3.CEM", (char *)address);
	address = 0x004BE800;
	ReadCodeFile("chars\\Scathacha_A\\St\\4.CEM", (char *)address);
	address = 0x004B4000;
	ReadCodeFile("chars\\Scathacha_A\\St\\5.CEM", (char *)address);
	
	address = 0x004B3000;
	ReadCodeFile("chars\\Scathacha_A\\St\\6.CEM", (char *)address);
	
	*/

	modifyCode(hmodule);
}


UINT mainEntryPoint = ADRDATA(0x004b5b4c);  //主程序入口地址
UINT pCns1 = NULL; //cns地址的地址备份
UINT pCns2 = NULL;//cns的地址备份
int cnsAtk = 0; //判断对方CNS攻击
/*
人物变量初始化
*/
void initial(UINT dAdr, UINT pAdr) {
	

	/*
	
	if (ADRDATA(VAR(2, pAdr)) < VALID_ADDRESS) {

		//主程序地址设置到var(2)
		ADRDATA((VAR(2, pAdr))) = mainEntryPoint;
	}
	if (ADRDATA(VAR(11, pAdr)) < VALID_ADDRESS) {

		//自己人物地址设置到var(11)
		ADRDATA((VAR(11, pAdr))) = pAdr;
	}
	if (ADRDATA((VAR(21, pAdr))) < VALID_ADDRESS) {

		//自己CNS地址设置到var(21)
		ADRDATA((VAR(21, pAdr))) = ADRDATA((dAdr + 0x3C4));
	}
	
	
	*/
	

}
/*

人物状态保护
*/
void protect(UINT selfAdr) {

	if (ADRDATA(VAR(18, selfAdr)) >= 6) {

		ADRDATA((selfAdr + 0xE24)) = 200;//Alive锁定
									 //时停抗性+pause解除+damage消除+fall.damage消除

		ADRDATA(selfAdr + 0x1DC) = MAXINT;
		ADRDATA(selfAdr + 0x1EC) = MAXINT;//时停抗性
		ADRDATA(selfAdr + 0x15C) = 0; // pause解除
		ADRDATA(selfAdr + 0x1028) = 0;//damgae消除
		ADRDATA(selfAdr + 0x1074) = 0;//fall.damgae消除

	}
	
}

/*
检查恢复CNS
*/
void checkCns(UINT dAdr, UINT pAdr, UINT &cns1,UINT &cns2, UINT &cns3,UINT &cns4) {

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
	for (size_t i = 1; i <= 60; i++)
	{

		UINT dAdr = *((UINT *)(mainEntryPoint + i * 4 + 0xB650)); //def人物指针
		if (dAdr < VALID_ADDRESS) {
			continue;
		}
		UINT pAdr = *((UINT *)(mainEntryPoint + i * 4 + 0xB750)); //人物指针
		if (pAdr < VALID_ADDRESS) {
			continue;
		}
		UINT lpName = dAdr + 0x30;

		if (i <= 4) {

			if ( strcmp((PCHAR)lpName, "Scathacha") == NULL) {
				selfAdr = pAdr;
				i = 4;
				continue;

			}
			continue;
		}
				
		if (selfAdr != ADRDATA(pAdr + 0x2624)) {

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

		UINT dAdr = ADRDATA((mainEntryPoint + i * 4 + 0xB650)); //def人物指针
		if (dAdr < VALID_ADDRESS) {
			continue;
		}
		UINT pAdr = ADRDATA((mainEntryPoint + i * 4 + 0xB750)); //人物指针
		if (pAdr < VALID_ADDRESS) {
			continue;
		}
			
		
		UINT cns1 = ADRDATA((dAdr + 0x3C4));    //def中的CNS地址的地址
		UINT cns2 = ADRDATA((pAdr + 0xBE8));//人物的cns地址的地址
		UINT cns3 = NULL;
		UINT cns4 = NULL;

		if (cns1 < VALID_ADDRESS) continue;
		cns3 = ADRDATA(cns1); //def中的CNS地址
		if (cns2 < VALID_ADDRESS) continue;
		cns4 = ADRDATA(cns2);//人物的cns地址


		UINT lpName = dAdr + 0x30;
		
		if (strcmp((PCHAR)lpName, "Scathacha") == NULL) {

			selfAddress = pAdr;
			
			protect(pAdr);

			initial(dAdr, pAdr);

			checkCns(dAdr, pAdr, cns1, cns2, cns3, cns4);


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


DWORD WINAPI ThreadProc(LPVOID lpParam)
{

	

	UINT mainEntryPoint;
	UINT* ptr = (UINT*)0x004b5b4c;
	mainEntryPoint = *ptr;  //主程序入口地址
	UINT pCns1=NULL; //cns地址的地址备份
	UINT pCns2=NULL;//cns的地址备份
	
	while (true)
	{
		Sleep(1);
		int count = 0;
		int cnsAtk = 0; //判断对方CNS攻击
		bool hasSelected = false;
		for (size_t i = 1; i <= 4; i++)
		{
			
			UINT dAdr = *((UINT *)(mainEntryPoint + i * 4 + 0xB650)); //def人物指针
			if (dAdr < VALID_ADDRESS) {
				continue;
			}
			UINT pAdr = *((UINT *)(mainEntryPoint + i * 4 + 0xB750)); //人物指针
			if (pAdr < VALID_ADDRESS) {
				continue;
			} 
					

			hasSelected = true;
			UINT cns1 = *((UINT *)(dAdr + 0x3C4));    //def中的CNS地址的地址
			UINT cns2 = *((UINT *)(pAdr + 0xBE8));//人物的cns地址的地址
			UINT cns3 = NULL;
			UINT cns4 = NULL;
						
			if (cns1 < VALID_ADDRESS) continue;
			cns3 = *((UINT*)cns1); //def中的CNS地址
			if (cns2 < VALID_ADDRESS) continue;
			cns4 = *((UINT*)cns2);//人物的cns地址
			
						
			UINT lpName = dAdr + 0x30;
			
		
			if (strcmp((char*)lpName, "Scathacha") == NULL) {

				*((UINT*)(pAdr + 0xE24)) = 200;//Alive锁定
							
				if (pCns1 == NULL || pCns1<0x004B404A) {
					//首次运行时备份cns地址的地址
					pCns1 = cns1;

				}
				if (pCns1>VALID_ADDRESS && cns1 != pCns1) {
					*((UINT*)(dAdr + 0x3C4)) = pCns1;//检查修复def的cns地址的地址
					cns1 = pCns1;
					cnsAtk = 1;
					
				} 
				if (pCns1>VALID_ADDRESS && cns2 != pCns1) {

					*((UINT*)(pAdr + 0xBE8)) = pCns1;//检查修复人物的cns地址的地址
					cns2 = pCns1;
					cnsAtk = 1;
				
				}
												
				if (pCns2 == NULL || pCns2<VALID_ADDRESS) {
					pCns2 = cns3;//首次运行时备份cns的地址

				}
						
				if (pCns2>VALID_ADDRESS && cns2>VALID_ADDRESS && cns4 != pCns2)
				{
					*((UINT*)cns2) = pCns2;//检查修复人物的cns的地址
					cns4 = pCns2;
					cnsAtk = 1;
				
				}
				

			}
			else
			{


				int roundState = *((UINT*)(mainEntryPoint + 0xBC30));
				if (roundState == 2 || roundState == 3) {

					if (cnsAtk == 1)
					{
						if (pAdr>VALID_ADDRESS && pCns1>VALID_ADDRESS)
							*((UINT*)(cns3)) = pCns2;//对方CNS修改

						*((UINT*)(pAdr + 0xE24)) = 0;//对方死亡
						
						cnsAtk = 0;
						
					}

				}
		

			}
		}
		if(!hasSelected)
			cnsAtk = 0;

		
	}
		
	return 0;
}


