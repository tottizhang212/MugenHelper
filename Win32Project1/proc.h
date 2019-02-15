#pragma once

#include "stdafx.h"

/*
---------------变量索引定义，这几个变量号为隔离专用，你可以根据自己的情况修改
*/
const UINT SWITCH_VAR = 2;//隔离标志
const UINT PRIMARY_LEVEL_VAR = 18; //基本隔离等级
const UINT TARGET_HELPER_VAR = 25;//记录永续Helper的ID
const UINT ATTAACK_VAR = 22;  //隔离攻击用控制变量
const UINT ASSISTANT_VAR = 39; //隔离辅助用控制变量
const UINT CONTROLER_VAR = 31; //控制器干涉用控制变量
const UINT TARGET_STATUS_VAR = 43;//记录控制对方状态号
const UINT TARGET_ANIM_NO_VAR = 14;//记录控制对方动画号
const UINT TARGET_LIFE_VAR = 26;//记录控制对方生命值量

//----------------------------------------------------------------------------------
extern const  char* path ;
extern const char* configName ;

typedef void(WINAPI *pFunc)(DWORD, DWORD);
 UINT WINAPI loadCodes(HMODULE hmodule);
 void WINAPI playerHandle();
 void log( char* info);