//LnkTester.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <conio.h>
#include <Windows.h>
#include "winsock.h"
#include <IPHlpApi.h>
#include "stdio.h"
#include "CfgFileParms.h"
#include "function.h"
//#include <afxwin.h>
#pragma comment(lib,"Ws2_32.lib")
#pragma comment(lib,"Iphlpapi.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

//============重点来了================================================================================================
//------------重要的控制参数------------------------------------------------------------
//以下从配置文件ne.txt中读取的重要参数
int lowerMode[10]; //如果低层是物理层模拟软件，这个数组放置的是每个接口对应的数据格式——0为比特数组，1为字节数组
int lowerNumber;   //低层实体数量，比如网络层之下可能有多个链路层
int iWorkMode = 0; //本层实体工作模式
string strDevID;    //设备号，字符串形式，从1开始
string strLayer;    //层次名
string strEntity;   //实体号，字符串形式，从0开始，可以通过atoi函数变成整数在程序中使用
int iLayOut = 1;		//布局编号，即拓扑中的节点数量

//以下是一些重要的与通信有关的控制参数，但是也可以不用管
SOCKET sock;
struct sockaddr_in local_addr;      //本层实体地址
struct sockaddr_in upper_addr;      //上层实体地址，一般情况下，上层实体只有1个
struct sockaddr_in lower_addr[10];  //最多10个下层对象，数组下标就是下层实体的编号
sockaddr_in cmd_addr;         //统一管理平台地址
sockaddr_in oneTouch_addr;  //一键启动服务器地址
in_addr* localAddrList; //本地地址表
int localAddrNum;   //本地地址表大小

CCfgFileParms cfgParms;

//------------华丽的分割线，以下是定时器--------------------------------------------
//基于select的定时器，目的是把数据的收发和定时都统一到一个事件驱动框架下
//可以有多个定时器，本设计实现了一个基准定时器，为周期性10ms定时，也可以当作是一种心跳计时器
//其余的定时器可以在这个基础上完成，可行的方案存在多种
//看懂设计思路后，自行扩展以满足需要
//基准定时器一开启就会立即触发一次
struct threadTimer_t {
	int iType;  //为0表示周期性定时器，定时达到后，会自动启动下一次定时
	ULONG ulInterval;
	LARGE_INTEGER llStopTime;
}sBasicTimer;  //全局唯一的计时器，默认是每10毫秒触发一次，设计者可以在这个计时器的基础上实现自己的各种定时。
               //比如计数100次以后，就是1秒。针对不同的事件设置两个变量，一个用来表示是否开始计时，一个用来表示计数到多大
#define HELLO_INTVAL 2000000 //向oneTouch发送hello的时间间隔，微妙为单位，2秒
unsigned int iHelloCount = 0; //向oneTouch发送hello的计时器，2秒发送1次
//*************************************************
//名称：StartTimerOnce
//功能：把全局计时器改为1次性，本函调用的同时计时也开始，当定时到达时TimeOut函数将被调用
//输入：计时间隔时间，单位微秒，计时的起始就是本函数调用时。
//输出：直接改变全局计时器变量 sBasicTimer的内容
void StartTimerOnce(ULONG ulInterval)
{
	LARGE_INTEGER llFreq;

	sBasicTimer.iType = 1;
	sBasicTimer.ulInterval = ulInterval;
	QueryPerformanceFrequency(&llFreq);
	QueryPerformanceCounter(&sBasicTimer.llStopTime);
	sBasicTimer.llStopTime.QuadPart += llFreq.QuadPart * sBasicTimer.ulInterval / 1000000;
}
//*************************************************
//名称：StartTimerPeriodically
//功能：重设全局计时器的周期性触发的间隔时间，同时周期性计时器也开始工作，每次计时到达TimeOut函数被调用1次
//      周期性计时器可以将间隔设短一些，这样就可以在它的基础上实现更多的各种定时时间的定时器了
//      例程默认是启动周期性计时器机制
//输入：计时间隔时间，单位微秒，计时的起始就是本函数调用时。
//输出：直接改变全局计时器变量 sBasicTimer内容
void StartTimerPeriodically(ULONG ulInterval)
{
	LARGE_INTEGER llFreq;

	sBasicTimer.iType = 0;
	sBasicTimer.ulInterval = ulInterval;
	QueryPerformanceFrequency(&llFreq);
	QueryPerformanceCounter(&sBasicTimer.llStopTime);
	sBasicTimer.llStopTime.QuadPart += llFreq.QuadPart * sBasicTimer.ulInterval / 1000000;
}
//***************重要函数提醒******************************
//名称：SendtoUpper
//功能：向高层实体递交数据时，使用这个函数
//输入：U8 * buf,准备递交的数据， int len，数据长度，单位字节，int ifNo
//输出：函数返回值是发送的数据量
int SendtoUpper(U8* buf, int len)
{
	int sendlen;
	sendlen = sendto(sock, buf, len, 0, (sockaddr*) & (upper_addr), sizeof(sockaddr_in));
	return sendlen;
}
//***************重要函数提醒******************************
//名称：SendtoLower
//功能：向低层实体下发数据时，使用这个函数
//输入：U8 * buf,准备下发的数据， int len，数据长度，单位字节,int ifNo,发往的低层接口号
//输出：函数返回值是发送的数据量
int SendtoLower(U8* buf, int len,int ifNo)
{
	int sendlen;
	if (ifNo < 0 || ifNo >= lowerNumber)
		return 0;
	sendlen = sendto(sock, buf, len, 0, (sockaddr*) & (lower_addr[ifNo]), sizeof(sockaddr_in));
	return sendlen;
}
//***************重要函数提醒******************************
//名称：SendtoCommander
//功能：向统一管理平台发送状态数据时，使用这个函数
//输入：U8 * buf,准备下发的数据， int len，数据长度，单位字节
//输出：函数返回值是发送的数据量
int SendtoCommander(U8* buf, int len)
{
	int sendlen;
	sendlen = sendto(sock, buf, len, 0, (sockaddr*)&(cmd_addr), sizeof(sockaddr_in));
	return sendlen;
}

//------------华丽的分割线，以下是一些数据处理的工具函数，可以用，没必要改------------------------------
//*************************************************
//名称：ByteArrayToBitArray
//功能：将字节数组流放大为比特数组流
//输入： int iBitLen——位流长度, U8* byteA——被放大字节数组, int iByteLen——字节数组长度
//输出：函数返回值是转出来有多少位；
//      U8* bitA,比特数组，注意比特数组的空间（声明）大小至少应是字节数组的8倍
int ByteArrayToBitArray(U8* bitA, int iBitLen, U8* byteA, int iByteLen)
{
	int i;
	int len;

	len = min(iByteLen, iBitLen / 8);
	for (i = 0; i < len; i++) {
		//每次编码8位
		code(byteA[i], &(bitA[i * 8]), 8);
	}
	return len * 8;
}
//*************************************************
//名称：BitArrayToByteArray
//功能：将字节数组流放大为比特数组流
//输入：U8* bitA,比特数组，int iBitLen——位流长度,  int iByteLen——字节数组长度
//      注意比特数组的空间（声明）大小至少应是字节数组的8倍
//输出：返回值是转出来有多少个字节，如果位流长度不是8位整数倍，则最后1字节不满；
//      U8* byteA——缩小后的字节数组,，
int BitArrayToByteArray(U8* bitA, int iBitLen, U8* byteA, int iByteLen)
{
	int i;
	int len;
	int retLen;

	len = min(iByteLen * 8, iBitLen);
	if (iBitLen > iByteLen * 8) {
		//截断转换
		retLen = iByteLen;
	}
	else {
		if (iBitLen % 8 != 0)
			retLen = iBitLen / 8 + 1;
		else
			retLen = iBitLen / 8;
	}

	for (i = 0; i < len; i += 8) {
		byteA[i / 8] = (U8)decode(bitA + i, 8);
	}
	return retLen;
}
//*************************************************
//名称：print_data_bit
//功能：按比特流形式打印数据缓冲区内容
//输入：U8* A——比特数组, int length——位数, int iMode——原始数据格式，0为比特流数组，1为字节数组
//输出：直接屏幕打印
void print_data_bit(U8* A, int length, int iMode)
{
	int i, j;
	U8 B[8];
	int lineCount = 0;
	cout << endl << "数据的位流：" << endl;
	if (iMode == 0) {
		for (i = 0; i < length; i++) {
			lineCount++;
			if (A[i] == 0) {
				printf("0 ");
			}
			else {
				printf("1 ");
			}
			if (lineCount % 8 == 0) {
				printf(" ");
			}
			if (lineCount >= 40) {
				printf("\n");
				lineCount = 0;
			}
		}
	}
	else {
		for (i = 0; i < length; i++) {
			lineCount++;
			code(A[i], B, 8);
			for (j = 0; j < 8; j++) {
				if (B[j] == 0) {
					printf("0 ");
				}
				else {
					printf("1 ");
				}
				lineCount++;
			}
			printf(" ");
			if (lineCount >= 40) {
				printf("\n");
				lineCount = 0;
			}
		}
	}
	printf("\n");
}
//*************************************************
//名称：print_data_byte
//功能：按字节流数组形式打印数据缓冲区内容,同时打印字符和十六进制数两种格式
//输入：U8* A——比特数组, int length——位数, int iMode——原始数据格式，0为比特流数组，1为字节数组
//输出：直接屏幕打印
void print_data_byte(U8* A, int length, int iMode)
{
	int linecount = 0;
	int i;

	if (iMode == 0) {
		length = BitArrayToByteArray(A, length, A, length);
	}
	cout << endl << "数据的字符流及十六进制字节流:" << endl;
	for (i = 0; i < length; i++) {
		linecount++;
		printf("%c ", A[i]);
		if (linecount >= 40) {
			printf("\n");
			linecount = 0;
		}
	}
	printf("\n");
	linecount = 0;
	for (i = 0; i < length; i++) {
		linecount++;
		printf("%02x ", (unsigned char)A[i]);
		if (linecount >= 40) {
			printf("\n");
			linecount = 0;
		}
	}
	printf("\n");
}
//end=========重要的就这些，真正需要动手改的“只有”TimeOut，RecvFromUpper，RecvFromLower=========================

//------------华丽的分割线，以下到main以前，都不用管了----------------------------
void initTimer(int interval)
{
	sBasicTimer.iType = 0;
	sBasicTimer.ulInterval = interval;//10ms,单位是微秒，10ms相对误差较小，但是也挺耗费CPU
	QueryPerformanceCounter(&sBasicTimer.llStopTime);
}
//根据系统当前时间设置select函数要用的超时时间——to，每次在select前使用
void setSelectTimeOut(timeval* to, struct threadTimer_t* sT)
{
	LARGE_INTEGER llCurrentTime;
	LARGE_INTEGER llFreq;
	LONGLONG next;
	//取系统当前时间
	QueryPerformanceFrequency(&llFreq);
	QueryPerformanceCounter(&llCurrentTime);
	if (llCurrentTime.QuadPart >= sT->llStopTime.QuadPart) {
		to->tv_sec = 0;
		to->tv_usec = 0;
		//		sT->llStopTime.QuadPart += llFreq.QuadPart * sT->ulInterval / 1000000;
	}
	else {
		next = sT->llStopTime.QuadPart - llCurrentTime.QuadPart;
		next = next * 1000000 / llFreq.QuadPart;
		to->tv_sec = (long)(next / 1000000);
		to->tv_usec = long(next % 1000000);
	}

}
//根据系统当前时间判断定时器sT是否超时，可每次在select后使用，返回值true表示超时，false表示没有超时
bool isTimeOut(struct threadTimer_t* sT)
{
	LARGE_INTEGER llCurrentTime;
	LARGE_INTEGER llFreq;
	//取系统当前时间
	QueryPerformanceFrequency(&llFreq);
	QueryPerformanceCounter(&llCurrentTime);

	if (llCurrentTime.QuadPart >= sT->llStopTime.QuadPart) {
		if (sT->iType == 0) {
			//定时器是周期性的，重置定时器
			sT->llStopTime.QuadPart += llFreq.QuadPart * sT->ulInterval / 1000000;
		}
		return true;
	}
	else {
		return false;
	}
}
//名称：code
//功能：长整数x中的指定位数，放大到A[]这个比特数组中，建议按8的倍数做
//输入：x，被放大的整数，里面包含length长度的位数
//输出：A[],放大后的比特数组
void code(unsigned long x, U8 A[], int length)
{
	unsigned long test;
	int i;
	//高位在前
	test = 1;
	test = test << (length - 1);
	for (i = 0; i < length; i++) {
		if (test & x) {
			A[i] = 1;
		}
		else {
			A[i] = 0;
		}
		test = test >> 1; //本算法利用了移位操作和"与"计算，逐位测出x的每一位是0还是1.
	}
}
//名称：decode
//功能：把比特数组A[]里的各位（元素），缩小放回到一个整数中，长度是length位，建议按8的倍数做
//输入：比特数组A[],需要变化的位长
//输出：缩小后，还原的整数
unsigned long decode(U8 A[], int length)
{
	unsigned long x;
	int i;

	x = 0;
	for (i = 0; i < length; i++) {
		if (A[i] == 0) {
			x = x << 1;;
		}
		else {
			x = x << 1;
			x = x | 1;
		}
	}
	return x;
}

void SetColor(int ForgC)
{
	WORD wColor;
	//We will need this handle to get the current background attribute
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO csbi;

	//We use csbi for the wAttributes word.
	if (GetConsoleScreenBufferInfo(hStdOut, &csbi))
	{
		//Mask out all but the background attribute, and add in the forgournd color
		wColor = (csbi.wAttributes & 0xF0) + (ForgC & 0x0F);
		SetConsoleTextAttribute(hStdOut, wColor);
	}
}
//------------华丽的分割线，根据布局计算显示位置-----------------
//布局因子，以左上角位坐标原点
#define MAX_LAYOUTS	9 //最大支持9个节点的布局
struct Layout_t {
	float xRate;
	float yRate;
};
//按照习惯，没有0号节点，节点都从1开始编号，但是接口号等实体号是可以从0开始编号的
struct Layout_t gsLayout[MAX_LAYOUTS + 1][MAX_LAYOUTS + 1] =
{ {},{},
  {{0.0f,0.0f},{0.25f,0.50f},{0.75f,0.50f},},
  {{0.0f,0.0f},{0.25f,0.25f},{0.50f,0.55f},{0.75f,0.25f},},
  {{0.0f,0.0f},{0.25f,0.25f},{0.75f,0.25f},{0.75f,0.75f},{0.25f,0.75f},},
  {{0.0f,0.0f},{0.25f,0.25f},{0.75f,0.25f},{0.75f,0.75f},{0.25f,0.75f},{0.50f,0.50f},},
  {{0.0f,0.0f},{0.25f,0.25f},{0.50f,0.25f},{0.75f,0.25f},{0.75f,0.75f},{0.50f,0.75f},{0.25f,0.75f},},
  {{0.0f,0.0f},{0.25f,0.33f},{0.50f,0.25f},{0.75f,0.33f},{0.75f,0.66f},{0.50f,0.75f},{0.25f,0.66f},{0.50f,0.50f},},
  {{0.0f,0.0f},{0.17f,0.25f},{0.50f,0.25f},{0.83f,0.25f},{0.83f,0.75f},{0.50f,0.75f},{0.17f,0.75f},{0.33f,0.50f},{0.66f,0.50f},},
  {{0.0f,0.0f},{0.25f,0.25f},{0.50f,0.25f},{0.75f,0.25f},{0.75f,0.50f},{0.75f,0.75f},{0.50f,0.75f},{0.25f,0.75f},{0.25f,0.50f},{0.50f,0.50f}}
};
void move2DispPos(bool bShow)
{
	int cx, cy;
	RECT myRect;
	int iLeft, iTop;
	int iWidth, iHeight;
	HWND hWnd = GetConsoleWindow();
	int iDevID;
	int iEntity;

	iDevID = atoi(strDevID.c_str());
	iEntity = atoi(strEntity.c_str());

	cx = ::GetSystemMetrics(SM_CXFULLSCREEN);
	cy = ::GetSystemMetrics(SM_CYFULLSCREEN);

	ShowWindow(hWnd, SW_NORMAL);
	GetWindowRect(hWnd, &myRect);
	iWidth = myRect.right - myRect.left;
	iHeight = myRect.bottom - myRect.top;

	iLeft = (int)(gsLayout[iLayOut][iDevID].xRate * cx) - 60 + iEntity *(120+15);
	iTop = (int)((gsLayout[iLayOut][iDevID].yRate * cy) + 45);
	if (iLeft > cx - iWidth) {
		iLeft = cx - iWidth;
		iTop += iHeight * iEntity;
		if (iTop > cy) {
			iTop = cy - iHeight;
		}
	}

	MoveWindow(hWnd, iLeft, iTop, iWidth, iHeight, TRUE);

	if (bShow) {
		ShowWindow(hWnd, SW_NORMAL);
	}
	else {
		ShowWindow(hWnd, SW_MINIMIZE);
	}
}
//名称：GetLocalAddrTable
//功能：获得本地地址表
//输入：piNum，地址表大小指针
//输出：返回值，地址表指针，已经实例化空间；piNum,本地地址表地址个数
in_addr* GetLocalAddrTable(int* piNum)
{
	in_addr* addrs;
	int addrNum;
	PMIB_IPADDRTABLE pIPAddrTable;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;
	LPVOID lpMsgBuf;

	// Before calling AddIPAddress we use GetIpAddrTable to get
	// an adapter to which we can add the IP.
	pIPAddrTable = (MIB_IPADDRTABLE*)MALLOC(sizeof(MIB_IPADDRTABLE));
	if (pIPAddrTable) {
		// Make an initial call to GetIpAddrTable to get the
		// necessary size into the dwSize variable
		if (GetIpAddrTable(pIPAddrTable, &dwSize, 0) ==
			ERROR_INSUFFICIENT_BUFFER) {
			FREE(pIPAddrTable);
			pIPAddrTable = (MIB_IPADDRTABLE*)MALLOC(dwSize);

		}
		if (pIPAddrTable == NULL) {
			//printf("Memory allocation failed for GetIpAddrTable\n");
			*piNum = 0;
			return NULL;
		}
	}
	// Make a second call to GetIpAddrTable to get the
	// actual data we want
	if ((dwRetVal = GetIpAddrTable(pIPAddrTable, &dwSize, 0)) != NO_ERROR) {
		if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),       // Default language
			(LPTSTR)&lpMsgBuf, 0, NULL)) {
			LocalFree(lpMsgBuf);
		}
		FREE(pIPAddrTable);
		*piNum = 0;
		return NULL;
	}
	if ((int)pIPAddrTable->dwNumEntries <= 0) {
		FREE(pIPAddrTable);
		*piNum = 0;
		return NULL;
	}
	addrNum = (int)pIPAddrTable->dwNumEntries;
	addrs = (in_addr*)malloc(sizeof(in_addr) * addrNum);
	for (int i = 0; i < addrNum; i++) {
		addrs[i].S_un.S_addr = (u_long)pIPAddrTable->table[i].dwAddr;
	}
	FREE(pIPAddrTable);
	*piNum = addrNum;
	return addrs;
}
//名称：isLocalAddrByStr
//功能：判断字符串地址是否为本地地址
//输入：strAddr 字符串地址, addrList 本地地址表, addrNum 本地地址数量
//输出：返回值，为真表示strAddr是本地地址
bool isLocalAddrByStr(string strAddr, in_addr* addrList, int addrNum)
{
	int i;
	in_addr InAddress;

	InAddress.S_un.S_addr = inet_addr(strAddr.c_str());
	if (InAddress.S_un.S_addr == htonl(INADDR_LOOPBACK)) {
		return true;
	}
	for (i = 0; i < addrNum; i++) {
		if (InAddress.S_un.S_addr == addrList[i].S_un.S_addr) {
			return true;
		}
	}
	return false;
}
//名称：isLocalAddr
//功能：判断地址是否为本地地址
//输入：InAddr 字符串地址, addrList 本地地址表, addrNum 本地地址数量
//输出：返回值，为真表示strAddr是本地地址
bool isLocalAddr(in_addr InAddr, in_addr* addrList, int addrNum)
{
	int i;

	if (InAddr.S_un.S_addr == htonl(INADDR_LOOPBACK)) {
		return true;
	}
	for (i = 0; i < addrNum; i++) {
		if (InAddr.S_un.S_addr == addrList[i].S_un.S_addr) {
			return true;
		}
	}
	return false;
}
//isSameEndPoint：判断两个端点地址是否相同，对于多地址主机，只要是本地地址之一都认为相同
//输入：addr1 端点地址1，addr2 端点地址2
//输出：返回值 true表示相同
bool isSameEndPoint(sockaddr_in addr1, sockaddr_in addr2)
{
	bool isSameIP = false;
	bool isSamePort = false;
	if (isLocalAddr(addr1.sin_addr,localAddrList,localAddrNum) && isLocalAddr(addr2.sin_addr, localAddrList, localAddrNum)) {
		isSameIP = true;
	}
	if (addr1.sin_addr.S_un.S_addr == addr2.sin_addr.S_un.S_addr) {
		isSameIP = true;
	}
	if(addr1.sin_port == addr2.sin_port) {
		isSamePort = true;
	}
	if (isSameIP && isSamePort)
		return true;
	return false;
}
//SendHello：向oneTouch一键启动服务器发送注册信息
//输入：全局唯一标识——设备号，层次名，实体号
//输出：
void SendHello()
{
	int retval;
	char* buf;
	int len;
	int i;
	//组装hello报文
	string strHello;
	strHello = "Hello:";
	strHello += strDevID + "|";
	strHello += strLayer + "[";
	strHello += strEntity + "]";
	len = (int)strHello.length() + 10;
	buf = (char*)malloc(len);
	for (i = 0; i < len - 10; i++) {
		buf[i] = strHello.at(i);
	}
	buf[i] = 0;
	retval = sendto(sock, buf, (int)strlen(buf)+1, 0, (sockaddr*)&oneTouch_addr, sizeof(oneTouch_addr));
	if (retval <= 0) {
		retval = WSAGetLastError();
	}
}
//HelloTimeout：计算发送hello的定时器是否到达，定时器到达时发送hello报文
//输入：全局变量iHelloCount，计时器计数值
//输出：
void HelloTimeout()
{
	iHelloCount++;
	if (iHelloCount >= HELLO_INTVAL / sBasicTimer.ulInterval) {
		SendHello();
		iHelloCount = 0;
	}
}

//oneTouch：接收到一键启动服务器发送过来的topo信息，进行处理
//输入：buf topo报文，len 报文长度
//输出：程序内改变全局的上层地址，下层地址
void oneTouch(char* buf, int len)
{
	string topo;
	int begin;
	int end;
	string strTmp;
	string strAddr;
	string strPort;
	in_addr addr;
	unsigned short port;
	int subBegin;
	int subEnd;

	topo = buf;
	if (topo.size() == 0)
		return;
	//去掉空格
	topo.erase(std::remove_if(topo.begin(), topo.end(), isspace), topo.end());

	begin = (int)topo.find_first_of('|', 0);
	while (begin < len) {
		begin += 1;
		end = (int)topo.find_first_of('|', begin);
		if (end == -1) {
			end = len;
		}
		//取下两个|之间的描述
		strTmp = topo.substr(begin, end - begin);
		int x = (int)strTmp.find("peer");
		int y = (int)strTmp.find("lower");
		if (x >= 0 || y >= 0) {
			//if (strTmp.find("peer") >= 0 || strTmp.find("lower") >= 0) {
			subBegin = (int)strTmp.find_first_of('-', 0);
			if (subBegin < 0) {
				break;
			}
			subBegin += 1;//去掉第一个冒号
			for (int i = 0; i < lowerNumber; i++) {
				//取一个地址
				subEnd = (int)strTmp.find_first_of(':', subBegin);
				if (subEnd < 0)
					break;
				strAddr = strTmp.substr(subBegin, subEnd - subBegin);
				subBegin = subEnd + 1;
				subEnd = (int)strTmp.find_first_of(',', subBegin);
				if (subEnd < 0)
					subEnd = (int)strTmp.length();

				strPort = strTmp.substr(subBegin, subEnd - subBegin);
				if (strAddr.compare("OT") == 0) {
					//该对象的地址使用oneTouch地址
					addr = oneTouch_addr.sin_addr;
				}else{
					addr.S_un.S_addr = inet_addr(strAddr.c_str());
				}
				port = htons(atoi(strPort.c_str()));
				if (lower_addr[i].sin_addr.S_un.S_addr != addr.S_un.S_addr || lower_addr[i].sin_port != port) {
					//重填地址
					lower_addr[i].sin_addr = addr;
					lower_addr[i].sin_port = port;
				}
				subBegin = subEnd + 1;
			}
		}
		else if (strTmp.find("upper") >= 0) {
			//取一个地址
			subBegin = (int)strTmp.find_first_of('-', 0);
			if (subBegin < 0) {
				break;
			}
			subBegin += 1;
			subEnd = (int)strTmp.find_first_of(':', subBegin);
			if (subEnd < 0)
				break;
			strAddr = strTmp.substr(subBegin, subEnd - subBegin);
			subBegin = subEnd + 1;
			subEnd = (int)strTmp.find_first_of(',', subBegin);
			if (subEnd < 0)
				subEnd = (int)strTmp.length();

			strPort = strTmp.substr(subBegin, subEnd - subBegin);
			if (strAddr.compare("OT") == 0) {
				//该对象的地址使用oneTouch地址
				addr = oneTouch_addr.sin_addr;
			}
			else {
				addr.S_un.S_addr = inet_addr(strAddr.c_str());
			}
			port = htons(atoi(strPort.c_str()));
			if (upper_addr.sin_addr.S_un.S_addr != addr.S_un.S_addr || upper_addr.sin_port != port) {
				//重填地址
				upper_addr.sin_addr = addr;
				upper_addr.sin_port = port;
			}
		}
		if (end >= len)
			break;
		begin = end;
	}
}

//------------华丽的分割线，main来了-----------------
int main(int argc, char* argv[])
{
	U8 * buf;          //存放从高层、低层、各方面来的数据的缓存，大小为MAX_BUFFER_SIZE
	int len;           //buf里有效数据的大小，单位是字节
	int iRecvIntfNo;
	struct sockaddr_in remote_addr;
	WSAData wsa;
	int retval;
	int tmpInt;
	fd_set readfds;
	timeval timeout;
	unsigned long arg;
	string s1, s2, s3;
	int i;
	string strTmp;

	buf = (char*)malloc(MAX_BUFFER_SIZE);
	if (buf == NULL) {
		cout << "内存不够" << endl;
		return 0;
	}

	if (argc == 4) {
		s1 = argv[1];
		s2 = argv[2];
		s3 = argv[3];
	}
	else if (argc == 3) {
		s1 = argv[1];
		s2 = "LNK";
		s3 = argv[2];
	}
	else {
		//从键盘读取
		cout << "请输入设备号：";
		cin >> s1;
		cout << "请输入层次名（大写）：";
		cin >> s2;
		//s2 = "NET";
		cout << "请输入实体号：";
		cin >> s3;
	}
	WSAStartup(0x101, &wsa);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == SOCKET_ERROR)
		return 0;

	//初始化本地地址表
	localAddrList = GetLocalAddrTable(&localAddrNum);

	cfgParms.setDeviceID(s1);
	cfgParms.setLayer(s2);
	cfgParms.setEntityID(s3);
	cfgParms.read();
	if (cfgParms.getLayer().compare("LNK") == 0) {
		SetColor(7);
	}
	else {
		SetColor(6);
	}

	cfgParms.print(); //打印出来看看是不是读出来了
	strDevID = cfgParms.getDeviceID();
	strLayer = cfgParms.getLayer();
	strEntity = cfgParms.getEntity();

	if (!cfgParms.isConfigExist) {
		//从键盘输入上、下层本层的地址和端口号等等
		//偷个懒，要求必须填好配置文件
		return 0;
	}
	
	//取本层实体参数，并设置——已废弃，采用隐式绑定
	//local_addr = cfgParms.getUDPAddr(CCfgFileParms::LOCAL,0);
	//local_addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	//if (bind(sock, (sockaddr*)& local_addr, sizeof(sockaddr_in)) != 0) {
		//printf("参数错误\n");
		//return 0;

	//}
	//获取工作参数
	retval = cfgParms.getValueInt(iWorkMode, (char*)"workMode");
	if (retval == -1) {
		iWorkMode = 0;
	}

	//读上层实体参数，已废弃，改为初始化
	//upper_addr = cfgParms.getUDPAddr(CCfgFileParms::UPPER, 0);
	upper_addr.sin_family = AF_INET;
	upper_addr.sin_addr.S_un.S_addr = 0;
	upper_addr.sin_port = 0;

	//取下层实体参数，并设置，已废弃，保留底层数量和底层工作参数
	//先取数量
	lowerNumber = cfgParms.getUDPAddrNumber(CCfgFileParms::LOWER);
	if (0 > lowerNumber) {
		printf("参数错误\n");
		return 0;
	}
	//逐个读取
	for (i = 0; i < lowerNumber; i++) {
		//已废弃，改为初始化
		//lower_addr[i] = cfgParms.getUDPAddr(CCfgFileParms::LOWER, i);
		lower_addr[i].sin_family = AF_INET;
		lower_addr[i].sin_addr.S_un.S_addr = 0;
		lower_addr[i].sin_port = 0;

		//读取低层接口数据形式，先组装lowerModex参数名，到局部参数中找
		strTmp = "lowerMode";
		strTmp += std::to_string(i);
		retval = cfgParms.getValueInt(lowerMode[i],strTmp.c_str());
		if (0 > retval) {
			//没找到局部专设的参数，则再找全局值
			retval = cfgParms.getValueInt(lowerMode[i], (char*)"lowerMode");
			if (0 > retval) {
				lowerMode[i] = 1; //默认都是字节流
			}
		}
	}

	//获取统一管理平台地址
	//cmd_addr = cfgParms.getUDPAddr(CCfgFileParms::CMDER, 0);
	cmd_addr.sin_family = AF_INET;
	strTmp = cfgParms.getValueStr("cmdIpAddr");
	cmd_addr.sin_addr.S_un.S_addr = inet_addr(strTmp.c_str());
	retval = cfgParms.getValueInt(tmpInt,"cmdPort");
	cmd_addr.sin_port = ntohs(tmpInt);
	cmd_addr.sin_family = AF_INET;
	//获取oneTouch一键启动地址
	oneTouch_addr.sin_family = AF_INET;
	strTmp = cfgParms.getValueStr("oneTouchAddr");
	oneTouch_addr.sin_addr.S_un.S_addr = inet_addr(strTmp.c_str());
	retval = cfgParms.getValueInt(tmpInt, "oneTouchPort");
	oneTouch_addr.sin_port = ntohs(tmpInt);

	//移动窗口到确定位置
	retval = cfgParms.getValueInt(tmpInt, "layOut");
	if (retval != -1) {
		iLayOut = tmpInt;
	}
	move2DispPos(false);
	move2DispPos(false);
	bool bIsShow = false;
	//心跳定时器
	retval = cfgParms.getValueInt(tmpInt, "heartBeatingTime");
	if (retval == 0)
		tmpInt = tmpInt * 1000;
	else {
		tmpInt = DEFAULT_TIMER_INTERVAL * 1000;
	}
	initTimer(tmpInt);

	//设置套接字为非阻塞态
	arg = 1;
	ioctlsocket(sock, FIONBIO, &arg);

	InitFunction(cfgParms);

	SendHello();
	retval = sizeof(local_addr);
	getsockname(sock, (sockaddr*)&local_addr, &retval);
	while (1) {
		FD_ZERO(&readfds);
		//采用了基于select机制，不断发送测试数据，和接收测试数据，也可以采用多线程，一线专发送，一线专接收的方案
		//设定超时时间
		if (sock > 0) {
			FD_SET(sock, &readfds);
		}
		setSelectTimeOut(&timeout, &sBasicTimer);
		retval = select(0, &readfds, NULL, NULL, &timeout);
		if (true == isTimeOut(&sBasicTimer)) {

			TimeOut();
			HelloTimeout();
			continue;
		}
		if (!FD_ISSET(sock, &readfds)) {
			continue;
		}
		len = sizeof(sockaddr_in);
		retval = recvfrom(sock, buf, MAX_BUFFER_SIZE, 0,(sockaddr*)&remote_addr,&len); //超过这个大小就不能愉快地玩耍了，因为缓冲不够大
		if (retval == 0) {
			closesocket(sock);
			sock = 0;
			printf("close a socket\n");
			continue;
		}
		else if (retval == -1) {
			retval = WSAGetLastError();
			if (retval == WSAEWOULDBLOCK || retval == WSAECONNRESET)
				continue;
			closesocket(sock);
			sock = 0;
			printf("close a socket\n");
			continue;
		}
		//收到数据后,通过源头判断是上层、下层、统一管理平台还是oneTouch的命令
		//if (remote_addr.sin_port == upper_addr.sin_port) {
		if(isSameEndPoint(remote_addr,upper_addr)){
			RecvfromUpper(buf, retval);
		}
		else {
			for (iRecvIntfNo = 0; iRecvIntfNo < lowerNumber; iRecvIntfNo++) {
				//下层收到的数据,检查是哪个接口的
				//if (remote_addr.sin_port == lower_addr[iRecvIntfNo].sin_port) {
				if(isSameEndPoint(remote_addr, lower_addr[iRecvIntfNo])){
					RecvfromLower(buf, retval, iRecvIntfNo);
					break;
				}
			}
			if (iRecvIntfNo >= lowerNumber) {
				//检查是不是控制口命令
				//if (remote_addr.sin_port == cmd_addr.sin_port) {
					if (strncmp(buf, "exit", 4) == 0) { 
						//收到退出命令
						goto ret;
					}
				//}
				//else {
					//从其他临时性端口来的命令
					if (strncmp(buf, "selected", 8) == 0) {
						//收到要求突出显示的命令
						if(!bIsShow){
							move2DispPos(true);
							bIsShow = true;
						}
						else {
							move2DispPos(false);
							bIsShow = false;
						}

					}
					if (strncmp(buf,"topo|",5) == 0){
						//收到oneTouch的通告 
						oneTouch(buf, retval);
					}
				//}
			}
		}
	}
ret:
	EndFunction();
	free(buf);
	if (sock > 0)
		closesocket(sock);
	WSACleanup();
	if (localAddrList != NULL) {
		free(localAddrList);
	}
	return 0;
}


// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
