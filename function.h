#pragma once
//yeah once, sure
//一般故事都是从定义开始
#define MAX_BUFFER_SIZE 65000 //默认缓冲的最大大小，也是UDP报文的上限
#define DEFAULT_TIMER_INTERVAL 50 //默认心跳计时器时间间隔，单位是毫秒
typedef char U8; //定义单字节无符号整数，这样就不纠结char这个类型了，现在是单字节整数

//============重点来了================================================================================================
//------------重要的控制参数------------------------------------------------------------
//以下从配置文件ne.txt中读取的重要参数
extern int lowerMode[10]; //如果低层是物理层模拟软件，这个数组放置的是每个接口对应的数据格式——0为比特数组，1为字节数组
extern int lowerNumber;   //低层实体数量，比如网络层之下可能有多个链路层
extern int iWorkMode;     //实体的工作模式，十位数：1 自动发送，0 手动发送；个位数 1 打印数据内容，0 打印统计数据
extern string strDevID;    //设备号，字符串形式，从1开始
extern string strLayer;    //层次名
extern string strEntity;   //实体好，字符串形式，从0开始，可以通过atoi函数变成整数在程序中使用
extern struct sockaddr_in local_addr;      //本层实体地址
extern struct sockaddr_in upper_addr;      //上层实体地址，一般情况下，上层实体只有1个
extern struct sockaddr_in lower_addr[10];  //最多10个下层对象，数组下标就是下层实体的编号
extern sockaddr_in cmd_addr;         //统一管理平台地址
extern sockaddr_in oneTouch_addr;  //一键启动服务器地址

//start------华丽的分割线---------------------------------------------------------
//------------重要的需要考虑实现其内容的函数------------------------------------------------------------
void TimeOut();
void RecvfromLower(U8* buf, int len, int ifNo);
void RecvfromUpper(U8* buf, int len);
void InitFunction(CCfgFileParms& cfgParms);
void EndFunction();

//------------重要的会使用到的函数------------------------------------------------------------
//************发送数据的函数*************
int SendtoUpper(U8* buf, int len);
int SendtoLower(U8* buf, int len, int ifNo);
void SendFlagToLower(int flag, int ifNo) ;
int SendtoCommander(U8* buf, int len);
//************一些工具函数***************
void print_data_bit(U8* A, int length, int iMode);
void print_data_byte(U8* A, int length, int iMode);
void code(unsigned long x, U8 A[], int length);
unsigned long decode(U8 A[], int length);
int ByteArrayToBitArray(U8* bitA, int iBitLen, U8* byteA, int iByteLen);
int BitArrayToByteArray(U8* bitA, int iBitLen, U8* byteA, int iByteLen);
void StartTimerOnce(ULONG ulInterval);
void StartTimerPeriodically(ULONG ulInterval);

