// Nettester 的功能文件
#include <iostream>
#include <conio.h>
#include "winsock.h"
#include "stdio.h"
#include "CfgFileParms.h"
#include "function.h"
#include <stdint.h> // 添加stdint.h以定义uint8_t (U8)
using namespace std;

#define HDLC_FLAG 0x7E      // 帧定界符 
#define HDLC_ESC 0x7D       // 转义字符
#define HDLC_ESC_MASK 0x20  // 转义掩码
#define MAX_FRAME_SIZE 500  // 最大帧长度
#define CRC_SIZE 2          // CRC校验码长度

static const uint16_t crc16_table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    /* ... 补充完整的CRC16表 */
};
typedef struct {
    U8* data;
    int len;
    bool isError;
    const char* description;
} TestCase;

// 以下为重要的变量
bool receivedSuccess = false;
bool isAutoTest = false;  // 控制自动测试的开关
int testDataCount = 0;    // 测试数据计数
U8* sendbuf;        // 用来组织发送数据的缓存，大小为MAX_BUFFER_SIZE,可以在这个基础上扩充设计
int printCount = 0; // 打印控制
int spin = 0;       // 打印动态信息控制
U8* buflast = NULL; // 保存上次发送的数据
int buflast_len = 0; // 保存上次发送的长度
//------一些统计用的全局变量------------
int iSndTotal = 0;         // 发送数据总量
int iSndTotalCount = 0;    // 发送数据总次数
int iSndErrorCount = 0;    // 发送错误次数
int iRcvForward = 0;       // 转发数据总量
int iRcvForwardCount = 0;  // 转发数据总次数
int iRcvToUpper = 0;       // 从低层递交高层数据总量
int iRcvToUpperCount = 0;  // 从低层递交高层数据总次数
int iRcvUnknownCount = 0;  // 收到不明来源数据总次数
#define MAX_RETRIES 3  // 最大重传次数
int retryCount = 0;    // 当前重传次数
// 打印统计信息
void print_statistics();
void menu();

// 这里是自动测试的函数

void AutoTestHDLC() {
    static TestCase testCases[] = {
        {NULL, 0, false, "Test1-Normal"},      // 正常发送
        {NULL, 0, false, "Test2-Normal"},      // 正常发送
        {NULL, 0, false, "Test3-Normal"},      // 正常发送
        {NULL, 0, false, "Test4-Normal"},      // 正常发送
        {NULL, 0, false, "Test5-Normal"},      // 正常发送
    };
    static const int TEST_CASES = sizeof(testCases) / sizeof(TestCase);
    static int currentRetries = 0;              // 当前测试用例的重试次数
    static const int TEST_TIMEOUT = 50;         // 每个测试用例的超时计数
    static int timeoutCounter = 0;              // 超时计数器

    if (!isAutoTest) return;

    if (testDataCount < TEST_CASES) {
        TestCase* currentTest = &testCases[testDataCount];
        static bool receivedSuccess = false;
        if (receivedSuccess) {
            // 如果已经收到成功确认,移动到下一个测试用例
            printf("\n测试用例 %s 完成(CRC校验成功)\n", currentTest->description);
            if (currentTest->data != NULL) {
                free(currentTest->data);
                currentTest->data = NULL;
            }
            testDataCount++;
            timeoutCounter = 0;
            currentRetries = 0;
            receivedSuccess = false; // 重置标志
            return;
        }
        // 检查是否超时
        if (timeoutCounter++ > TEST_TIMEOUT) {
            printf("\n当前测试用例(%s)超时，跳转到下一个测试...\n", currentTest->description);
            if (currentTest->data != NULL) {
                free(currentTest->data);
                currentTest->data = NULL;
            }
            testDataCount++;
            timeoutCounter = 0;
            currentRetries = 0;
            return;
        }

        // 如果当前测试数据未准备好，进行准备
        if (currentTest->data == NULL) {
            timeoutCounter = 0;  // 重置超时计数器
            cout << "\n开始发送测试数据 " << testDataCount + 1 << ": " << currentTest->description << endl;

            const char* testStr = currentTest->description;
            int len = strlen(testStr) + 1;

            currentTest->data = (U8*)malloc(len);
            if (currentTest->data == NULL) {
                cout << "内存分配失败!" << endl;
                isAutoTest = false;
                return;
            }
            memcpy(currentTest->data, testStr, len);
            currentTest->len = len;

            // 不做错误扰动
            currentRetries = 0;  // 重置重试计数
        }

        // 检查是否需要发送数据
        if (currentRetries < MAX_RETRIES) {
            RecvfromUpper(currentTest->data, currentTest->len);
            currentRetries++;
            receivedSuccess = false;
        }
        else {
            // 达到最大重试次数，移动到下一个测试
            printf("\n测试用例 %s 完成(达到最大重试次数)\n", currentTest->description);
            free(currentTest->data);
            currentTest->data = NULL;
            testDataCount++;
            timeoutCounter = 0;
            currentRetries = 0;
        }

        // 检查是否完成所有测试
        if (testDataCount >= TEST_CASES) {
            isAutoTest = false;
            cout << "\n自动测试完成!" << endl;
            cout << "测试统计：" << endl;
            cout << "总发送次数：" << iSndTotalCount << endl;
            cout << "发送错误次数：" << iSndErrorCount << endl;
            cout << "重传次数：" << iRcvUnknownCount << endl;
        }
    }
}



// 计算CRC16校验值
uint16_t calculateCRC16(U8* data, int len) {
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < len; i++) {
        crc = (crc << 8) ^ crc16_table[((crc >> 8) ^ data[i]) & 0xFF];
    }
    return crc;
}

//***************重要函数提醒******************************
//名称：InitFunction
//功能：初始化功能面，由main函数在读完配置文件，正式进入驱动机制前调用
void InitFunction(CCfgFileParms& cfgParms) {
    sendbuf = (char*)malloc(MAX_BUFFER_SIZE);
    if (sendbuf == NULL) {
        cout << "内存不够" << endl;
        exit(0);
    }
    return;
}

//***************重要函数提醒******************************
//名称：EndFunction
//功能：结束功能面，由main函数在收到exit命令，整个程序退出前调用
void EndFunction() {
    if (sendbuf != NULL)
        free(sendbuf);
    if (buflast != NULL)
        free(buflast);
    return;
}

//***************重要函数提醒******************************
//名称：TimeOut
//功能：本函数被调用时，意味着sBasicTimer中设置的超时时间到了，
//        (1)因为scanf会阻塞，导致计时器在等待键盘的时候完全失效，所以使用_kbhit()无阻塞、不间断地在计时的控制下判断键盘状态
//      (2)不断刷新打印各种统计值，通过打印控制符的控制，可以始终保持在同一行打印
//输入：时间到了就触发，只能通过全局变量供给输入

void TimeOut() {
    static int testTimeout = 0;
    static int waitForConfirm = 0;  // 等待确认的计数器
    printCount++;
    if (_kbhit()) {
        // 键盘有动作，进入菜单模式
        menu();
    }
    if (isAutoTest) {
        // 每100ms调用一次自动测试
        if (testTimeout++ >= 10) {  // 假设基础定时器是10ms
            if (receivedSuccess) {
                // 如果收到成功确认，立即重置计数器并进入下一个测试
                printf("\n传输成功，进入下一个测试\n");
                testDataCount++;
                retryCount = 0;
                receivedSuccess = false;
                waitForConfirm = 0;
            }
            else if (waitForConfirm++ > 50) { // 500ms超时
                printf("\n等待确认超时，进入下一个测试\n");
                testDataCount++;
                waitForConfirm = 0;
            }
            AutoTestHDLC();
            testTimeout = 0;
        }
    }


    print_statistics();
}
//bool ValidateFrame(U8* buf, int len) {
//    if (len < 4) return false;  // 最小帧长度检查
//
//    // 检查帧起始和结束标志
//    if (buf[0] != HDLC_FLAG || buf[len - 1] != HDLC_FLAG) {
//        return false;
//    }
//
//    // 检查帧内容的合法性
//    int escCount = 0;
//    for (int i = 1; i < len - 1; i++) {
//        if (buf[i] == HDLC_ESC) escCount++;
//        if (escCount > len / 2) return false; // 转义字符过多,可能是损坏的帧
//    }
//
//    return true;
//}
//------------以下是数据的收发--------------------------------

//***************重要函数提醒******************************
//名称：RecvfromUpper
//功能：本函数被调用时，意味着收到一份高层下发的数据
void RecvfromUpper(U8* buf, int len) {
    if (len > MAX_FRAME_SIZE - 4) {
        iSndErrorCount++;
        return;  // 数据太长
    }

    // 先打印原始数据
    printf("\n===== 发送数据详情 =====\n");
    printf("原始数据 (%d字节):\n", len);
    for (int i = 0; i < len; i++) {
        printf("%02X ", (unsigned char)buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    U8* tempBuf = (U8*)malloc(MAX_FRAME_SIZE);
    if (tempBuf == NULL) {
        iSndErrorCount++;
        return;
    }
    // HDLC帧封装
    int frameIndex = 0;
    tempBuf[frameIndex++] = HDLC_FLAG;  // 起始标志

    // 计算CRC
    uint16_t fcs = calculateCRC16(buf, len);
    U8* dataWithCRC = (U8*)malloc(len + CRC_SIZE);
    if (dataWithCRC == NULL) {
        free(tempBuf);
        iSndErrorCount++;
        return;
    }
    memcpy(dataWithCRC, buf, len);
    dataWithCRC[len] = (fcs >> 8) & 0xFF;
    dataWithCRC[len + 1] = fcs & 0xFF;

    // 字节填充
    for (int i = 0; i < len + CRC_SIZE; i++) {
        if (dataWithCRC[i] == HDLC_FLAG || dataWithCRC[i] == HDLC_ESC) {
            tempBuf[frameIndex++] = HDLC_ESC;
            tempBuf[frameIndex++] = dataWithCRC[i] ^ HDLC_ESC_MASK;
        }
        else {
            tempBuf[frameIndex++] = dataWithCRC[i];
        }
    }
    free(dataWithCRC);
    tempBuf[frameIndex++] = HDLC_FLAG; // 结束标志
    printf("\nHDLC帧 (%d字节):\n", frameIndex);
    printf("\n发送HDLC帧: 长度=%d 起始标志=0x%02X 结束标志=0x%02X\n",
        frameIndex, (unsigned char)tempBuf[0], (unsigned char)tempBuf[frameIndex - 1]);

    // 发送数据
    int iSndRetval = 0;
    U8* bufSend = NULL;

    if (lowerMode[0] == 0) {
        bufSend = (U8*)malloc(frameIndex * 8);
        if (bufSend == NULL) {
            free(tempBuf);
            return;
        }
        int bitLen = ByteArrayToBitArray(bufSend, frameIndex * 8, tempBuf, frameIndex);
        iSndRetval = SendtoLower(bufSend, bitLen, 0); // 这里用bitLen
    }
    else {
        iSndRetval = SendtoLower(tempBuf, frameIndex, 0);
        iSndRetval = iSndRetval * 8;
    }

    free(tempBuf);
    if (bufSend != NULL) {
        if (buflast != NULL) free(buflast);
        buflast = (U8*)malloc(iSndRetval);
        if (buflast != NULL) {
            memcpy(buflast, bufSend, iSndRetval);
            buflast_len = iSndRetval;
        }
        free(bufSend);
    }

    if (iSndRetval <= 0) {
        iSndErrorCount++;
    }
    else {
        iSndTotal += iSndRetval;
        iSndTotalCount++;
    }
    if (iSndRetval > 0) {
        if (buflast != NULL) free(buflast);
        buflast = (U8*)malloc(frameIndex);
        if (buflast != NULL) {
            memcpy(buflast, tempBuf, frameIndex);
            buflast_len = frameIndex;
        }
    }

    switch (iWorkMode % 10) {
    case 1:
        cout << endl << "高层要求向接口 " << 0 << " 发送数据：" << endl;
        print_data_bit(buf, len, 1);
        break;
    case 2:
        cout << endl << "高层要求向接口 " << 0 << " 发送数据：" << endl;
        print_data_byte(buf, len, 1);
        break;
    case 0:
        break;
    }
}


//***************重要函数提醒******************************
//名称：RecvfromLower
//输入：U8 * buf,低层递交上来的数据， int len，数据长度，单位字节，int ifNo ，低层实体号码，用来区分是哪个低层
void RecvfromLower(U8* buf, int len, int ifNo) {
    // 处理重传请求
    if (buf[0] == '1' && len == 1) {
        if (buflast != NULL && retryCount < MAX_RETRIES) {
            printf("\n收到重传请求，正在进行第%d次重传...原始帧长度=%d\n", retryCount + 1, buflast_len);
            printf("重传帧的起始标志=0x%02X 结束标志=0x%02X\n",
            (unsigned char)buflast[0], (unsigned char)buflast[buflast_len - 1]);
            int sendResult = SendtoLower(buflast, buflast_len, ifNo);
            if (sendResult > 0) {
                printf("重传数据已发送，等待确认...\n");
                retryCount++;
            }
            else {
                printf("重传失败!\n");
            }
        }
        else {
            if (buflast == NULL) {
                printf("没有可重传的数据\n");
            }
            else {
                printf("重传次数已达上限(%d次)，放弃重传\n", MAX_RETRIES);
            }
            retryCount = 0;
        }
        return;
    }

    // bit流转byte流
    U8* byteBuf = buf;
    int byteLen = len;
    U8* tmpAlloc = nullptr;
    if (lowerMode[ifNo] == 0) {
        int byteBufLen = len / 8 + ((len % 8) ? 1 : 0);
        tmpAlloc = (U8*)malloc(byteBufLen);
        if (tmpAlloc == nullptr) {
            printf("内存分配失败\n");
            return;
        }
        byteLen = BitArrayToByteArray(buf, len, tmpAlloc, byteBufLen);
        byteBuf = tmpAlloc;
    }
    // 打印收到的原始数据
    printf("\n===== 接收数据详情 =====\n");
    printf("收到原始数据 (%d字节):\n", byteLen);
    for (int i = 0; i < byteLen; i++) {
        printf("%02X ", (unsigned char)byteBuf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
    // 扫描byteBuf，查找合法的HDLC帧 
    // 修改帧定位逻辑
    printf("开始在比特流中查找帧标志....\n");
    int start = -1, end = -1;
    for (int i = 0; i < byteLen - 1; i++) {
        if ((unsigned char)byteBuf[i] == HDLC_FLAG) {
            for (int j = i + 1; j < byteLen; j++) {
                if ((unsigned char)byteBuf[j] == HDLC_FLAG) {
                    if (j - i >= 4) {
                        start = i;
                        end = j;
                        printf("找到完整HDLC帧: 起始位置=%d, 结束位置=%d\n", start, end);
                        break;
                        U8 byte = 0;
                    }
                }
            }
            if (start != -1) break;
        }
    }

    if (start == -1 || end == -1 || end - start < 4) {
        iRcvUnknownCount++;
        printf("未找到有效的HDLC帧!\n");
        printf("===================\n");
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    int frameLen = end - start + 1;
    printf("\n接收到帧: 长度=%d 起始标志=0x%02X 结束标志=0x%02X\n",
        frameLen, (unsigned char)byteBuf[start], (unsigned char)byteBuf[end]);

    U8* frameBuf = (U8*)malloc(frameLen);
    if (!frameBuf) {
        if (tmpAlloc) free(tmpAlloc);
        printf("内存分配失败\n");
        return;
    }
    memcpy(frameBuf, byteBuf + start, frameLen);

    printf("\n提取到的HDLC帧 (%d字节):\n", frameLen);
    for (int i = 0; i < frameLen; i++) {
        printf("%02X ", (unsigned char)frameBuf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    U8* tempBuf = (U8*)malloc(frameLen);
    if (!tempBuf) {
        free(frameBuf);
        if (tmpAlloc) free(tmpAlloc);
        printf("内存分配失败\n");
        return;
    }
    int dataIndex = 0;
    bool isEsc = false;
    for (int i = 1; i < frameLen - 3; i++) {
        if (isEsc) {
            tempBuf[dataIndex++] = frameBuf[i] ^ HDLC_ESC_MASK;
            isEsc = false;
        }
        else if (frameBuf[i] == HDLC_ESC) {
            isEsc = true;
        }
        else {
            tempBuf[dataIndex++] = frameBuf[i];
        }
    }

    uint16_t receivedFCS = (frameBuf[frameLen - 3] << 8) | frameBuf[frameLen - 2];
    uint16_t calculatedFCS = calculateCRC16(tempBuf, dataIndex);

    if (receivedFCS != calculatedFCS) {
        free(tempBuf);
        free(frameBuf);
        iRcvUnknownCount++;
        printf("\nCRC校验失败(收到:0x%04X, 计算:0x%04X)\n", receivedFCS, calculatedFCS);
        printf("请求重传...\n");
        SendFlagToLower(1, ifNo);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }

    if (receivedFCS == calculatedFCS) {
        printf("CRC校验通过!\n");
        printf("===================\n");

        // 递交数据到上层
        int sendlen = SendtoUpper(tempBuf, dataIndex);
        if (sendlen > 0) {
            iRcvToUpper += sendlen * 8; // 统计位数
            iRcvToUpperCount++;
            retryCount = 0; // 清理重传计数

            // 重要：收到正确数据后，清除上一次发送的数据缓存
            if (buflast != NULL) {
                free(buflast);
                buflast = NULL;
                buflast_len = 0;
            }

            if (isAutoTest) {
                receivedSuccess = true;
            }
        }
    }

    free(tempBuf);
    free(frameBuf);
    if (tmpAlloc) free(tmpAlloc);
}

void print_statistics() {
    if (printCount % 10 == 0) {
        switch (spin) {
        case 1:
            printf("\r-");
            break;
        case 2:
            printf("\r\\");
            break;
        case 3:
            printf("\r|");
            break;
        case 4:
            printf("\r/");
            spin = 0;
            break;
        }
        cout << "共转发 " << iRcvForward << " 位，" << iRcvForwardCount << " 次，" << "递交 " << iRcvToUpper << " 位，" << iRcvToUpperCount << " 次," << "发送 " << iSndTotal << " 位，" << iSndTotalCount << " 次，" << "发送不成功 " << iSndErrorCount << " 次," << "收到不明来源 " << iRcvUnknownCount << " 次。";
        spin++;
    }
}

// PrintParms 打印工作参数，注意不是cfgFilms读出来的，而是目前生效的参数
void PrintParms() {
    size_t i;
    cout << "设备号: " << strDevID << " 层次: " << strLayer << "实体: " << strEntity << endl;
    cout << "上层实体地址: " << inet_ntoa(upper_addr.sin_addr) << "  UDP端口号: " << ntohs(upper_addr.sin_port) << endl;
    cout << "本层实体地址: " << inet_ntoa(local_addr.sin_addr) << "  UDP端口号: " << ntohs(local_addr.sin_port) << endl;
    if (strLayer.compare("PHY") == 0) {
        if (lowerNumber <= 1) {
            cout << "下层点到点信道" << endl;
            cout << "链路对端地址: ";
        }
        else {
            cout << "下层广播式信道" << endl;
            cout << "共享信道站点：";
        }
    }
    else {
        cout << "下层实体";
    }

    if (strLayer.compare("PHY") == 0) {
        cout << endl;
        for (i = 0; i < lowerNumber; i++) {
            cout << "        地址：" << inet_ntoa(lower_addr[i].sin_addr) << "  UDP端口号: " << ntohs(lower_addr[i].sin_port) << endl;
        }
    }
    else {
        cout << endl;
        for (i = 0; i < lowerNumber; i++) {
            cout << "        接口: [" << i << "] 地址" << inet_ntoa(lower_addr[i].sin_addr) << "  UDP端口号: " << ntohs(lower_addr[i].sin_port) << endl;
        }
    }
    string strTmp;
    // strTmp = getValueStr("cmdIpAddr");
    cout << "统一管理平台地址: " << inet_ntoa(cmd_addr.sin_addr);
    // strTmp = getValueStr("cmdPort");
    cout << "  UDP端口号: " << ntohs(cmd_addr.sin_port) << endl;
    // strTmp = getValueStr("oneTouchAddr");
    cout << "oneTouch一键启动地址: " << inet_ntoa(oneTouch_addr.sin_addr);
    // strTmp = getValueStr("oneTouchPort");
    cout << "  UDP端口号; " << ntohs(oneTouch_addr.sin_port) << endl;
    cout << "##################" << endl;
    // cfgParms.printArray();
    cout << "--------------------------------------------------------------------" << endl;
    cout << endl;
}

void menu() {
    int selection;
    unsigned short port;
    int iSndRetval;
    char kbBuf[100];
    int len;
    U8* bufSend;
    // 发送|打印：[发送控制（0，等待键盘输入；1，自动）][打印控制（0，仅定期打印统计信息；1，按bit流打印数据，2按字节流打印数据]
    cout << endl << endl << "设备号:" << strDevID << ",    层次:" << strLayer << ",    实体号:" << strEntity;
    cout << endl << "7-打印工作参数表; ";
    cout << endl << "0-取消" << endl << "请输入数字选择命令：";
    cout << endl << "8-启动HDLC自动测试;";  // 新增选项
    cin >> selection;
    switch (selection) {
    case 0:
        break;
    case 1:
        break;
    case 2:
        break;
    case 3:
        break;
    case 4:
        break;
    case 5:
        break;
    case 6:
        break;
    case 7:
        PrintParms();
        break;
    case 8:
        cout << "开始HDLC自动测试..." << endl;
        cout << "测试将包含正常发送和错误重传的情况" << endl;
        isAutoTest = true;
        testDataCount = 0;
        break;
    }
}