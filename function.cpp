// Nettester 的功能文件
#include <iostream>
#include <conio.h>
#include "winsock.h"
#include "stdio.h"
#include "CfgFileParms.h"
#include "function.h"
using namespace std;


#define HDLC_FLAG 0x7E      // 帧定界符 
#define HDLC_ESC 0x7D       // 转义字符
#define HDLC_ESC_MASK 0x20  // 转义掩码
#define MAX_FRAME_SIZE 500  // 最大帧长度
#define CRC_SIZE 2          // CRC校验码长度
extern int lowerNumber;  //底层实体数量

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

// 定义MAC地址
struct MAC_Address {
    U8 device_id;  // 设备号作为第一个字节
    U8 entity_id;  // 实体号作为第二个字节
};

extern MAC_Address dest_mac;

// 地址表项结构
struct AddressTableEntry {
    MAC_Address mac;        // MAC地址
    int port;              // 对应的端口号
    int cost;             // 链路代价(用于Prim算法)
    bool isActive;         // 是否在最小生成树中
};

// 全局地址表
std::vector<AddressTableEntry> addressTable;

// 广播MAC地址定义
const MAC_Address BROADCAST_MAC = { 0xFF, 0xFF };

// 全局MAC地址变量
MAC_Address local_mac;  // 本地MAC地址
MAC_Address dest_mac;   // 目的MAC地址
#define MAC_ADDR_SIZE 2 // MAC地址长度(字节)

// 邻接矩阵用于Prim算法
#define MAX_NODES 256  // 最大节点数(基于MAC地址范围)
int adjMatrix[MAX_NODES][MAX_NODES];
bool mstMatrix[MAX_NODES][MAX_NODES];  // 最小生成树矩阵
int nodeCount = 0;    // 当前节点数量

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

// 全局变量：源 MAC 地址和目的 MAC 地址


// 打印统计信息
void print_statistics();
void menu();

// 初始化邻接矩阵
void InitMatrix() {
    memset(adjMatrix, 0x3f, sizeof(adjMatrix)); // 初始化为无穷大
    memset(mstMatrix, 0, sizeof(mstMatrix));
    for (int i = 0; i < MAX_NODES; i++) {
        adjMatrix[i][i] = 0;
    }
}
// 使用Prim算法构建最小生成树
void BuildMST() {
    if (nodeCount == 0) return;

    std::vector<bool> visited(nodeCount, false);
    std::vector<int> minCost(nodeCount, INT_MAX);
    std::vector<int> parent(nodeCount, -1);

    // 从第一个节点开始
    minCost[0] = 0;

    for (int i = 0; i < nodeCount; i++) {
        int minVertex = -1;
        int minValue = INT_MAX;

        // 找到未访问的最小代价节点
        for (int j = 0; j < nodeCount; j++) {
            if (!visited[j] && minCost[j] < minValue) {
                minValue = minCost[j];
                minVertex = j;
            }
        }

        if (minVertex == -1) break;

        visited[minVertex] = true;

        // 更新相邻节点的代价
        for (int j = 0; j < nodeCount; j++) {
            if (!visited[j] && adjMatrix[minVertex][j] < minCost[j]) {
                minCost[j] = adjMatrix[minVertex][j];
                parent[j] = minVertex;
            }
        }
    }

    // 构建最小生成树矩阵
    memset(mstMatrix, 0, sizeof(mstMatrix));
    for (int i = 1; i < nodeCount; i++) {
        if (parent[i] != -1) {
            mstMatrix[parent[i]][i] = true;
            mstMatrix[i][parent[i]] = true;
        }
    }
}

// 在地址表中查找MAC地址
int FindMACInTable(const MAC_Address& mac) {
    for (size_t i = 0; i < addressTable.size(); i++) {
        if (addressTable[i].mac.device_id == mac.device_id &&
            addressTable[i].mac.entity_id == mac.entity_id) {
            return i;
        }
    }
    return -1;
}

// 添加或更新地址表项
void UpdateAddressTable(const MAC_Address& mac, int port, int cost = 1) {
    // 不将广播地址加入地址表
    if (mac.device_id == 0xFFFFFFFF && mac.entity_id == 0xFFFFFFFF) {
        return;
    }

    // 如果是本地地址且端口未知(-1)，设置为本地端口(0)
    if (mac.device_id == local_mac.device_id &&
        mac.entity_id == local_mac.entity_id &&
        port == -1) {
        port = 0;  // 修正自己发给自己时的端口号
    }

    int index = FindMACInTable(mac);
    if (index == -1) {
        // 新增表项
        AddressTableEntry entry = { mac, port, cost, false };
        addressTable.push_back(entry);

        if (nodeCount < MAX_NODES - 1) {
            // 为新节点添加连接
            for (int i = 0; i < nodeCount; i++) {
                adjMatrix[i][nodeCount] = cost;
                adjMatrix[nodeCount][i] = cost;
            }
            adjMatrix[nodeCount][nodeCount] = 0;
            nodeCount++;
            BuildMST();

            printf("\n新增地址表项 - 设备:%02X 实体:%02X 端口:%d\n",
                mac.device_id, mac.entity_id, port);
        }
    }
    else {
        // 如果是已知地址，但端口未知，则更新端口信息(反向地址学习)
        if (addressTable[index].port == -1 && port != -1) {
            addressTable[index].port = port;
            addressTable[index].cost = cost;

            printf("\n更新地址表项(反向学习) - 设备:%02X 实体:%02X 端口:%d\n",
                mac.device_id, mac.entity_id, port);
        }
        // 其他情况下更新已有表项
        else if (addressTable[index].port != port || addressTable[index].cost != cost) {
            addressTable[index].port = port;
            addressTable[index].cost = cost;

            // 更新邻接矩阵中的代价
            for (int i = 0; i < nodeCount; i++) {
                if (i != index) {
                    adjMatrix[i][index] = cost;
                    adjMatrix[index][i] = cost;
                }
            }
            BuildMST();

            printf("\n更新地址表项 - 设备:%02X 实体:%02X 端口:%d\n",
                mac.device_id, mac.entity_id, port);
        }
    }
}

//---------------------------------------------------------------------------
//---------------------------------------------------------------------------
void InitMAC() {
    // 从设备号和实体号初始化本地MAC
    local_mac.device_id = (U8)atoi(strDevID.c_str());
    local_mac.entity_id = (U8)atoi(strEntity.c_str());
}

// 检查MAC地址是否匹配
bool CheckMACMatch(const MAC_Address* received_mac) {
    return (received_mac->device_id == local_mac.device_id &&
        received_mac->entity_id == local_mac.entity_id);
}
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
    // 初始化MAC地址
    InitMAC();

    // 初始化邻接矩阵和最小生成树
    InitMatrix();

    // 清空地址表
    addressTable.clear();

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

    // 查找目的MAC地址
    if (dest_mac.device_id == 0xFFFFFFFF && dest_mac.entity_id == 0xFFFFFFFF) {
        // 广播包
        tempBuf[frameIndex++] = 0xFF;   // 广播目的MAC地址
        tempBuf[frameIndex++] = 0xFF;
        printf("帧类型: %s\n", (dest_mac.device_id == 0xFFFFFFFF && dest_mac.entity_id == 0xFFFFFFFF) ?
            "广播" : "单播");

    }
    else {
        // 单播包 - 直接使用设置的目的MAC地址
        tempBuf[frameIndex++] = dest_mac.device_id;
        tempBuf[frameIndex++] = dest_mac.entity_id;

        // 打印目的地址信息用于调试
        printf("正在发送单播数据包到 %02X:%02X\n",
            dest_mac.device_id, dest_mac.entity_id);
        printf("\n目的MAC地址: %02X:%02X\n", dest_mac.device_id, dest_mac.entity_id);
        printf("帧类型: %s\n", (dest_mac.device_id == 0xFFFFFFFF && dest_mac.entity_id == 0xFFFFFFFF) ?
            "广播" : "单播");

    }
    // 添加本地MAC地址到地址表(在发送数据时)
    UpdateAddressTable(local_mac, 0);

    // 如果是单播且不是广播，添加目的MAC到地址表
    if (dest_mac.device_id != 0xFFFFFFFF || dest_mac.entity_id != 0xFFFFFFFF) {
        // 如果目的地址是本地地址，使用本地端口0
        if (dest_mac.device_id == local_mac.device_id &&
            dest_mac.entity_id == local_mac.entity_id) {
            UpdateAddressTable(dest_mac, 0);
        }
        else {
            UpdateAddressTable(dest_mac, -1); // 其他情况使用-1表示未知端口
        }
    }

    // 添加源MAC地址
    tempBuf[frameIndex++] = local_mac.device_id;
    tempBuf[frameIndex++] = local_mac.entity_id;

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
    printf("\n===== HDLC帧封装完成 =====\n");
    printf("HDLC帧 (%d字节):\n", frameIndex);
    for (int i = 0; i < frameIndex; i++) {
        printf("%02X ", (unsigned char)tempBuf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
//-----------------------------------------------------------------------------------------
    // 发送数据
    // 发送数据
    int iSndRetval = 0;
    U8* bufSend = NULL;

    // 确定发送端口
    int targetPort = -1;
    if (dest_mac.device_id == 0xFFFFFFFF && dest_mac.entity_id == 0xFFFFFFFF) {
        // 广播包：需要发送到所有端口
        printf("\n发送广播包到所有端口\n");
		printf("%d\n", lowerNumber);
        bool sendSuccess = true;
        for (int i = 0; i < lowerNumber; i++) {
            printf("正在发送到端口 %d... ", i);  // 添加调试输出
			printf("lowerMode[%d]: %d\n", i, lowerMode[i]);
            if (lowerMode[i] == 0) {
                // 比特流模式
                bufSend = (U8*)malloc(frameIndex * 8);
                if (bufSend == NULL) {
                    printf("内存分配失败!\n");
                    iSndErrorCount++;
                    continue;
                }
                int bitLen = ByteArrayToBitArray(bufSend, frameIndex * 8, tempBuf, frameIndex);
                int ret = SendtoLower(bufSend, bitLen, i);
                if (ret > 0) {
                    printf("发送成功，大小: %d\n", ret);
                    iSndTotal += ret;
                    iSndTotalCount++;
                }
                else {
                    printf("发送失败!\n");
                    sendSuccess = false;
                    iSndErrorCount++;
                }
                free(bufSend);
                bufSend = NULL;
            }
            else {
                // 字节流模式
                int ret = SendtoLower(tempBuf, frameIndex, i);
                if (ret > 0) {
                    iSndTotal += ret * 8;
                    iSndTotalCount++;
                }
                else {
                    sendSuccess = false;
                    iSndErrorCount++;
                }
            }
        }

        // 保存最后发送的数据用于重传
        if (sendSuccess && buflast != NULL) {
            free(buflast);
            buflast = (U8*)malloc(frameIndex);
            if (buflast != NULL) {
                memcpy(buflast, tempBuf, frameIndex);
                buflast_len = frameIndex;
            }
        }
    }
    else {
        // 单播包：使用最小生成树确定转发端口
		printf("发送单播包到端口 %d\n", targetPort);
        int destIndex = FindMACInTable(dest_mac);
        if (destIndex != -1) {
            // 在地址表中找到目标MAC
            targetPort = addressTable[destIndex].port;
            if (targetPort == -1) {
                // 端口未知，需要遍历最小生成树找到合适的转发端口
                int localIndex = FindMACInTable(local_mac);
                if (localIndex != -1) {
                    for (int i = 0; i < lowerNumber; i++) {
                        if (mstMatrix[localIndex][destIndex]) {
                            targetPort = i;
                            break;
                        }
                    }
                }
            }
        }

        if (targetPort >= 0 && targetPort < lowerNumber) {
            printf("\n发送单播包到端口 %d\n", targetPort);
            if (lowerMode[targetPort] == 0) {
                // 比特流模式
                bufSend = (U8*)malloc(frameIndex * 8);
                if (bufSend == NULL) {
                    iSndErrorCount++;
                    free(tempBuf);
                    return;
                }
                int bitLen = ByteArrayToBitArray(bufSend, frameIndex * 8, tempBuf, frameIndex);
                iSndRetval = SendtoLower(bufSend, bitLen, targetPort);
                if (iSndRetval > 0) {
                    iSndTotal += iSndRetval;
                    iSndTotalCount++;
                    // 保存用于重传
                    if (buflast != NULL) free(buflast);
                    buflast = (U8*)malloc(iSndRetval);
                    if (buflast != NULL) {
                        memcpy(buflast, bufSend, iSndRetval);
                        buflast_len = iSndRetval;
                    }
                }
                else {
                    iSndErrorCount++;
                }
                free(bufSend);
            }
            else {
                // 字节流模式
                iSndRetval = SendtoLower(tempBuf, frameIndex, targetPort);
                if (iSndRetval > 0) {
                    iSndTotal += iSndRetval * 8;
                    iSndTotalCount++;
                    // 保存用于重传
                    if (buflast != NULL) free(buflast);
                    buflast = (U8*)malloc(frameIndex);
                    if (buflast != NULL) {
                        memcpy(buflast, tempBuf, frameIndex);
                        buflast_len = frameIndex;
                    }
                }
                else {
                    iSndErrorCount++;
                }
            }
        }
        else {
            printf("\n错误：找不到有效的发送端口，目标MAC=%02X:%02X\n",
                dest_mac.device_id, dest_mac.entity_id);
            iSndErrorCount++;
        }
    }

    free(tempBuf);
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
//------------------------------------------------------------------------------------------------------
//     注意：以下内容全部是帧定位的部分，能够完成的工作就是进行帧定位
    // bit流转byte流
    // 这里只是显示初始转化的结果，实际上得到的内容是不正确的！！！
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
//---------------------------------------------------------------------------
    // 1. 将byteBuf转换为比特流
    int bitBufLen = byteLen * 8;
    U8* bitBuf = (U8*)malloc(bitBufLen);
    if (!bitBuf) {
        printf("内存分配失败\n");
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    for (int i = 0; i < byteLen; i++) {
        for (int j = 0; j < 8; j++) {
            bitBuf[i * 8 + j] = (byteBuf[i] >> (7 - j)) & 0x1;
        }
    }

    // 2. 在比特流中查找第一个01111110
    int flagPattern[8] = { 0,1,1,1,1,1,1,0 };
    int firstFlag = -1, lastFlag = -1;
    for (int i = 0; i <= bitBufLen - 8; i++) {
        bool match = true;
        for (int j = 0; j < 8; j++) {
            if (bitBuf[i + j] != flagPattern[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            if (firstFlag == -1) firstFlag = i;
            lastFlag = i;
        }
    }
    if (firstFlag == -1 || lastFlag == -1 || lastFlag < firstFlag) {
        printf("未找到有效的01111110标志位\n");
        free(bitBuf);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }

    // 3. 截取第一个到最后一个标志位之间的比特流
    int validBitStart = firstFlag;
    int validBitEnd = lastFlag + 8; // 包含最后一个标志位
    int validBitLen = validBitEnd - validBitStart;
    if (validBitLen <= 0) {
        printf("标志位区间无效\n");
        free(bitBuf);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    U8* validBits = (U8*)malloc(validBitLen);
    if (!validBits) {
        printf("内存分配失败\n");
        free(bitBuf);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    memcpy(validBits, bitBuf + validBitStart, validBitLen);

    // 4. 将有效比特流转换回字节流
    int validByteLen = (validBitLen + 7) / 8;
    U8* validBytes = (U8*)malloc(validByteLen);
    if (!validBytes) {
        printf("内存分配失败\n");
        free(validBits);
        free(bitBuf);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    memset(validBytes, 0, validByteLen);
    for (int i = 0; i < validBitLen; i++) {
        validBytes[i / 8] |= (validBits[i] & 0x1) << (7 - (i % 8));
    }

    // 打印转换后的有效字节流
    printf("提取的有效HDLC帧字节流（%d字节）:\n", validByteLen);
    for (int i = 0; i < validByteLen; i++) {
        printf("%02X ", validBytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // 用完记得释放
    
    free(validBits);
    free(bitBuf);

    // 扫描validBytes，查找合法的HDLC帧 
    printf("开始在比特流中查找帧标志....\n");
    int start = -1, end = -1;
    for (int i = 0; i < validByteLen; i++) {
        if ((unsigned char)validBytes[i] == HDLC_FLAG) {
            if (start == -1) {
                // 找到起始标志
                start = i;
            }
            else {
                // 找到结束标志
                end = i;
                if (end - start >= 4) {
                    // 找到完整帧
                    printf("找到完整HDLC帧: 起始位置=%d, 结束位置=%d\n", start, end);
                    break;
                }
                else {
                    // 如果帧长度不足，重置起始标志
                    start = i;
                }
            }
        }
    }

    if (start == -1 || end == -1 || end - start < 4) {
        iRcvUnknownCount++;
        printf("未找到有效的HDLC帧!\n");
        printf("===================\n");
        if (tmpAlloc) free(tmpAlloc);
        return;
    }

    // 解析MAC地址
    MAC_Address received_dest_mac, received_src_mac;
    received_dest_mac.device_id = validBytes[start + 1];
    received_dest_mac.entity_id = validBytes[start + 2];
    received_src_mac.device_id = validBytes[start + 3];
    received_src_mac.entity_id = validBytes[start + 4];

    // 更新地址表
    UpdateAddressTable(received_src_mac, ifNo);

    // 检查MAC地址是否匹配
    bool isForMe = (received_dest_mac.device_id == 0xFF && received_dest_mac.entity_id == 0xFF) ||
        CheckMACMatch(&received_dest_mac);

    // in RecvfromLower() function
    if (!isForMe) {
        // 如果不是发给我的包，需要判断是否需要转发
        if (received_dest_mac.device_id == 0xFFFFFFFF && received_dest_mac.entity_id == 0xFFFFFFFF) {
            // 广播包：转发到除了接收端口外的所有端口
            printf("转发广播包到所有其他端口\n");
            for (int i = 0; i < lowerNumber; i++) {
                if (i != ifNo) { // 不从收到的端口转发出去
                    SendtoLower(validBytes, validByteLen, i);
                    iRcvForward += validByteLen * 8;
                    iRcvForwardCount++;
                }
            }
        }
        else {
            // 单播包：查找最小生成树确定转发路径
            int srcIndex = FindMACInTable(received_src_mac);
            int destIndex = FindMACInTable(received_dest_mac);

            if (srcIndex != -1 && destIndex != -1) {
                // 检查是否在最小生成树路径上
                if (mstMatrix[srcIndex][destIndex]) {
                    // 找到目的MAC对应的转发端口
                    int forwardPort = -1;
                    for (size_t i = 0; i < addressTable.size(); i++) {
                        if (addressTable[i].mac.device_id == received_dest_mac.device_id &&
                            addressTable[i].mac.entity_id == received_dest_mac.entity_id) {
                            forwardPort = addressTable[i].port;
                            break;
                        }
                    }

                    if (forwardPort >= 0 && forwardPort < lowerNumber && forwardPort != ifNo) {
                        printf("通过最小生成树转发单播包到端口 %d\n", forwardPort);
                        SendtoLower(validBytes, validByteLen, forwardPort);
                        iRcvForward += validByteLen * 8;
                        iRcvForwardCount++;
                    }
                }
            }
        }

        free(validBytes);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }

    

    // 存储源MAC地址用于回复
    dest_mac = received_src_mac;

    printf("MAC地址匹配!\n");
    printf("源MAC: %02X:%02X\n", received_src_mac.device_id, received_src_mac.entity_id);
    printf("目的MAC: %02X:%02X\n", received_dest_mac.device_id, received_dest_mac.entity_id);

    int frameLen = end - start + 1;
    printf("\n接收到帧: 长度=%d 起始标志=0x%02X 结束标志=0x%02X\n",
        frameLen, (unsigned char)validBytes[start], (unsigned char)validBytes[end]);
//-------------------------------------------------------
// 以上的部分是帧解析完成的所有内容

    U8* frameBuf = (U8*)malloc(frameLen);
    if (!frameBuf) {
        if (tmpAlloc) free(tmpAlloc);
        printf("内存分配失败\n");
        return;
    }
    memcpy(frameBuf, validBytes + start, frameLen);

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
    free(validBytes);
    free(tempBuf);
    free(frameBuf);
    if (tmpAlloc) {
        free(tmpAlloc);
    }
}

//打印最小生成树和当前的地址表
void printTree() {
    printf("\n============= 当前网络状态 =============\n");

    // 打印当前的地址表
    printf("\n=== 地址表 ===\n");
    printf("索引\t设备:实体\t端口\t代价\t状态\n");
    printf("----------------------------------------\n");
    for (size_t i = 0; i < addressTable.size(); i++) {
        printf("%zu\t%02X:%02X\t\t%d\t%d\t%s\n",
            i,
            addressTable[i].mac.device_id,
            addressTable[i].mac.entity_id,
            addressTable[i].port,
            addressTable[i].cost,
            addressTable[i].isActive ? "活动" : "非活动");
    }

    // 打印邻接矩阵
    printf("\n=== 邻接矩阵 ===\n");
    printf("    ");
    for (int i = 0; i < nodeCount; i++) {
        printf("%2d ", i);
    }
    printf("\n");
    for (int i = 0; i < nodeCount; i++) {
        printf("%2d: ", i);
        for (int j = 0; j < nodeCount; j++) {
            if (adjMatrix[i][j] >= 0x3f3f3f3f)
                printf("∞ ");
            else
                printf("%2d ", adjMatrix[i][j]);
        }
        printf("\n");
    }

    // 打印最小生成树
    printf("\n=== 最小生成树 ===\n");
    for (int i = 0; i < nodeCount; i++) {
        for (int j = i + 1; j < nodeCount; j++) {
            if (mstMatrix[i][j]) {
                printf("节点%d <--> 节点%d\n", i, j);
            }
        }
    }

    printf("\n======================================\n");
}


//打印相关的统计信息
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

// 菜单函数
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
    cout << endl << "9-设置目的MAC地址;";

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
        // 在menu()函数中添加新的case:
    case 9:
        cout << "设置目的MAC地址:" << endl;
        cout << "输入目的设备号(0-255,输入255为广播): ";
        int device_id;
        cin >> device_id;
        if (device_id == 255) {
            dest_mac.device_id = 0xFF;
            dest_mac.entity_id = 0xFF;
            cout << "已设置为广播地址 FF:FF" << endl;
        }
        else {
            dest_mac.device_id = (U8)device_id;
            cout << "输入目的实体号(0-255,输入255为广播): ";
            int entity_id;
            cin >> entity_id;
            if (entity_id == 255) {
                dest_mac.entity_id = 0xFF;
                if (dest_mac.device_id == 0xFF) {
                    cout << "已设置为广播地址 FF:FF" << endl;
                }
                else {
                    cout << "已设置目的MAC为 " << hex << (int)dest_mac.device_id << ":FF" << dec << endl;
                }
            }
            else {
                dest_mac.entity_id = (U8)entity_id;
                cout << "已设置目的MAC为 " << hex << (int)dest_mac.device_id << ":" << (int)dest_mac.entity_id << dec << endl;
            }
        }
        // 生成测试数据
        const char* testMessage = "Hello from device ";
        string message = testMessage + strDevID;
        int dataLen = message.length() + 1;
        U8* testData = (U8*)malloc(dataLen);
        if (!testData) {
            cout << "内存分配失败!" << endl;
            break;
        }
        memcpy(testData, message.c_str(), dataLen);

        // 发送数据
        RecvfromUpper(testData, dataLen);
        free(testData);
        // 打印当前地址表和最小生成树
        printTree();
        break;
    }
}