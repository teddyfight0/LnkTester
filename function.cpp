// Nettester �Ĺ����ļ�
#include <iostream>
#include <conio.h>
#include "winsock.h"
#include "stdio.h"
#include "CfgFileParms.h"
#include "function.h"
using namespace std;


#define HDLC_FLAG 0x7E      // ֡����� 
#define HDLC_ESC 0x7D       // ת���ַ�
#define HDLC_ESC_MASK 0x20  // ת������
#define MAX_FRAME_SIZE 500  // ���֡����
#define CRC_SIZE 2          // CRCУ���볤��
extern int lowerNumber;  //�ײ�ʵ������

static const uint16_t crc16_table[256] = {
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    /* ... ����������CRC16�� */
};
typedef struct {
    U8* data;
    int len;
    bool isError;
    const char* description;
} TestCase;

// ����MAC��ַ
struct MAC_Address {
    U8 device_id;  // �豸����Ϊ��һ���ֽ�
    U8 entity_id;  // ʵ�����Ϊ�ڶ����ֽ�
};

extern MAC_Address dest_mac;

// ��ַ����ṹ
struct AddressTableEntry {
    MAC_Address mac;        // MAC��ַ
    int port;              // ��Ӧ�Ķ˿ں�
    int cost;             // ��·����(����Prim�㷨)
    bool isActive;         // �Ƿ�����С��������
};

// ȫ�ֵ�ַ��
std::vector<AddressTableEntry> addressTable;

// �㲥MAC��ַ����
const MAC_Address BROADCAST_MAC = { 0xFF, 0xFF };

// ȫ��MAC��ַ����
MAC_Address local_mac;  // ����MAC��ַ
MAC_Address dest_mac;   // Ŀ��MAC��ַ
#define MAC_ADDR_SIZE 2 // MAC��ַ����(�ֽ�)

// �ڽӾ�������Prim�㷨
#define MAX_NODES 256  // ���ڵ���(����MAC��ַ��Χ)
int adjMatrix[MAX_NODES][MAX_NODES];
bool mstMatrix[MAX_NODES][MAX_NODES];  // ��С����������
int nodeCount = 0;    // ��ǰ�ڵ�����

// ����Ϊ��Ҫ�ı���
bool receivedSuccess = false;
bool isAutoTest = false;  // �����Զ����ԵĿ���
int testDataCount = 0;    // �������ݼ���
U8* sendbuf;        // ������֯�������ݵĻ��棬��СΪMAX_BUFFER_SIZE,����������������������
int printCount = 0; // ��ӡ����
int spin = 0;       // ��ӡ��̬��Ϣ����
U8* buflast = NULL; // �����ϴη��͵�����
int buflast_len = 0; // �����ϴη��͵ĳ���
//------һЩͳ���õ�ȫ�ֱ���------------
int iSndTotal = 0;         // ������������
int iSndTotalCount = 0;    // ���������ܴ���
int iSndErrorCount = 0;    // ���ʹ������
int iRcvForward = 0;       // ת����������
int iRcvForwardCount = 0;  // ת�������ܴ���
int iRcvToUpper = 0;       // �ӵͲ�ݽ��߲���������
int iRcvToUpperCount = 0;  // �ӵͲ�ݽ��߲������ܴ���
int iRcvUnknownCount = 0;  // �յ�������Դ�����ܴ���
#define MAX_RETRIES 3  // ����ش�����
int retryCount = 0;    // ��ǰ�ش�����

// ȫ�ֱ�����Դ MAC ��ַ��Ŀ�� MAC ��ַ


// ��ӡͳ����Ϣ
void print_statistics();
void menu();

// ��ʼ���ڽӾ���
void InitMatrix() {
    memset(adjMatrix, 0x3f, sizeof(adjMatrix)); // ��ʼ��Ϊ�����
    memset(mstMatrix, 0, sizeof(mstMatrix));
    for (int i = 0; i < MAX_NODES; i++) {
        adjMatrix[i][i] = 0;
    }
}
// ʹ��Prim�㷨������С������
void BuildMST() {
    if (nodeCount == 0) return;

    std::vector<bool> visited(nodeCount, false);
    std::vector<int> minCost(nodeCount, INT_MAX);
    std::vector<int> parent(nodeCount, -1);

    // �ӵ�һ���ڵ㿪ʼ
    minCost[0] = 0;

    for (int i = 0; i < nodeCount; i++) {
        int minVertex = -1;
        int minValue = INT_MAX;

        // �ҵ�δ���ʵ���С���۽ڵ�
        for (int j = 0; j < nodeCount; j++) {
            if (!visited[j] && minCost[j] < minValue) {
                minValue = minCost[j];
                minVertex = j;
            }
        }

        if (minVertex == -1) break;

        visited[minVertex] = true;

        // �������ڽڵ�Ĵ���
        for (int j = 0; j < nodeCount; j++) {
            if (!visited[j] && adjMatrix[minVertex][j] < minCost[j]) {
                minCost[j] = adjMatrix[minVertex][j];
                parent[j] = minVertex;
            }
        }
    }

    // ������С����������
    memset(mstMatrix, 0, sizeof(mstMatrix));
    for (int i = 1; i < nodeCount; i++) {
        if (parent[i] != -1) {
            mstMatrix[parent[i]][i] = true;
            mstMatrix[i][parent[i]] = true;
        }
    }
}

// �ڵ�ַ���в���MAC��ַ
int FindMACInTable(const MAC_Address& mac) {
    for (size_t i = 0; i < addressTable.size(); i++) {
        if (addressTable[i].mac.device_id == mac.device_id &&
            addressTable[i].mac.entity_id == mac.entity_id) {
            return i;
        }
    }
    return -1;
}

// ��ӻ���µ�ַ����
void UpdateAddressTable(const MAC_Address& mac, int port, int cost = 1) {
    // �����㲥��ַ�����ַ��
    if (mac.device_id == 0xFFFFFFFF && mac.entity_id == 0xFFFFFFFF) {
        return;
    }

    // ����Ǳ��ص�ַ�Ҷ˿�δ֪(-1)������Ϊ���ض˿�(0)
    if (mac.device_id == local_mac.device_id &&
        mac.entity_id == local_mac.entity_id &&
        port == -1) {
        port = 0;  // �����Լ������Լ�ʱ�Ķ˿ں�
    }

    int index = FindMACInTable(mac);
    if (index == -1) {
        // ��������
        AddressTableEntry entry = { mac, port, cost, false };
        addressTable.push_back(entry);

        if (nodeCount < MAX_NODES - 1) {
            // Ϊ�½ڵ��������
            for (int i = 0; i < nodeCount; i++) {
                adjMatrix[i][nodeCount] = cost;
                adjMatrix[nodeCount][i] = cost;
            }
            adjMatrix[nodeCount][nodeCount] = 0;
            nodeCount++;
            BuildMST();

            printf("\n������ַ���� - �豸:%02X ʵ��:%02X �˿�:%d\n",
                mac.device_id, mac.entity_id, port);
        }
    }
    else {
        // �������֪��ַ�����˿�δ֪������¶˿���Ϣ(�����ַѧϰ)
        if (addressTable[index].port == -1 && port != -1) {
            addressTable[index].port = port;
            addressTable[index].cost = cost;

            printf("\n���µ�ַ����(����ѧϰ) - �豸:%02X ʵ��:%02X �˿�:%d\n",
                mac.device_id, mac.entity_id, port);
        }
        // ��������¸������б���
        else if (addressTable[index].port != port || addressTable[index].cost != cost) {
            addressTable[index].port = port;
            addressTable[index].cost = cost;

            // �����ڽӾ����еĴ���
            for (int i = 0; i < nodeCount; i++) {
                if (i != index) {
                    adjMatrix[i][index] = cost;
                    adjMatrix[index][i] = cost;
                }
            }
            BuildMST();

            printf("\n���µ�ַ���� - �豸:%02X ʵ��:%02X �˿�:%d\n",
                mac.device_id, mac.entity_id, port);
        }
    }
}

//---------------------------------------------------------------------------
//---------------------------------------------------------------------------
void InitMAC() {
    // ���豸�ź�ʵ��ų�ʼ������MAC
    local_mac.device_id = (U8)atoi(strDevID.c_str());
    local_mac.entity_id = (U8)atoi(strEntity.c_str());
}

// ���MAC��ַ�Ƿ�ƥ��
bool CheckMACMatch(const MAC_Address* received_mac) {
    return (received_mac->device_id == local_mac.device_id &&
        received_mac->entity_id == local_mac.entity_id);
}
// �������Զ����Եĺ���
void AutoTestHDLC() {
    static TestCase testCases[] = {
        {NULL, 0, false, "Test1-Normal"},      // ��������
        {NULL, 0, false, "Test2-Normal"},      // ��������
        {NULL, 0, false, "Test3-Normal"},      // ��������
        {NULL, 0, false, "Test4-Normal"},      // ��������
        {NULL, 0, false, "Test5-Normal"},      // ��������
    };
    static const int TEST_CASES = sizeof(testCases) / sizeof(TestCase);
    static int currentRetries = 0;              // ��ǰ�������������Դ���
    static const int TEST_TIMEOUT = 50;         // ÿ�����������ĳ�ʱ����
    static int timeoutCounter = 0;              // ��ʱ������

    if (!isAutoTest) return;

    if (testDataCount < TEST_CASES) {
        TestCase* currentTest = &testCases[testDataCount];
        static bool receivedSuccess = false;
        if (receivedSuccess) {
            // ����Ѿ��յ��ɹ�ȷ��,�ƶ�����һ����������
            printf("\n�������� %s ���(CRCУ��ɹ�)\n", currentTest->description);
            if (currentTest->data != NULL) {
                free(currentTest->data);
                currentTest->data = NULL;
            }
            testDataCount++;
            timeoutCounter = 0;
            currentRetries = 0;
            receivedSuccess = false; // ���ñ�־
            return;
        }
        // ����Ƿ�ʱ
        if (timeoutCounter++ > TEST_TIMEOUT) {
            printf("\n��ǰ��������(%s)��ʱ����ת����һ������...\n", currentTest->description);
            if (currentTest->data != NULL) {
                free(currentTest->data);
                currentTest->data = NULL;
            }
            testDataCount++;
            timeoutCounter = 0;
            currentRetries = 0;
            return;
        }

        // �����ǰ��������δ׼���ã�����׼��
        if (currentTest->data == NULL) {
            timeoutCounter = 0;  // ���ó�ʱ������
            cout << "\n��ʼ���Ͳ������� " << testDataCount + 1 << ": " << currentTest->description << endl;

            const char* testStr = currentTest->description;
            int len = strlen(testStr) + 1;

            currentTest->data = (U8*)malloc(len);
            if (currentTest->data == NULL) {
                cout << "�ڴ����ʧ��!" << endl;
                isAutoTest = false;
                return;
            }
            memcpy(currentTest->data, testStr, len);
            currentTest->len = len;

            // ���������Ŷ�
            currentRetries = 0;  // �������Լ���
        }

        // ����Ƿ���Ҫ��������
        if (currentRetries < MAX_RETRIES) {
            RecvfromUpper(currentTest->data, currentTest->len);
            currentRetries++;
            receivedSuccess = false;
        }
        else {
            // �ﵽ������Դ������ƶ�����һ������
            printf("\n�������� %s ���(�ﵽ������Դ���)\n", currentTest->description);
            free(currentTest->data);
            currentTest->data = NULL;
            testDataCount++;
            timeoutCounter = 0;
            currentRetries = 0;
        }

        // ����Ƿ�������в���
        if (testDataCount >= TEST_CASES) {
            isAutoTest = false;
            cout << "\n�Զ��������!" << endl;
            cout << "����ͳ�ƣ�" << endl;
            cout << "�ܷ��ʹ�����" << iSndTotalCount << endl;
            cout << "���ʹ��������" << iSndErrorCount << endl;
            cout << "�ش�������" << iRcvUnknownCount << endl;
        }
    }
}



// ����CRC16У��ֵ
uint16_t calculateCRC16(U8* data, int len) {
    uint16_t crc = 0xFFFF;
    for (int i = 0; i < len; i++) {
        crc = (crc << 8) ^ crc16_table[((crc >> 8) ^ data[i]) & 0xFF];
    }
    return crc;
}

//***************��Ҫ��������******************************
//���ƣ�InitFunction
//���ܣ���ʼ�������棬��main�����ڶ��������ļ�����ʽ������������ǰ����
void InitFunction(CCfgFileParms& cfgParms) {
    sendbuf = (char*)malloc(MAX_BUFFER_SIZE);
    if (sendbuf == NULL) {
        cout << "�ڴ治��" << endl;
        exit(0);
    }
    // ��ʼ��MAC��ַ
    InitMAC();

    // ��ʼ���ڽӾ������С������
    InitMatrix();

    // ��յ�ַ��
    addressTable.clear();

    return;
}

//***************��Ҫ��������******************************
//���ƣ�EndFunction
//���ܣ����������棬��main�������յ�exit������������˳�ǰ����
void EndFunction() {
    if (sendbuf != NULL)
        free(sendbuf);
    if (buflast != NULL)
        free(buflast);
    return;
}

//***************��Ҫ��������******************************
//���ƣ�TimeOut
//���ܣ�������������ʱ����ζ��sBasicTimer�����õĳ�ʱʱ�䵽�ˣ�
//        (1)��Ϊscanf�����������¼�ʱ���ڵȴ����̵�ʱ����ȫʧЧ������ʹ��_kbhit()������������ϵ��ڼ�ʱ�Ŀ������жϼ���״̬
//      (2)����ˢ�´�ӡ����ͳ��ֵ��ͨ����ӡ���Ʒ��Ŀ��ƣ�����ʼ�ձ�����ͬһ�д�ӡ
//���룺ʱ�䵽�˾ʹ�����ֻ��ͨ��ȫ�ֱ�����������

void TimeOut() {
    static int testTimeout = 0;
    static int waitForConfirm = 0;  // �ȴ�ȷ�ϵļ�����
    printCount++;
    if (_kbhit()) {
        // �����ж���������˵�ģʽ
        menu();
    }
    if (isAutoTest) {
        // ÿ100ms����һ���Զ�����
        if (testTimeout++ >= 10) {  // ���������ʱ����10ms
            if (receivedSuccess) {
                // ����յ��ɹ�ȷ�ϣ��������ü�������������һ������
                printf("\n����ɹ���������һ������\n");
                testDataCount++;
                retryCount = 0;
                receivedSuccess = false;
                waitForConfirm = 0;
            }
            else if (waitForConfirm++ > 50) { // 500ms��ʱ
                printf("\n�ȴ�ȷ�ϳ�ʱ��������һ������\n");
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
//    if (len < 4) return false;  // ��С֡���ȼ��
//
//    // ���֡��ʼ�ͽ�����־
//    if (buf[0] != HDLC_FLAG || buf[len - 1] != HDLC_FLAG) {
//        return false;
//    }
//
//    // ���֡���ݵĺϷ���
//    int escCount = 0;
//    for (int i = 1; i < len - 1; i++) {
//        if (buf[i] == HDLC_ESC) escCount++;
//        if (escCount > len / 2) return false; // ת���ַ�����,�������𻵵�֡
//    }
//
//    return true;
//}
//------------���������ݵ��շ�--------------------------------

//***************��Ҫ��������******************************
//���ƣ�RecvfromUpper
//���ܣ�������������ʱ����ζ���յ�һ�ݸ߲��·�������
void RecvfromUpper(U8* buf, int len) {
    if (len > MAX_FRAME_SIZE - 4) {
        iSndErrorCount++;
        return;  // ����̫��
    }

    // �ȴ�ӡԭʼ����
    printf("\n===== ������������ =====\n");
    printf("ԭʼ���� (%d�ֽ�):\n", len);
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
    // HDLC֡��װ
    int frameIndex = 0;
    tempBuf[frameIndex++] = HDLC_FLAG;  // ��ʼ��־

    // ����Ŀ��MAC��ַ
    if (dest_mac.device_id == 0xFFFFFFFF && dest_mac.entity_id == 0xFFFFFFFF) {
        // �㲥��
        tempBuf[frameIndex++] = 0xFF;   // �㲥Ŀ��MAC��ַ
        tempBuf[frameIndex++] = 0xFF;
        printf("֡����: %s\n", (dest_mac.device_id == 0xFFFFFFFF && dest_mac.entity_id == 0xFFFFFFFF) ?
            "�㲥" : "����");

    }
    else {
        // ������ - ֱ��ʹ�����õ�Ŀ��MAC��ַ
        tempBuf[frameIndex++] = dest_mac.device_id;
        tempBuf[frameIndex++] = dest_mac.entity_id;

        // ��ӡĿ�ĵ�ַ��Ϣ���ڵ���
        printf("���ڷ��͵������ݰ��� %02X:%02X\n",
            dest_mac.device_id, dest_mac.entity_id);
        printf("\nĿ��MAC��ַ: %02X:%02X\n", dest_mac.device_id, dest_mac.entity_id);
        printf("֡����: %s\n", (dest_mac.device_id == 0xFFFFFFFF && dest_mac.entity_id == 0xFFFFFFFF) ?
            "�㲥" : "����");

    }
    // ��ӱ���MAC��ַ����ַ��(�ڷ�������ʱ)
    UpdateAddressTable(local_mac, 0);

    // ����ǵ����Ҳ��ǹ㲥�����Ŀ��MAC����ַ��
    if (dest_mac.device_id != 0xFFFFFFFF || dest_mac.entity_id != 0xFFFFFFFF) {
        // ���Ŀ�ĵ�ַ�Ǳ��ص�ַ��ʹ�ñ��ض˿�0
        if (dest_mac.device_id == local_mac.device_id &&
            dest_mac.entity_id == local_mac.entity_id) {
            UpdateAddressTable(dest_mac, 0);
        }
        else {
            UpdateAddressTable(dest_mac, -1); // �������ʹ��-1��ʾδ֪�˿�
        }
    }

    // ���ԴMAC��ַ
    tempBuf[frameIndex++] = local_mac.device_id;
    tempBuf[frameIndex++] = local_mac.entity_id;

    // ����CRC
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

    // �ֽ����
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
    tempBuf[frameIndex++] = HDLC_FLAG; // ������־
    printf("\n===== HDLC֡��װ��� =====\n");
    printf("HDLC֡ (%d�ֽ�):\n", frameIndex);
    for (int i = 0; i < frameIndex; i++) {
        printf("%02X ", (unsigned char)tempBuf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
//-----------------------------------------------------------------------------------------
    // ��������
    // ��������
    int iSndRetval = 0;
    U8* bufSend = NULL;

    // ȷ�����Ͷ˿�
    int targetPort = -1;
    if (dest_mac.device_id == 0xFFFFFFFF && dest_mac.entity_id == 0xFFFFFFFF) {
        // �㲥������Ҫ���͵����ж˿�
        printf("\n���͹㲥�������ж˿�\n");
		printf("%d\n", lowerNumber);
        bool sendSuccess = true;
        for (int i = 0; i < lowerNumber; i++) {
            printf("���ڷ��͵��˿� %d... ", i);  // ��ӵ������
			printf("lowerMode[%d]: %d\n", i, lowerMode[i]);
            if (lowerMode[i] == 0) {
                // ������ģʽ
                bufSend = (U8*)malloc(frameIndex * 8);
                if (bufSend == NULL) {
                    printf("�ڴ����ʧ��!\n");
                    iSndErrorCount++;
                    continue;
                }
                int bitLen = ByteArrayToBitArray(bufSend, frameIndex * 8, tempBuf, frameIndex);
                int ret = SendtoLower(bufSend, bitLen, i);
                if (ret > 0) {
                    printf("���ͳɹ�����С: %d\n", ret);
                    iSndTotal += ret;
                    iSndTotalCount++;
                }
                else {
                    printf("����ʧ��!\n");
                    sendSuccess = false;
                    iSndErrorCount++;
                }
                free(bufSend);
                bufSend = NULL;
            }
            else {
                // �ֽ���ģʽ
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

        // ��������͵����������ش�
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
        // ��������ʹ����С������ȷ��ת���˿�
		printf("���͵��������˿� %d\n", targetPort);
        int destIndex = FindMACInTable(dest_mac);
        if (destIndex != -1) {
            // �ڵ�ַ�����ҵ�Ŀ��MAC
            targetPort = addressTable[destIndex].port;
            if (targetPort == -1) {
                // �˿�δ֪����Ҫ������С�������ҵ����ʵ�ת���˿�
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
            printf("\n���͵��������˿� %d\n", targetPort);
            if (lowerMode[targetPort] == 0) {
                // ������ģʽ
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
                    // ���������ش�
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
                // �ֽ���ģʽ
                iSndRetval = SendtoLower(tempBuf, frameIndex, targetPort);
                if (iSndRetval > 0) {
                    iSndTotal += iSndRetval * 8;
                    iSndTotalCount++;
                    // ���������ش�
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
            printf("\n�����Ҳ�����Ч�ķ��Ͷ˿ڣ�Ŀ��MAC=%02X:%02X\n",
                dest_mac.device_id, dest_mac.entity_id);
            iSndErrorCount++;
        }
    }

    free(tempBuf);
}


//***************��Ҫ��������******************************
//���ƣ�RecvfromLower
//���룺U8 * buf,�Ͳ�ݽ����������ݣ� int len�����ݳ��ȣ���λ�ֽڣ�int ifNo ���Ͳ�ʵ����룬�����������ĸ��Ͳ�
void RecvfromLower(U8* buf, int len, int ifNo) {
    // �����ش�����
    if (buf[0] == '1' && len == 1) {
        if (buflast != NULL && retryCount < MAX_RETRIES) {
            printf("\n�յ��ش��������ڽ��е�%d���ش�...ԭʼ֡����=%d\n", retryCount + 1, buflast_len);
            printf("�ش�֡����ʼ��־=0x%02X ������־=0x%02X\n",
            (unsigned char)buflast[0], (unsigned char)buflast[buflast_len - 1]);
            int sendResult = SendtoLower(buflast, buflast_len, ifNo);
            if (sendResult > 0) {
                printf("�ش������ѷ��ͣ��ȴ�ȷ��...\n");
                retryCount++;
            }
            else {
                printf("�ش�ʧ��!\n");
            }
        }
        else {
            if (buflast == NULL) {
                printf("û�п��ش�������\n");
            }
            else {
                printf("�ش������Ѵ�����(%d��)�������ش�\n", MAX_RETRIES);
            }
            retryCount = 0;
        }
        return;
    }
//------------------------------------------------------------------------------------------------------
//     ע�⣺��������ȫ����֡��λ�Ĳ��֣��ܹ���ɵĹ������ǽ���֡��λ
    // bit��תbyte��
    // ����ֻ����ʾ��ʼת���Ľ����ʵ���ϵõ��������ǲ���ȷ�ģ�����
    U8* byteBuf = buf;
    int byteLen = len;
    U8* tmpAlloc = nullptr;
    if (lowerMode[ifNo] == 0) {
        int byteBufLen = len / 8 + ((len % 8) ? 1 : 0);
        tmpAlloc = (U8*)malloc(byteBufLen);
        if (tmpAlloc == nullptr) {
            printf("�ڴ����ʧ��\n");
            return;
        }
        byteLen = BitArrayToByteArray(buf, len, tmpAlloc, byteBufLen);
        byteBuf = tmpAlloc;
    }
    // ��ӡ�յ���ԭʼ����
    printf("\n===== ������������ =====\n");
    printf("�յ�ԭʼ���� (%d�ֽ�):\n", byteLen);
    for (int i = 0; i < byteLen; i++) {
        printf("%02X ", (unsigned char)byteBuf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
//---------------------------------------------------------------------------
    // 1. ��byteBufת��Ϊ������
    int bitBufLen = byteLen * 8;
    U8* bitBuf = (U8*)malloc(bitBufLen);
    if (!bitBuf) {
        printf("�ڴ����ʧ��\n");
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    for (int i = 0; i < byteLen; i++) {
        for (int j = 0; j < 8; j++) {
            bitBuf[i * 8 + j] = (byteBuf[i] >> (7 - j)) & 0x1;
        }
    }

    // 2. �ڱ������в��ҵ�һ��01111110
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
        printf("δ�ҵ���Ч��01111110��־λ\n");
        free(bitBuf);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }

    // 3. ��ȡ��һ�������һ����־λ֮��ı�����
    int validBitStart = firstFlag;
    int validBitEnd = lastFlag + 8; // �������һ����־λ
    int validBitLen = validBitEnd - validBitStart;
    if (validBitLen <= 0) {
        printf("��־λ������Ч\n");
        free(bitBuf);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    U8* validBits = (U8*)malloc(validBitLen);
    if (!validBits) {
        printf("�ڴ����ʧ��\n");
        free(bitBuf);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    memcpy(validBits, bitBuf + validBitStart, validBitLen);

    // 4. ����Ч������ת�����ֽ���
    int validByteLen = (validBitLen + 7) / 8;
    U8* validBytes = (U8*)malloc(validByteLen);
    if (!validBytes) {
        printf("�ڴ����ʧ��\n");
        free(validBits);
        free(bitBuf);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    memset(validBytes, 0, validByteLen);
    for (int i = 0; i < validBitLen; i++) {
        validBytes[i / 8] |= (validBits[i] & 0x1) << (7 - (i % 8));
    }

    // ��ӡת�������Ч�ֽ���
    printf("��ȡ����ЧHDLC֡�ֽ�����%d�ֽڣ�:\n", validByteLen);
    for (int i = 0; i < validByteLen; i++) {
        printf("%02X ", validBytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // ����ǵ��ͷ�
    
    free(validBits);
    free(bitBuf);

    // ɨ��validBytes�����ҺϷ���HDLC֡ 
    printf("��ʼ�ڱ������в���֡��־....\n");
    int start = -1, end = -1;
    for (int i = 0; i < validByteLen; i++) {
        if ((unsigned char)validBytes[i] == HDLC_FLAG) {
            if (start == -1) {
                // �ҵ���ʼ��־
                start = i;
            }
            else {
                // �ҵ�������־
                end = i;
                if (end - start >= 4) {
                    // �ҵ�����֡
                    printf("�ҵ�����HDLC֡: ��ʼλ��=%d, ����λ��=%d\n", start, end);
                    break;
                }
                else {
                    // ���֡���Ȳ��㣬������ʼ��־
                    start = i;
                }
            }
        }
    }

    if (start == -1 || end == -1 || end - start < 4) {
        iRcvUnknownCount++;
        printf("δ�ҵ���Ч��HDLC֡!\n");
        printf("===================\n");
        if (tmpAlloc) free(tmpAlloc);
        return;
    }

    // ����MAC��ַ
    MAC_Address received_dest_mac, received_src_mac;
    received_dest_mac.device_id = validBytes[start + 1];
    received_dest_mac.entity_id = validBytes[start + 2];
    received_src_mac.device_id = validBytes[start + 3];
    received_src_mac.entity_id = validBytes[start + 4];

    // ���µ�ַ��
    UpdateAddressTable(received_src_mac, ifNo);

    // ���MAC��ַ�Ƿ�ƥ��
    bool isForMe = (received_dest_mac.device_id == 0xFF && received_dest_mac.entity_id == 0xFF) ||
        CheckMACMatch(&received_dest_mac);

    // in RecvfromLower() function
    if (!isForMe) {
        // ������Ƿ����ҵİ�����Ҫ�ж��Ƿ���Ҫת��
        if (received_dest_mac.device_id == 0xFFFFFFFF && received_dest_mac.entity_id == 0xFFFFFFFF) {
            // �㲥����ת�������˽��ն˿�������ж˿�
            printf("ת���㲥�������������˿�\n");
            for (int i = 0; i < lowerNumber; i++) {
                if (i != ifNo) { // �����յ��Ķ˿�ת����ȥ
                    SendtoLower(validBytes, validByteLen, i);
                    iRcvForward += validByteLen * 8;
                    iRcvForwardCount++;
                }
            }
        }
        else {
            // ��������������С������ȷ��ת��·��
            int srcIndex = FindMACInTable(received_src_mac);
            int destIndex = FindMACInTable(received_dest_mac);

            if (srcIndex != -1 && destIndex != -1) {
                // ����Ƿ�����С������·����
                if (mstMatrix[srcIndex][destIndex]) {
                    // �ҵ�Ŀ��MAC��Ӧ��ת���˿�
                    int forwardPort = -1;
                    for (size_t i = 0; i < addressTable.size(); i++) {
                        if (addressTable[i].mac.device_id == received_dest_mac.device_id &&
                            addressTable[i].mac.entity_id == received_dest_mac.entity_id) {
                            forwardPort = addressTable[i].port;
                            break;
                        }
                    }

                    if (forwardPort >= 0 && forwardPort < lowerNumber && forwardPort != ifNo) {
                        printf("ͨ����С������ת�����������˿� %d\n", forwardPort);
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

    

    // �洢ԴMAC��ַ���ڻظ�
    dest_mac = received_src_mac;

    printf("MAC��ַƥ��!\n");
    printf("ԴMAC: %02X:%02X\n", received_src_mac.device_id, received_src_mac.entity_id);
    printf("Ŀ��MAC: %02X:%02X\n", received_dest_mac.device_id, received_dest_mac.entity_id);

    int frameLen = end - start + 1;
    printf("\n���յ�֡: ����=%d ��ʼ��־=0x%02X ������־=0x%02X\n",
        frameLen, (unsigned char)validBytes[start], (unsigned char)validBytes[end]);
//-------------------------------------------------------
// ���ϵĲ�����֡������ɵ���������

    U8* frameBuf = (U8*)malloc(frameLen);
    if (!frameBuf) {
        if (tmpAlloc) free(tmpAlloc);
        printf("�ڴ����ʧ��\n");
        return;
    }
    memcpy(frameBuf, validBytes + start, frameLen);

    printf("\n��ȡ����HDLC֡ (%d�ֽ�):\n", frameLen);
    for (int i = 0; i < frameLen; i++) {
        printf("%02X ", (unsigned char)frameBuf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    U8* tempBuf = (U8*)malloc(frameLen);
    if (!tempBuf) {
        free(frameBuf);
        if (tmpAlloc) free(tmpAlloc);
        printf("�ڴ����ʧ��\n");
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
        printf("\nCRCУ��ʧ��(�յ�:0x%04X, ����:0x%04X)\n", receivedFCS, calculatedFCS);
        printf("�����ش�...\n");
        SendFlagToLower(1, ifNo);
        if (tmpAlloc) free(tmpAlloc);
        return;
    }

    if (receivedFCS == calculatedFCS) {
        printf("CRCУ��ͨ��!\n");
        printf("===================\n");

        // �ݽ����ݵ��ϲ�
        int sendlen = SendtoUpper(tempBuf, dataIndex);
        if (sendlen > 0) {
            iRcvToUpper += sendlen * 8; // ͳ��λ��
            iRcvToUpperCount++;
            retryCount = 0; // �����ش�����

            // ��Ҫ���յ���ȷ���ݺ������һ�η��͵����ݻ���
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

//��ӡ��С�������͵�ǰ�ĵ�ַ��
void printTree() {
    printf("\n============= ��ǰ����״̬ =============\n");

    // ��ӡ��ǰ�ĵ�ַ��
    printf("\n=== ��ַ�� ===\n");
    printf("����\t�豸:ʵ��\t�˿�\t����\t״̬\n");
    printf("----------------------------------------\n");
    for (size_t i = 0; i < addressTable.size(); i++) {
        printf("%zu\t%02X:%02X\t\t%d\t%d\t%s\n",
            i,
            addressTable[i].mac.device_id,
            addressTable[i].mac.entity_id,
            addressTable[i].port,
            addressTable[i].cost,
            addressTable[i].isActive ? "�" : "�ǻ");
    }

    // ��ӡ�ڽӾ���
    printf("\n=== �ڽӾ��� ===\n");
    printf("    ");
    for (int i = 0; i < nodeCount; i++) {
        printf("%2d ", i);
    }
    printf("\n");
    for (int i = 0; i < nodeCount; i++) {
        printf("%2d: ", i);
        for (int j = 0; j < nodeCount; j++) {
            if (adjMatrix[i][j] >= 0x3f3f3f3f)
                printf("�� ");
            else
                printf("%2d ", adjMatrix[i][j]);
        }
        printf("\n");
    }

    // ��ӡ��С������
    printf("\n=== ��С������ ===\n");
    for (int i = 0; i < nodeCount; i++) {
        for (int j = i + 1; j < nodeCount; j++) {
            if (mstMatrix[i][j]) {
                printf("�ڵ�%d <--> �ڵ�%d\n", i, j);
            }
        }
    }

    printf("\n======================================\n");
}


//��ӡ��ص�ͳ����Ϣ
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
        cout << "��ת�� " << iRcvForward << " λ��" << iRcvForwardCount << " �Σ�" << "�ݽ� " << iRcvToUpper << " λ��" << iRcvToUpperCount << " ��," << "���� " << iSndTotal << " λ��" << iSndTotalCount << " �Σ�" << "���Ͳ��ɹ� " << iSndErrorCount << " ��," << "�յ�������Դ " << iRcvUnknownCount << " �Ρ�";
        spin++;
    }
}

// PrintParms ��ӡ����������ע�ⲻ��cfgFilms�������ģ�����Ŀǰ��Ч�Ĳ���
void PrintParms() {
    size_t i;
    cout << "�豸��: " << strDevID << " ���: " << strLayer << "ʵ��: " << strEntity << endl;
    cout << "�ϲ�ʵ���ַ: " << inet_ntoa(upper_addr.sin_addr) << "  UDP�˿ں�: " << ntohs(upper_addr.sin_port) << endl;
    cout << "����ʵ���ַ: " << inet_ntoa(local_addr.sin_addr) << "  UDP�˿ں�: " << ntohs(local_addr.sin_port) << endl;
    if (strLayer.compare("PHY") == 0) {
        if (lowerNumber <= 1) {
            cout << "�²�㵽���ŵ�" << endl;
            cout << "��·�Զ˵�ַ: ";
        }
        else {
            cout << "�²�㲥ʽ�ŵ�" << endl;
            cout << "�����ŵ�վ�㣺";
        }
    }
    else {
        cout << "�²�ʵ��";
    }

    if (strLayer.compare("PHY") == 0) {
        cout << endl;
        for (i = 0; i < lowerNumber; i++) {
            cout << "        ��ַ��" << inet_ntoa(lower_addr[i].sin_addr) << "  UDP�˿ں�: " << ntohs(lower_addr[i].sin_port) << endl;
        }
    }
    else {
        cout << endl;
        for (i = 0; i < lowerNumber; i++) {
            cout << "        �ӿ�: [" << i << "] ��ַ" << inet_ntoa(lower_addr[i].sin_addr) << "  UDP�˿ں�: " << ntohs(lower_addr[i].sin_port) << endl;
        }
    }
    string strTmp;
    // strTmp = getValueStr("cmdIpAddr");
    cout << "ͳһ����ƽ̨��ַ: " << inet_ntoa(cmd_addr.sin_addr);
    // strTmp = getValueStr("cmdPort");
    cout << "  UDP�˿ں�: " << ntohs(cmd_addr.sin_port) << endl;
    // strTmp = getValueStr("oneTouchAddr");
    cout << "oneTouchһ��������ַ: " << inet_ntoa(oneTouch_addr.sin_addr);
    // strTmp = getValueStr("oneTouchPort");
    cout << "  UDP�˿ں�; " << ntohs(oneTouch_addr.sin_port) << endl;
    cout << "##################" << endl;
    // cfgParms.printArray();
    cout << "--------------------------------------------------------------------" << endl;
    cout << endl;
}

// �˵�����
void menu() {
    int selection;
    unsigned short port;
    int iSndRetval;
    char kbBuf[100];
    int len;
    U8* bufSend;
    // ����|��ӡ��[���Ϳ��ƣ�0���ȴ��������룻1���Զ���][��ӡ���ƣ�0�������ڴ�ӡͳ����Ϣ��1����bit����ӡ���ݣ�2���ֽ�����ӡ����]
    cout << endl << endl << "�豸��:" << strDevID << ",    ���:" << strLayer << ",    ʵ���:" << strEntity;
    cout << endl << "7-��ӡ����������; ";
    cout << endl << "0-ȡ��" << endl << "����������ѡ�����";
    cout << endl << "8-����HDLC�Զ�����;";  // ����ѡ��
    cout << endl << "9-����Ŀ��MAC��ַ;";

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
        cout << "��ʼHDLC�Զ�����..." << endl;
        cout << "���Խ������������ͺʹ����ش������" << endl;
        isAutoTest = true;
        testDataCount = 0;
        break;
        // ��menu()����������µ�case:
    case 9:
        cout << "����Ŀ��MAC��ַ:" << endl;
        cout << "����Ŀ���豸��(0-255,����255Ϊ�㲥): ";
        int device_id;
        cin >> device_id;
        if (device_id == 255) {
            dest_mac.device_id = 0xFF;
            dest_mac.entity_id = 0xFF;
            cout << "������Ϊ�㲥��ַ FF:FF" << endl;
        }
        else {
            dest_mac.device_id = (U8)device_id;
            cout << "����Ŀ��ʵ���(0-255,����255Ϊ�㲥): ";
            int entity_id;
            cin >> entity_id;
            if (entity_id == 255) {
                dest_mac.entity_id = 0xFF;
                if (dest_mac.device_id == 0xFF) {
                    cout << "������Ϊ�㲥��ַ FF:FF" << endl;
                }
                else {
                    cout << "������Ŀ��MACΪ " << hex << (int)dest_mac.device_id << ":FF" << dec << endl;
                }
            }
            else {
                dest_mac.entity_id = (U8)entity_id;
                cout << "������Ŀ��MACΪ " << hex << (int)dest_mac.device_id << ":" << (int)dest_mac.entity_id << dec << endl;
            }
        }
        // ���ɲ�������
        const char* testMessage = "Hello from device ";
        string message = testMessage + strDevID;
        int dataLen = message.length() + 1;
        U8* testData = (U8*)malloc(dataLen);
        if (!testData) {
            cout << "�ڴ����ʧ��!" << endl;
            break;
        }
        memcpy(testData, message.c_str(), dataLen);

        // ��������
        RecvfromUpper(testData, dataLen);
        free(testData);
        // ��ӡ��ǰ��ַ�����С������
        printTree();
        break;
    }
}