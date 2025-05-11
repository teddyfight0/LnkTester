// Nettester �Ĺ����ļ�
#include <iostream>
#include <conio.h>
#include "winsock.h"
#include "stdio.h"
#include "CfgFileParms.h"
#include "function.h"
#include <stdint.h> // ���stdint.h�Զ���uint8_t (U8)
using namespace std;

#define HDLC_FLAG 0x7E      // ֡����� 
#define HDLC_ESC 0x7D       // ת���ַ�
#define HDLC_ESC_MASK 0x20  // ת������
#define MAX_FRAME_SIZE 500  // ���֡����
#define CRC_SIZE 2          // CRCУ���볤��

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
// ��ӡͳ����Ϣ
void print_statistics();
void menu();

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
    printf("\nHDLC֡ (%d�ֽ�):\n", frameIndex);
    printf("\n����HDLC֡: ����=%d ��ʼ��־=0x%02X ������־=0x%02X\n",
        frameIndex, (unsigned char)tempBuf[0], (unsigned char)tempBuf[frameIndex - 1]);

    // ��������
    int iSndRetval = 0;
    U8* bufSend = NULL;

    if (lowerMode[0] == 0) {
        bufSend = (U8*)malloc(frameIndex * 8);
        if (bufSend == NULL) {
            free(tempBuf);
            return;
        }
        int bitLen = ByteArrayToBitArray(bufSend, frameIndex * 8, tempBuf, frameIndex);
        iSndRetval = SendtoLower(bufSend, bitLen, 0); // ������bitLen
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
        cout << endl << "�߲�Ҫ����ӿ� " << 0 << " �������ݣ�" << endl;
        print_data_bit(buf, len, 1);
        break;
    case 2:
        cout << endl << "�߲�Ҫ����ӿ� " << 0 << " �������ݣ�" << endl;
        print_data_byte(buf, len, 1);
        break;
    case 0:
        break;
    }
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

    // bit��תbyte��
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
    // ɨ��byteBuf�����ҺϷ���HDLC֡ 
    // �޸�֡��λ�߼�
    printf("��ʼ�ڱ������в���֡��־....\n");
    int start = -1, end = -1;
    for (int i = 0; i < byteLen - 1; i++) {
        if ((unsigned char)byteBuf[i] == HDLC_FLAG) {
            for (int j = i + 1; j < byteLen; j++) {
                if ((unsigned char)byteBuf[j] == HDLC_FLAG) {
                    if (j - i >= 4) {
                        start = i;
                        end = j;
                        printf("�ҵ�����HDLC֡: ��ʼλ��=%d, ����λ��=%d\n", start, end);
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
        printf("δ�ҵ���Ч��HDLC֡!\n");
        printf("===================\n");
        if (tmpAlloc) free(tmpAlloc);
        return;
    }
    int frameLen = end - start + 1;
    printf("\n���յ�֡: ����=%d ��ʼ��־=0x%02X ������־=0x%02X\n",
        frameLen, (unsigned char)byteBuf[start], (unsigned char)byteBuf[end]);

    U8* frameBuf = (U8*)malloc(frameLen);
    if (!frameBuf) {
        if (tmpAlloc) free(tmpAlloc);
        printf("�ڴ����ʧ��\n");
        return;
    }
    memcpy(frameBuf, byteBuf + start, frameLen);

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
    }
}