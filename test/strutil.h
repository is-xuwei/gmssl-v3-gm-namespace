#pragma once
#include <cstring>
#include <string>

static void printx(void* ptr, int len, char* title = "", char* footer = "")
{
    printf("%s\n", title);
    for (int i = 0; i < len; i++)
        printf("%02x", ((uint8_t*)ptr)[i]);
    printf("%s\n\n", footer);
}

//数组转hex字符串
static std::string ToHexString(const unsigned char* pData, size_t nSize)
{
    std::string str;
    char szBuf[3] = "";
    for (size_t i = 0; i < nSize; i++)
    {
        std::snprintf(szBuf, 3, "%02x", *(pData + i));
        str += szBuf;
    }
    return str;
}

//数组转字符串
static std::string ToString(const unsigned char* data, size_t nSize)
{
    unsigned char* pData = new unsigned char[nSize];
    memcpy(pData, data, nSize);
    std::string str;
    char szBuf[3] = "";
    for (size_t i = 0; i < nSize; i++)
    {
        std::snprintf(szBuf, 3, "%c", *(pData + i));
        str += szBuf;
    }
    delete pData;
    return str;
}

static int hex2byte(uint8_t* dst, uint32_t* len, char* src) {
    uint32_t i = 0;
    while (*src) {
        if (' ' == *src) {
            src++;
            continue;
        }
        sscanf(src, "%02X", dst);
        src += 2;
        dst++;
        i++;
    }
    *len = i;
    return 0;
}
