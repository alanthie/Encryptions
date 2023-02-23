#ifndef _INCLUDES_crypto_const
#define _INCLUDES_crypto_const

#include <filesystem>
#include <curl/curl.h>
#include "encrypt.h"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <string>
// LINKER -lcurl

enum class CRYPTO_ALGO : uint16_t
{
    ALGO_BIN_DES = 1,
    ALGO_BIN_AES_16_16_ecb,
    ALGO_BIN_AES_16_16_cbc,
    ALGO_BIN_AES_16_16_cfb,
};
enum class CRYPTO_ALGO_AES
{
    ECB,
    CBC,
    CFB
};

constexpr static uint32_t BASE          = 25000; // BASE*BASE >= FILE_SIZE_LIM
constexpr static int16_t MAGIC_SIZE     = 4;
constexpr static int16_t KEYPOS_ENCODESIZE  = 6;
constexpr static int16_t URL_LEN_ENCODESIZE = 2;
constexpr static int16_t CRYPTO_ALGO_ENCODESIZE = 2;
constexpr static int16_t URL_MIN_SIZE   = 10;
constexpr static int16_t URL_MAX_SIZE   = 256;
constexpr static int16_t KEY_SIZE       = 256*4; // KEYS extract from URL files - Make it dynamic...
constexpr static int16_t CHKSUM_SIZE    = 64;
constexpr static int16_t PADDING_LEN_ENCODESIZE = 2;
constexpr static int16_t URLINFO_SIZE   =   URL_LEN_ENCODESIZE + URL_MAX_SIZE + MAGIC_SIZE +
                                            KEYPOS_ENCODESIZE  + CHKSUM_SIZE  + KEY_SIZE +
                                            CRYPTO_ALGO_ENCODESIZE + PADDING_LEN_ENCODESIZE; // padding 16x

constexpr static int16_t PADDING_MULTIPLE   = 16; // should be 16x with AES
constexpr static int16_t NITER_LIM          = 100;
constexpr static int16_t PUZZLE_SIZE_LIM    = 10000;
constexpr static uint32_t FILE_SIZE_LIM     = 100*1000*1000;

const std::string REM_TOKEN             = "REM";
const std::string CHKSUM_TOKEN          = "CHKSUM";

// test
class urlkey
{
public:
    urlkey() {}

    uint16_t crypto_algo = 1;           // 2
    uint16_t url_size = 0;              // 2
    char url[URL_MAX_SIZE]= {0};        // 256
    char magic[4]= {'a','b','c','d'};   // 4
    uint16_t key_fromH = 0;             // 2 random offset
    uint16_t key_fromL = 0;             // 2
    uint16_t key_size = KEY_SIZE;       // 2
    char key[KEY_SIZE] = {0};           // 256
    char checksum[CHKSUM_SIZE] = {0};   // 64

    char urlinfo_with_padding[URLINFO_SIZE] = {0};
};

std::string get_current_time_and_date()
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X");
    return ss.str();
}

std::string get_current_date()
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d");
    return ss.str();
}

int find_string(std::string url, char delim, std::string vlist, bool verbose = false)
{
    size_t pos_start = 0;
    size_t pos_end = 0;
    std::string  token;
    int cnt = 0;

    if (verbose)
        std::cout << "searching for match of "<< url << " in list " << vlist << std::endl;

    for(size_t i=0;i<vlist.size();i++)
    {
        if (vlist[i]!=delim) pos_end++;
        else
        {
            token = vlist.substr(pos_start, pos_end-pos_start);
            if (verbose)
                std::cout << "token "<< token << std::endl;
            if (url.find(token, 0) != std::string::npos)
            {
                return cnt;
            }
            pos_start = pos_end+1;
            cnt++;
        }
    }
    return -1;
}

std::string get_string_by_index(std::string vlist, char delim, int idx, bool verbose = false)
{
    size_t pos_start = 0;
    size_t pos_end = 0;
    std::string token;
    int cnt = 0;

    for(size_t i=0;i<vlist.size();i++)
    {
        if (vlist[i]!=delim) pos_end++;
        else
        {
            token = vlist.substr(pos_start, pos_end-pos_start);
            if (verbose)
                std::cout << "token "<< token << std::endl;
            if (idx == cnt)
                return token;

            pos_start = pos_end+1;
            i = pos_start;
            cnt++;
        }
    }
    return "";
}

#endif

