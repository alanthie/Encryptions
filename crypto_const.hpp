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
// Post builds
//cp /home/server/dev/Encryptions/bin/Release/crypto /home/server/dev/Encryptions/Exec_Linux/crypto
//copy x64\Release\crypto.exe ..\..\Exec_Windows\*

// Windows:
//D:\000DEV\Encryptions\testcase\manual > D:\000DEV\Encryptions\Exec_Windows\crypto.exe batch_encode - i crypto_batch_manual_win.ini
//
// Linux:
//~/dev/Encryptions/testcase/manual$ ./../../bin/Release/crypto batch_encode -i manual.ini -v 1



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

constexpr static uint32_t BASE          = 255*256; // BASE*BASE >= FILE_SIZE_LIM, BASE < 256*256 (64k)
constexpr static int16_t MAGIC_SIZE     = 4;
constexpr static int16_t KEYPOS_ENCODESIZE  = 8;
constexpr static int16_t URL_LEN_ENCODESIZE = 2;
constexpr static int16_t CRYPTO_ALGO_ENCODESIZE = 2;
constexpr static int16_t URL_MIN_SIZE   = 4;
constexpr static int16_t URL_MAX_SIZE   = 256;
constexpr static int16_t MIN_KEY_SIZE   = 64; // KEYS are extract from URL files (local or web)
constexpr static int16_t CHKSUM_SIZE    = 64;
constexpr static int16_t PADDING_LEN_ENCODESIZE = 2;
constexpr static int16_t URLINFO_SIZE   =   URL_LEN_ENCODESIZE + URL_MAX_SIZE + MAGIC_SIZE +
                                            KEYPOS_ENCODESIZE  + CHKSUM_SIZE  + MIN_KEY_SIZE +
                                            CRYPTO_ALGO_ENCODESIZE + PADDING_LEN_ENCODESIZE + 14; // padding 16x

constexpr static int16_t PADDING_MULTIPLE   = 16; // should be at least 16x with AES 128bits data size requirement
constexpr static int16_t NITER_LIM          = 128;
constexpr static int16_t PUZZLE_SIZE_LIM    = 64*256;
constexpr static uint32_t FILE_SIZE_LIM     = 128*1024*1024; // 128MB

const std::string REM_TOKEN             = "REM";
const std::string CHKSUM_TOKEN          = "CHKSUM";

class urlkey
{
public:
    urlkey() {}
    ~urlkey()
    {
        if (buff_key != nullptr)
        {
            delete buff_key;
            buff_key = nullptr;
        }
    }

    Buffer* get_buffer()
    {
        if (buff_key == nullptr)
        {
            buff_key = new Buffer(MIN_KEY_SIZE);
        }
        return buff_key;
    }

    void erase_buffer()
    {
        if (buff_key != nullptr)
        {
            buff_key->erase();
        }
    }

    uint16_t crypto_algo = (uint16_t)CRYPTO_ALGO::ALGO_BIN_DES; // 2
    uint16_t url_size = 0;              // 2
    char url[URL_MAX_SIZE]= {0};        // 256
    char magic[4]= {'a','b','c','d'};   // 4
    uint16_t key_fromH = 0;             // 2 random offset where to extract a key
    uint16_t key_fromL = 0;             // 2
    uint32_t key_size = MIN_KEY_SIZE;   // 4 bytes
    char key[MIN_KEY_SIZE] = {0};       // NOT THE FULL KEY, a small default buffer for small keys for future usage
    char checksum[CHKSUM_SIZE] = {0};   // 64

    char urlinfo_with_padding[URLINFO_SIZE] = {0};

protected:
    Buffer* buff_key = nullptr;
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

