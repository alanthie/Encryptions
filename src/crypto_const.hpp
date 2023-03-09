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
#include "base_const.hpp"


// LINKER -lcurl
// Post builds
//cp /home/server/dev/Encryptions/bin/Release/crypto /home/server/dev/Encryptions/Exec_Linux/crypto
//copy x64\Release\crypto.exe ..\..\Exec_Windows\*


namespace cryptoAL
{

enum class CRYPTO_ALGO : uint16_t
{
    ALGO_BIN_DES = 1,
    ALGO_BIN_AES_16_16_ecb,
    ALGO_BIN_AES_16_16_cbc,
    ALGO_BIN_AES_16_16_cfb,
    ALGO_TWOFISH,
    ALGO_Salsa20,
    ALGO_IDEA
};
enum class CRYPTO_ALGO_AES
{
    ECB,
    CBC,
    CFB
};

constexpr static uint32_t BASE              = 255*256; // BASE*BASE >= FILE_SIZE_LIM, BASE < 256*256 (64k)
constexpr static int16_t MAGIC_SIZE         = 4;
constexpr static int16_t KEYPOS_ENCODESIZE  = 8;
constexpr static int16_t URL_LEN_ENCODESIZE = 2;
constexpr static int16_t CRYPTO_ALGO_ENCODESIZE = 2;
constexpr static uint32_t URL_MIN_SIZE      = 4;
constexpr static uint32_t URL_MAX_SIZE_GUESS = 4 * (64 + MAX_RSA_BITS/8) / 3; // add base64 lost space 2 bits/8
constexpr static uint32_t URL_MAX_SIZE      = URL_MAX_SIZE_GUESS + (64 - (URL_MAX_SIZE_GUESS % 64)); // multiple 64x
constexpr static uint32_t MIN_KEY_SIZE      = 64;    // RSA KEY_NAME
constexpr static int16_t CHKSUM_SIZE        = 64;
constexpr static int16_t PADDING_LEN_ENCODESIZE = 2;
constexpr static uint32_t URLINFO_SIZE      =   URL_LEN_ENCODESIZE + URL_MAX_SIZE +
                                                MAGIC_SIZE +
                                                KEYPOS_ENCODESIZE  +
                                                CHKSUM_SIZE +
                                                MIN_KEY_SIZE +
                                                CRYPTO_ALGO_ENCODESIZE +
                                                PADDING_LEN_ENCODESIZE + 14 + 32; // padding 64

constexpr static int16_t PADDING_MULTIPLE       = 64; // should be at least 64x with Salsa20 requirement
constexpr static int16_t PADDING_KEY_MULTIPLE   = 32; // should be at least 32x with Salsa20 requirement
constexpr static int16_t NITER_LIM              = 128;
constexpr static uint32_t FILE_SIZE_LIM         = 128*1024*1024; // 128MB

constexpr static uint32_t RSAKEYLEN_MIN_SIZE    = 64;               // 64 bytes = 512 bits
constexpr static uint32_t RSAKEYLEN_MAX_SIZE    = 64 + (MAX_RSA_BITS/8);   // 16k bits - TODO More since using base64

const std::string QA_TOKEN              = "QA";
const std::string REM_TOKEN             = "REM";
const std::string BLOCK_START_TOKEN     = "BLOCK_START";
const std::string BLOCK_END_TOKEN       = "BLOCK_END";
const std::string CHKSUM_TOKEN          = "CHKSUM";

constexpr static uint32_t CRYPTO_HEADER_SIZE = 64+64;
constexpr static int16_t HINT_SIZE           = 32+64-4;
struct CRYPTO_HEADER {
    char sig[6];                               // File Signature (CRYPTO)
    std::uint16_t version;                      // Format Version
    std::uint32_t enc_puzzle_size;              // Size of encrypted puzzle
    std::uint32_t enc_puzzle_padding_size;      // Size of encrypted puzzle before padding
    std::uint32_t enc_data_size;                // Size of encrypted data before padding
    std::uint32_t enc_data_padding_size;
    std::uint32_t crc_enc_data_hash;            // CRC32 hash of encrypted data before padding
    std::uint32_t crc_enc_puzzle_hash;
    std::uint32_t crc_enc_puzzle_key_hash = 0;  // 0 if no enc key for puzzle
    char enc_puzzle_key_hint[HINT_SIZE];        // Encrypted Puzzle Extract Key Hint
};
static_assert(sizeof(CRYPTO_HEADER) == CRYPTO_HEADER_SIZE);

}

#endif

